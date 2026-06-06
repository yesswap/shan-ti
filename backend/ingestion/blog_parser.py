"""
Free threat intel blog parser — NO paid AI APIs.

Pipeline:
  1. Fetch blog post HTML → trafilatura extracts clean text
  2. regex patterns extract IOCs (IPs, domains, hashes, CVEs, emails)
  3. spaCy NER extracts actor names / organization mentions
  4. Link extracted IOCs to actor profiles in DB
  5. Store as indicators with source attribution

Supported feeds (RSS):
  - Mandiant: https://www.mandiant.com/resources/blog/rss.xml
  - Unit 42: https://unit42.paloaltonetworks.com/feed/
  - Microsoft MSTIC: https://www.microsoft.com/en-us/security/blog/feed/
  - Secureworks: https://www.secureworks.com/rss?feed=blog
  - ESET: https://feeds.feedburner.com/eset/blog
  - CISA: https://www.cisa.gov/news.xml
  - Krebs on Security: https://krebsonsecurity.com/feed/
"""
import re
import logging
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import feedparser
import requests

try:
    import trafilatura
    TRAFILATURA_AVAILABLE = True
except ImportError:
    TRAFILATURA_AVAILABLE = False
    logging.warning("trafilatura not installed — using basic text extraction")

try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
except Exception:
    SPACY_AVAILABLE = False
    logging.warning("spaCy model not available — skipping NER")

from sqlalchemy.orm import Session
from models import ThreatActor, Indicator, IngestSource, IndicatorType, ConfidenceLevel, IndicatorStatus

logger = logging.getLogger(__name__)

# ─── Regex patterns ───────────────────────────────────────────────────────────

RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|ir|kp|gov|mil|edu|info|biz|co|uk|de|fr|nl|jp|kr|in|br|au|xyz|top|club|site|online|store|shop|tech|app)\b",
    re.IGNORECASE,
)
RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
RE_URL = re.compile(r"https?://[^\s\"'<>]{10,}", re.IGNORECASE)

# Private / reserved IPs to exclude
PRIVATE_IP_PATTERNS = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.|255\.)"
)

# Common benign domains to exclude
BENIGN_DOMAINS = {
    "microsoft.com", "google.com", "github.com", "amazon.com", "cloudflare.com",
    "windows.com", "office.com", "azure.com", "twitter.com", "linkedin.com",
    "facebook.com", "apple.com", "mozilla.org", "w3.org", "adobe.com",
}

APT_PATTERN = re.compile(
    r"\b(APT[\s\-]?\d+|Lazarus(?:\s+Group)?|Fancy\s+Bear|Cozy\s+Bear|Sandworm|Kimsuky|"
    r"Darkhotel|FIN\d+|Carbanak|Turla|Equation\s+Group|Shadow\s+Brokers|"
    r"Charming\s+Kitten|Double\s+Dragon|Stone\s+Panda|Gothic\s+Panda|"
    r"Winnti|Ocean\s+Lotus|APT-C-\d+|TA\d+|UNC\d+|DEV-\d+)\b",
    re.IGNORECASE,
)

# TTL by indicator type (days)
TTL_MAP = {
    IndicatorType.IP: 7,
    IndicatorType.DOMAIN: 30,
    IndicatorType.URL: 3,
    IndicatorType.MD5: 365,
    IndicatorType.SHA1: 365,
    IndicatorType.SHA256: 365,
    IndicatorType.EMAIL: 90,
    IndicatorType.CVE: 730,
}

THREAT_FEEDS = [
    {"name": "Mandiant Blog",    "url": "https://www.mandiant.com/resources/blog/rss.xml"},
    {"name": "Unit42 Blog",      "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "Microsoft MSTIC",  "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
    {"name": "Secureworks Blog", "url": "https://www.secureworks.com/rss?feed=blog"},
    {"name": "ESET Research",    "url": "https://feeds.feedburner.com/eset/blog"},
    {"name": "CISA Alerts",      "url": "https://www.cisa.gov/news.xml"},
    {"name": "Krebs Security",   "url": "https://krebsonsecurity.com/feed/"},
    {"name": "The DFIR Report",  "url": "https://thedfirreport.com/feed/"},
]


# ─── Text extraction ──────────────────────────────────────────────────────────

def fetch_article_text(url: str) -> Optional[str]:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; ThreatLens/1.0)"}
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        html = resp.text

        if TRAFILATURA_AVAILABLE:
            text = trafilatura.extract(html, include_links=False, include_images=False)
            return text
        else:
            # Fallback: strip HTML tags
            clean = re.sub(r"<[^>]+>", " ", html)
            clean = re.sub(r"\s+", " ", clean)
            return clean[:50_000]
    except Exception as e:
        logger.warning(f"Could not fetch {url}: {e}")
        return None


# ─── IOC Extraction ───────────────────────────────────────────────────────────

def extract_iocs(text: str) -> dict[IndicatorType, list[str]]:
    """Extract all IOC types from raw text. Returns deduplicated lists."""
    results: dict[IndicatorType, set[str]] = {t: set() for t in IndicatorType}

    # IPs — exclude private/loopback
    for match in RE_IPV4.finditer(text):
        ip = match.group()
        if not PRIVATE_IP_PATTERNS.match(ip):
            results[IndicatorType.IP].add(ip)

    # Domains — exclude benign
    for match in RE_DOMAIN.finditer(text):
        domain = match.group().lower()
        root = ".".join(domain.split(".")[-2:])
        if root not in BENIGN_DOMAINS and len(domain) < 200:
            results[IndicatorType.DOMAIN].add(domain)

    # Hashes (longest first to avoid substring overlap)
    for match in RE_SHA256.finditer(text):
        results[IndicatorType.SHA256].add(match.group().lower())
    for match in RE_SHA1.finditer(text):
        h = match.group().lower()
        if h not in {v for v in results[IndicatorType.SHA256]}:  # avoid mis-tagging
            results[IndicatorType.SHA1].add(h)
    for match in RE_MD5.finditer(text):
        h = match.group().lower()
        results[IndicatorType.MD5].add(h)

    # CVEs
    for match in RE_CVE.finditer(text):
        results[IndicatorType.CVE].add(match.group().upper())

    # Emails
    for match in RE_EMAIL.finditer(text):
        email = match.group().lower()
        if not any(b in email for b in ["example.com", "test.com"]):
            results[IndicatorType.EMAIL].add(email)

    # URLs (only suspicious-looking ones, skip news/social URLs)
    for match in RE_URL.finditer(text):
        url = match.group()
        domain = urlparse(url).netloc.replace("www.", "")
        root = ".".join(domain.split(".")[-2:]) if domain else ""
        if root not in BENIGN_DOMAINS:
            results[IndicatorType.URL].add(url[:500])

    return {k: list(v) for k, v in results.items()}


def extract_actor_mentions(text: str) -> list[str]:
    """Extract actor/group names from text."""
    mentions = set()

    # Regex APT patterns
    for match in APT_PATTERN.finditer(text):
        mentions.add(match.group().strip())

    # spaCy NER — organizations
    if SPACY_AVAILABLE and len(text) < 100_000:
        doc = nlp(text[:50_000])
        for ent in doc.ents:
            if ent.label_ == "ORG" and len(ent.text) > 3:
                if any(kw in ent.text.lower() for kw in ["apt", "bear", "panda", "tiger", "dragon", "kitten", "group", "team"]):
                    mentions.add(ent.text.strip())

    return list(mentions)


def _find_actor(db: Session, mentions: list[str]) -> Optional[ThreatActor]:
    actors = db.query(ThreatActor).all()
    for mention in mentions:
        ml = mention.lower()
        for actor in actors:
            if actor.name.lower() == ml:
                return actor
            if any(a.lower() == ml for a in (actor.aliases or [])):
                return actor
            if ml in actor.name.lower() or actor.name.lower() in ml:
                return actor
    return None


# ─── Main ingestion ───────────────────────────────────────────────────────────

def ingest_blog_feeds(db: Session, max_articles_per_feed: int = 5):
    """Iterate all threat intel RSS feeds, parse articles, extract and store IOCs."""
    total_iocs = 0

    for feed_config in THREAT_FEEDS:
        feed_name = feed_config["name"]
        feed_url = feed_config["url"]

        logger.info(f"Processing feed: {feed_name}")

        source = db.query(IngestSource).filter(IngestSource.name == feed_name).first()
        if not source:
            source = IngestSource(name=feed_name, type="rss", url=feed_url)
            db.add(source)
            db.commit()

        try:
            feed = feedparser.parse(feed_url)
            entries = feed.entries[:max_articles_per_feed]
        except Exception as e:
            logger.error(f"{feed_name} RSS parse failed: {e}")
            source.last_run_status = "error"
            source.error_message = str(e)
            db.commit()
            continue

        feed_iocs = 0
        for entry in entries:
            article_url = entry.get("link", "")
            if not article_url:
                continue

            text = fetch_article_text(article_url)
            if not text or len(text) < 200:
                continue

            iocs = extract_iocs(text)
            actor_mentions = extract_actor_mentions(text)
            actor = _find_actor(db, actor_mentions)

            now = datetime.now(timezone.utc)

            for ioc_type, values in iocs.items():
                for value in values[:50]:  # cap per article
                    expires = now + timedelta(days=TTL_MAP.get(ioc_type, 30))

                    existing = db.query(Indicator).filter(
                        Indicator.value == value,
                        Indicator.type == ioc_type,
                    ).first()

                    if existing:
                        existing.corroboration_count += 1
                        existing.last_seen = now
                        existing.status = IndicatorStatus.FRESH
                        if actor and not existing.actor_id:
                            existing.actor_id = actor.id
                    else:
                        db.add(Indicator(
                            actor_id=actor.id if actor else None,
                            type=ioc_type,
                            value=value,
                            confidence=ConfidenceLevel.LOW,
                            confidence_score=0.35,
                            status=IndicatorStatus.FRESH,
                            first_seen=now,
                            last_seen=now,
                            expires_at=expires,
                            source=feed_name,
                            source_url=article_url,
                            corroboration_count=1,
                            tags=actor_mentions[:5],
                            metadata_={"article_url": article_url, "feed": feed_name},
                        ))
                        feed_iocs += 1

        db.commit()
        source.last_run_at = datetime.now(timezone.utc)
        source.last_run_status = "success"
        source.records_ingested += feed_iocs
        db.commit()
        total_iocs += feed_iocs
        logger.info(f"  {feed_name}: +{feed_iocs} IOCs")

    logger.info(f"✓ Blog parser total: {total_iocs} new IOCs")
    return total_iocs
