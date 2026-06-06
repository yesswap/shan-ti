"""
AlienVault OTX ingestion — pulls threat pulses and links IOCs to known actors.
Free API key from https://otx.alienvault.com — no payment needed.
"""
import os
import re
import requests
import logging
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from models import ThreatActor, Indicator, IngestSource, IndicatorType, ConfidenceLevel, IndicatorStatus

logger = logging.getLogger(__name__)

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_BASE = "https://otx.alienvault.com/api/v1"

# Map OTX indicator types to our schema
OTX_TYPE_MAP = {
    "IPv4": IndicatorType.IP,
    "IPv6": IndicatorType.IP,
    "domain": IndicatorType.DOMAIN,
    "hostname": IndicatorType.DOMAIN,
    "URL": IndicatorType.URL,
    "FileHash-MD5": IndicatorType.MD5,
    "FileHash-SHA1": IndicatorType.SHA1,
    "FileHash-SHA256": IndicatorType.SHA256,
    "email": IndicatorType.EMAIL,
    "CVE": IndicatorType.CVE,
}

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


def _get_actor(db: Session, actor_name: str) -> ThreatActor | None:
    """Fuzzy match actor name against known actors."""
    if not actor_name:
        return None
    name_lower = actor_name.lower().strip()
    actors = db.query(ThreatActor).all()
    for actor in actors:
        if actor.name.lower() == name_lower:
            return actor
        aliases = [a.lower() for a in (actor.aliases or [])]
        if name_lower in aliases:
            return actor
        # Partial match
        if name_lower in actor.name.lower() or actor.name.lower() in name_lower:
            return actor
    return None


def _extract_actor_from_tags(tags: list) -> str | None:
    """OTX pulses often tag APT names."""
    apt_pattern = re.compile(r"(apt[\s\-]?\d+|lazarus|fancy bear|cozy bear|kimsuky|sandworm|darkhotel|fin\d+)", re.IGNORECASE)
    for tag in tags:
        match = apt_pattern.search(tag)
        if match:
            return match.group(0)
    return None


def ingest_otx(db: Session, pages: int = 5):
    """
    Pulls recent OTX pulses, extracts IOCs, and links them to known actors.
    pages: number of pulse pages to fetch (each page = 10 pulses)
    """
    if not OTX_API_KEY:
        logger.warning("OTX_API_KEY not set — skipping OTX ingestion. Get a free key at otx.alienvault.com")
        return

    source_record = db.query(IngestSource).filter(IngestSource.name == "AlienVault OTX").first()
    if not source_record:
        source_record = IngestSource(name="AlienVault OTX", type="api", url=OTX_BASE)
        db.add(source_record)
        db.commit()

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    total_iocs = 0

    for page in range(1, pages + 1):
        try:
            resp = requests.get(
                f"{OTX_BASE}/pulses/subscribed",
                headers=headers,
                params={"limit": 10, "page": page, "modified_since": (datetime.now() - timedelta(days=30)).isoformat()},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error(f"OTX page {page} failed: {e}")
            break

        for pulse in data.get("results", []):
            pulse_name = pulse.get("name", "")
            pulse_url = f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}"
            tags = pulse.get("tags", [])
            adversary = pulse.get("adversary", "") or _extract_actor_from_tags(tags) or ""

            actor = _get_actor(db, adversary)

            for ioc in pulse.get("indicators", []):
                ioc_type = OTX_TYPE_MAP.get(ioc.get("type"))
                if not ioc_type:
                    continue
                value = ioc.get("indicator", "").strip()
                if not value:
                    continue

                # Check for existing IOC
                existing = db.query(Indicator).filter(
                    Indicator.value == value,
                    Indicator.type == ioc_type,
                ).first()

                now = datetime.now(timezone.utc)
                expires = now + timedelta(days=TTL_MAP.get(ioc_type, 30))

                if existing:
                    # Corroborate
                    existing.corroboration_count += 1
                    existing.last_seen = now
                    existing.expires_at = expires
                    existing.status = IndicatorStatus.FRESH
                    if actor and not existing.actor_id:
                        existing.actor_id = actor.id
                    _update_confidence(existing)
                else:
                    ind = Indicator(
                        actor_id=actor.id if actor else None,
                        type=ioc_type,
                        value=value,
                        confidence=ConfidenceLevel.MEDIUM,
                        confidence_score=0.5,
                        status=IndicatorStatus.FRESH,
                        first_seen=now,
                        last_seen=now,
                        expires_at=expires,
                        source="AlienVault OTX",
                        source_url=pulse_url,
                        corroboration_count=1,
                        tags=tags[:10],
                        metadata_={"pulse_name": pulse_name, "pulse_adversary": adversary},
                    )
                    db.add(ind)
                    total_iocs += 1

        db.commit()

        if not data.get("next"):
            break

    source_record.last_run_at = datetime.now(timezone.utc)
    source_record.last_run_status = "success"
    source_record.records_ingested = total_iocs
    db.commit()
    logger.info(f"✓ OTX: ingested {total_iocs} new IOCs")


def _update_confidence(indicator: Indicator):
    """Raise confidence based on corroboration count."""
    count = indicator.corroboration_count
    if count >= 5:
        indicator.confidence = ConfidenceLevel.HIGH
        indicator.confidence_score = 0.85
    elif count >= 3:
        indicator.confidence = ConfidenceLevel.MEDIUM
        indicator.confidence_score = 0.65
    elif count >= 2:
        indicator.confidence = ConfidenceLevel.LOW
        indicator.confidence_score = 0.45
