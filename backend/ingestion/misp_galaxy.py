"""
MISP Galaxy ingestion — enriches existing threat actors with the community
threat-actor cluster (https://github.com/MISP/misp-galaxy). No API key required.

Backfills, for actors we already know from MITRE:
  - aliases / synonyms
  - nation_state  (ISO country -> readable name, or suspected state sponsor)
  - sponsor
  - targeted_sectors
  - motivation
  - source attribution

Matching is by name or any known alias (case-insensitive).
"""
import logging
from datetime import datetime, timezone

import requests
from sqlalchemy.orm import Session

from models import ThreatActor, IngestSource

logger = logging.getLogger(__name__)

MISP_GALAXY_URL = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
)

# ISO 3166-1 alpha-2 -> readable name. Names for the well-known origins are kept
# consistent with the frontend's flag map (China/Russia/North Korea/...).
COUNTRY_NAMES = {
    "CN": "China", "RU": "Russia", "KP": "North Korea", "IR": "Iran",
    "VN": "Vietnam", "PK": "Pakistan", "IN": "India", "TR": "Turkey",
    "IL": "Israel", "US": "USA", "PS": "Palestine", "UA": "Ukraine",
    "KR": "South Korea", "SY": "Syria", "LB": "Lebanon", "AE": "UAE",
    "SA": "Saudi Arabia", "EG": "Egypt", "NG": "Nigeria", "RO": "Romania",
    "GB": "United Kingdom", "FR": "France", "DE": "Germany", "BY": "Belarus",
    "KZ": "Kazakhstan", "UZ": "Uzbekistan", "TH": "Thailand", "MY": "Malaysia",
    "ID": "Indonesia", "TW": "Taiwan", "SD": "Sudan", "CO": "Colombia",
    "MX": "Mexico", "IT": "Italy", "ES": "Spain",
}

# cfr-type-of-incident -> normalized motivation tokens
MOTIVATION_MAP = {
    "espionage": "espionage",
    "financial": "financial",
    "financial crime": "financial",
    "sabotage": "sabotage",
    "denial of service": "sabotage",
    "hacktivism": "hacktivism",
    "doxing": "hacktivism",
    "destruction": "destruction",
}


def _norm(s: str) -> str:
    return " ".join((s or "").lower().split())


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _motivations(meta: dict) -> list[str]:
    out = set()
    for raw in _as_list(meta.get("cfr-type-of-incident")):
        token = MOTIVATION_MAP.get(_norm(raw))
        if token:
            out.add(token)
    return sorted(out)


def _sectors(meta: dict) -> list[str]:
    out = []
    for key in ("cfr-target-category", "targeted-sector"):
        for s in _as_list(meta.get(key)):
            s = (s or "").strip().title()
            if s and s not in out:
                out.append(s)
    return out


def _nation(meta: dict) -> str | None:
    code = (meta.get("country") or "").strip().upper()
    if code:
        return COUNTRY_NAMES.get(code, code)
    sponsor = meta.get("cfr-suspected-state-sponsor")
    if sponsor and sponsor.strip().lower() not in ("unknown", "n/a", ""):
        # "Russian Federation" -> "Russia" style left as-is if unknown
        return {"Russian Federation": "Russia"}.get(sponsor, sponsor)
    return None


def ingest_misp_galaxy(db: Session):
    """Fetch the MISP threat-actor galaxy and enrich matching actors in our DB."""
    source = db.query(IngestSource).filter(IngestSource.name == "MISP Galaxy").first()
    if not source:
        source = IngestSource(name="MISP Galaxy", type="api", url=MISP_GALAXY_URL)
        db.add(source)
        db.commit()

    logger.info("Fetching MISP Galaxy threat-actor cluster...")
    try:
        resp = requests.get(MISP_GALAXY_URL, timeout=60)
        resp.raise_for_status()
        values = resp.json().get("values", [])
    except Exception as e:
        logger.error(f"MISP Galaxy fetch failed: {e}")
        source.last_run_status = "error"
        source.error_message = str(e)
        db.commit()
        return

    # Index galaxy entries by every name/synonym they go by
    index: dict[str, dict] = {}
    for v in values:
        names = [v.get("value", "")] + _as_list(v.get("meta", {}).get("synonyms"))
        for n in names:
            n = _norm(n)
            if n and n not in index:
                index[n] = v

    enriched = 0
    for actor in db.query(ThreatActor).all():
        candidates = [actor.name] + list(actor.aliases or [])
        entry = next((index[_norm(c)] for c in candidates if _norm(c) in index), None)
        if not entry:
            continue

        meta = entry.get("meta", {})

        # Merge aliases (keep existing, add synonyms, drop the actor's own name)
        merged = list(actor.aliases or [])
        for syn in _as_list(meta.get("synonyms")):
            if syn and syn != actor.name and syn not in merged:
                merged.append(syn)
        actor.aliases = merged

        # Nation / sponsor — only fill if missing or improving
        nation = _nation(meta)
        if nation and not actor.nation_state:
            actor.nation_state = nation
        if meta.get("cfr-suspected-state-sponsor") and not actor.sponsor:
            actor.sponsor = meta["cfr-suspected-state-sponsor"]

        # Sectors / motivation — fill if empty
        sectors = _sectors(meta)
        if sectors and not (actor.targeted_sectors or []):
            actor.targeted_sectors = sectors
        motivations = _motivations(meta)
        if motivations and not (actor.motivation or []):
            actor.motivation = motivations

        # Source attribution
        srcs = list(actor.sources or [])
        if "MISP Galaxy" not in srcs:
            srcs.append("MISP Galaxy")
        actor.sources = srcs

        enriched += 1

    db.commit()
    source.last_run_at = datetime.now(timezone.utc)
    source.last_run_status = "success"
    source.records_ingested = enriched
    db.commit()
    logger.info(f"✓ MISP Galaxy: enriched {enriched} actors")
    return enriched
