"""
Metadata backfill — fills actor fields that the upstream feeds leave sparse:
  - active_since / active_status   (neither MITRE nor MISP expose these well)
  - motivation / targeted_sectors  (heuristic from description when still empty)

Runs after MITRE + MISP enrichment, so it only fills gaps.
"""
import logging
import re

from sqlalchemy.orm import Session
from models import ThreatActor

logger = logging.getLogger(__name__)

# Curated facts for the most-tracked actors. Keyed by name OR alias (lowercase).
# value: (nation, motivation[], sectors[], active_since, active_status)
CURATED = {
    "apt28":   ("Russia", ["espionage"], ["Government", "Military", "Defense"], "2004", "active"),
    "apt29":   ("Russia", ["espionage"], ["Government", "Think Tanks", "Healthcare"], "2008", "active"),
    "sandworm team": ("Russia", ["sabotage", "destruction"], ["Energy", "Government"], "2009", "active"),
    "turla":   ("Russia", ["espionage"], ["Government", "Defense"], "2004", "active"),
    "gamaredon group": ("Russia", ["espionage"], ["Government", "Military"], "2013", "active"),
    "lazarus group": ("North Korea", ["financial", "espionage"], ["Financial", "Cryptocurrency", "Defense"], "2009", "active"),
    "kimsuky": ("North Korea", ["espionage"], ["Government", "Think Tanks", "Academia"], "2012", "active"),
    "apt37":   ("North Korea", ["espionage"], ["Government", "Media", "Defense"], "2012", "active"),
    "apt38":   ("North Korea", ["financial"], ["Financial", "Cryptocurrency"], "2014", "active"),
    "apt1":    ("China", ["espionage"], ["Technology", "Manufacturing", "Government"], "2006", "inactive"),
    "apt10":   ("China", ["espionage"], ["Technology", "Aerospace", "Government"], "2009", "active"),
    "apt40":   ("China", ["espionage"], ["Maritime", "Engineering", "Government"], "2013", "active"),
    "apt41":   ("China", ["espionage", "financial"], ["Healthcare", "Telecommunications", "Gaming"], "2012", "active"),
    "mustang panda": ("China", ["espionage"], ["Government", "NGOs"], "2017", "active"),
    "winnti group": ("China", ["espionage", "financial"], ["Gaming", "Technology"], "2010", "active"),
    "apt33":   ("Iran", ["espionage", "sabotage"], ["Energy", "Aviation", "Defense"], "2013", "active"),
    "apt34":   ("Iran", ["espionage"], ["Energy", "Government", "Financial"], "2014", "active"),
    "apt35":   ("Iran", ["espionage"], ["Government", "Media", "Academia"], "2014", "active"),
    "muddywater": ("Iran", ["espionage"], ["Government", "Telecommunications", "Energy"], "2017", "active"),
    "oilrig":  ("Iran", ["espionage"], ["Energy", "Government", "Financial"], "2014", "active"),
    "apt32":   ("Vietnam", ["espionage"], ["Government", "Manufacturing", "Media"], "2014", "active"),
    "apt36":   ("Pakistan", ["espionage"], ["Government", "Military"], "2013", "active"),
    "sidewinder": ("India", ["espionage"], ["Government", "Military"], "2012", "active"),
    "fin7":    (None, ["financial"], ["Retail", "Hospitality", "Financial"], "2015", "active"),
    "carbanak": (None, ["financial"], ["Financial", "Hospitality"], "2013", "active"),
    "cobalt group": (None, ["financial"], ["Financial"], "2016", "active"),
    "ta505":   (None, ["financial"], ["Financial", "Retail"], "2014", "active"),
    "wizard spider": ("Russia", ["financial"], ["Healthcare", "Financial"], "2016", "active"),
}

MOTIVATION_KEYWORDS = {
    "espionage": ["espionage", "intelligence", "cyber spying", "information theft", "surveillance"],
    "financial": ["financial gain", "financially motivated", "monetary", "ransom", "extortion", "cybercrime", "theft of money"],
    "sabotage": ["sabotage", "disruptive", "wiper", "denial of service"],
    "destruction": ["destructive", "destruction of data"],
    "hacktivism": ["hacktivist", "hacktivism", "political message"],
}

SECTOR_KEYWORDS = {
    "Government": ["government", "ministr", "diplomat", "embassy"],
    "Military": ["military", "armed forces", "defense ministry"],
    "Defense": ["defense", "defence", "aerospace"],
    "Financial": ["financial", "bank", "fintech"],
    "Energy": ["energy", "oil", "gas", "utilities", "power grid"],
    "Healthcare": ["healthcare", "hospital", "pharmaceutical"],
    "Technology": ["technology", "software", "semiconductor"],
    "Telecommunications": ["telecom", "telecommunication"],
    "Education": ["education", "university", "academ"],
    "Manufacturing": ["manufactur", "industrial"],
    "Media": ["media", "journalist", "press"],
}


def _heuristic_motivation(text: str) -> list[str]:
    t = (text or "").lower()
    return sorted({m for m, kws in MOTIVATION_KEYWORDS.items() if any(k in t for k in kws)})


def _heuristic_sectors(text: str) -> list[str]:
    t = (text or "").lower()
    out = []
    for sector, kws in SECTOR_KEYWORDS.items():
        if any(k in t for k in kws) and sector not in out:
            out.append(sector)
    return out


def enrich_metadata(db: Session):
    """Fill gaps in actor metadata using curated facts + description heuristics."""
    filled = 0
    for actor in db.query(ThreatActor).all():
        keys = [actor.name.lower()] + [a.lower() for a in (actor.aliases or [])]
        curated = next((CURATED[k] for k in keys if k in CURATED), None)

        changed = False
        if curated:
            nation, motiv, sectors, since, status = curated
            if nation and not actor.nation_state:
                actor.nation_state = nation; changed = True
            if motiv and not (actor.motivation or []):
                actor.motivation = motiv; changed = True
            if sectors and not (actor.targeted_sectors or []):
                actor.targeted_sectors = sectors; changed = True
            if since and not actor.active_since:
                actor.active_since = since; changed = True
            if status and (not actor.active_status or actor.active_status == "unknown"):
                actor.active_status = status; changed = True

        # Heuristics from description for whatever is still empty
        if not (actor.motivation or []):
            m = _heuristic_motivation(actor.description)
            if m:
                actor.motivation = m; changed = True
        if not (actor.targeted_sectors or []):
            s = _heuristic_sectors(actor.description)
            if s:
                actor.targeted_sectors = s; changed = True

        if changed:
            filled += 1

    db.commit()
    logger.info(f"✓ Metadata backfill: updated {filled} actors")
    return filled
