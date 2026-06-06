"""
Malpedia ingestion — pulls the public family dump
(https://malpedia.caad.fkie.fraunhofer.de/api/get/families). No API key required.

Two enrichments:
  1. Enrich malware families we already have (from MITRE) with Malpedia
     descriptions, aliases (alt_names) and a malpedia_id.
  2. Create malware<->actor links from Malpedia's `attribution` field, so
     known malware gets attached to the right actor in our DB.
"""
import logging
from datetime import datetime, timezone

import requests
from sqlalchemy.orm import Session

from models import ThreatActor, MalwareFamily, IngestSource

logger = logging.getLogger(__name__)

MALPEDIA_FAMILIES_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/families"


def _norm(s: str) -> str:
    return " ".join((s or "").lower().split())


def _build_actor_index(db: Session) -> dict[str, ThreatActor]:
    idx: dict[str, ThreatActor] = {}
    for actor in db.query(ThreatActor).all():
        for name in [actor.name] + list(actor.aliases or []):
            n = _norm(name)
            if n and n not in idx:
                idx[n] = actor
    return idx


def ingest_malpedia(db: Session):
    source = db.query(IngestSource).filter(IngestSource.name == "Malpedia").first()
    if not source:
        source = IngestSource(name="Malpedia", type="api", url=MALPEDIA_FAMILIES_URL)
        db.add(source)
        db.commit()

    logger.info("Fetching Malpedia family dump...")
    try:
        resp = requests.get(MALPEDIA_FAMILIES_URL, timeout=90)
        resp.raise_for_status()
        families = resp.json()
    except Exception as e:
        logger.error(f"Malpedia fetch failed: {e}")
        source.last_run_status = "error"
        source.error_message = str(e)
        db.commit()
        return

    actor_index = _build_actor_index(db)

    # Existing malware in our DB, indexed by name + aliases (for enrichment)
    malware_index: dict[str, list[MalwareFamily]] = {}
    for m in db.query(MalwareFamily).all():
        for name in [m.name] + list(m.aliases or []):
            malware_index.setdefault(_norm(name), []).append(m)

    enriched = 0
    linked = 0
    created = 0

    for key, fam in families.items():
        common = fam.get("common_name") or key.split(".")[-1]
        alt_names = fam.get("alt_names") or []
        description = (fam.get("description") or "").strip()
        attribution = fam.get("attribution") or []

        fam_names = [_norm(common)] + [_norm(a) for a in alt_names]

        # ── 1. Enrich any existing malware we already track ──────────────────
        seen_ids = set()
        for fn in fam_names:
            for m in malware_index.get(fn, []):
                if m.id in seen_ids:
                    continue
                seen_ids.add(m.id)
                if not m.malpedia_id:
                    m.malpedia_id = key
                if description and not (m.description or "").strip():
                    m.description = description[:1000]
                merged = list(m.aliases or [])
                for a in alt_names:
                    if a and a != m.name and a not in merged:
                        merged.append(a)
                m.aliases = merged
                if not m.source:
                    m.source = "Malpedia"
                enriched += 1

        # ── 2. Attribution -> ensure malware is linked to the actor ──────────
        for actor_name in attribution:
            actor = actor_index.get(_norm(actor_name))
            if not actor:
                continue
            # Already have this malware under the actor?
            existing = (
                db.query(MalwareFamily)
                .filter(MalwareFamily.actor_id == actor.id, MalwareFamily.name == common)
                .first()
            )
            if existing:
                if not existing.malpedia_id:
                    existing.malpedia_id = key
                    linked += 1
                continue
            db.add(MalwareFamily(
                actor_id=actor.id,
                name=common,
                aliases=alt_names[:10],
                type=key.split(".")[0] if "." in key else None,  # platform (win/elf/apk/...)
                description=description[:1000] if description else None,
                malpedia_id=key,
                source="Malpedia",
            ))
            created += 1
            linked += 1

    db.commit()
    source.last_run_at = datetime.now(timezone.utc)
    source.last_run_status = "success"
    source.records_ingested = created
    db.commit()
    logger.info(
        f"✓ Malpedia: enriched {enriched} families, "
        f"created {created} new, {linked} actor links"
    )
    return {"enriched": enriched, "created": created, "linked": linked}
