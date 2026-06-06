"""
MITRE ATT&CK ingestion — pulls all intrusion sets (APT groups) via the free ATT&CK STIX API.
No API key required. Data is refreshed periodically.
"""
import requests
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from models import ThreatActor, TTP, MalwareFamily, IngestSource

logger = logging.getLogger(__name__)

MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


def _get_obj(bundle: dict, obj_id: str) -> dict:
    for obj in bundle.get("objects", []):
        if obj.get("id") == obj_id:
            return obj
    return {}


def _extract_aliases(obj: dict) -> list[str]:
    aliases = obj.get("aliases", []) or obj.get("x_mitre_aliases", [])
    name = obj.get("name", "")
    return [a for a in aliases if a != name]


def _extract_sectors(obj: dict) -> list[str]:
    """Extract targeted industry sectors from x_mitre_sectors."""
    return obj.get("x_mitre_sectors", []) or []


def _extract_regions(obj: dict) -> list[str]:
    return obj.get("x_mitre_regions", []) or []


def ingest_mitre(db: Session):
    """
    Downloads MITRE ATT&CK enterprise bundle and upserts:
    - ThreatActor records (intrusion-set objects)
    - TTP records (technique relationships)
    - MalwareFamily records (malware objects + relationships)
    """
    source_record = db.query(IngestSource).filter(IngestSource.name == "MITRE ATT&CK").first()
    if not source_record:
        source_record = IngestSource(name="MITRE ATT&CK", type="api", url=MITRE_ENTERPRISE_URL)
        db.add(source_record)
        db.commit()

    logger.info("Fetching MITRE ATT&CK bundle...")
    try:
        resp = requests.get(MITRE_ENTERPRISE_URL, timeout=60)
        resp.raise_for_status()
        bundle = resp.json()
    except Exception as e:
        logger.error(f"MITRE fetch failed: {e}")
        source_record.last_run_status = "error"
        source_record.error_message = str(e)
        db.commit()
        return

    objects = bundle.get("objects", [])
    obj_map = {o["id"]: o for o in objects}

    # ── Collect relationships ────────────────────────────────────────────────
    # Relationship: intrusion-set → uses → attack-pattern (TTP)
    # Relationship: intrusion-set → uses → malware
    actor_ttp_rels: dict[str, list] = {}    # actor_stix_id → [technique_stix_ids]
    actor_malware_rels: dict[str, list] = {}

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        if "intrusion-set" in src:
            if "attack-pattern" in tgt:
                actor_ttp_rels.setdefault(src, []).append(tgt)
            elif "malware" in tgt or "tool" in tgt:
                actor_malware_rels.setdefault(src, []).append(tgt)

    # ── Ingest intrusion sets ────────────────────────────────────────────────
    ingested = 0
    for obj in objects:
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        stix_id = obj["id"]
        name = obj.get("name", "Unknown")
        mitre_id = next(
            (ref["external_id"] for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"),
            None,
        )
        description = obj.get("description", "")
        aliases = _extract_aliases(obj)
        sectors = _extract_sectors(obj)
        regions = _extract_regions(obj)
        source_urls = [ref.get("url") for ref in obj.get("external_references", []) if ref.get("url")]

        # Extract nation state from description heuristic (MITRE doesn't always tag)
        nation_state = _guess_nation_state(name, aliases, description)

        # Upsert actor
        actor = db.query(ThreatActor).filter(ThreatActor.stix_id == stix_id).first()
        if not actor:
            actor = ThreatActor(stix_id=stix_id)
            db.add(actor)

        actor.name = name
        actor.mitre_id = mitre_id
        actor.aliases = aliases
        actor.description = description[:4000] if description else ""
        actor.targeted_sectors = sectors
        actor.targeted_regions = regions
        actor.nation_state = nation_state
        actor.sources = ["MITRE ATT&CK"]
        actor.source_urls = source_urls[:10]
        actor.active_status = "inactive" if obj.get("x_mitre_deprecated") else "unknown"
        actor.overall_confidence = 0.9  # MITRE is high quality
        db.flush()

        # ── TTPs ────────────────────────────────────────────────────────────
        ttp_ids = actor_ttp_rels.get(stix_id, [])
        for tid in ttp_ids:
            technique = obj_map.get(tid)
            if not technique:
                continue
            ext_id = next(
                (r["external_id"] for r in technique.get("external_references", []) if r.get("source_name") == "mitre-attack"),
                None,
            )
            tactic = ""
            if technique.get("kill_chain_phases"):
                tactic = technique["kill_chain_phases"][0].get("phase_name", "").replace("-", " ").title()

            existing_ttp = db.query(TTP).filter(
                TTP.actor_id == actor.id, TTP.technique_id == ext_id
            ).first()
            if not existing_ttp and ext_id:
                db.add(TTP(
                    actor_id=actor.id,
                    technique_id=ext_id,
                    technique_name=technique.get("name", ""),
                    tactic=tactic,
                    description=technique.get("description", "")[:1000],
                    source="MITRE ATT&CK",
                ))

        # ── Malware families ────────────────────────────────────────────────
        malware_ids = actor_malware_rels.get(stix_id, [])
        for mid in malware_ids:
            malware = obj_map.get(mid)
            if not malware:
                continue
            mname = malware.get("name", "")
            existing_m = db.query(MalwareFamily).filter(
                MalwareFamily.actor_id == actor.id, MalwareFamily.name == mname
            ).first()
            if not existing_m:
                db.add(MalwareFamily(
                    actor_id=actor.id,
                    name=mname,
                    aliases=malware.get("x_mitre_aliases", []),
                    type=malware.get("x_mitre_platforms", [""])[0] if malware.get("x_mitre_platforms") else "",
                    description=malware.get("description", "")[:1000],
                    source="MITRE ATT&CK",
                ))

        ingested += 1

    db.commit()

    source_record.last_run_at = datetime.now(timezone.utc)
    source_record.last_run_status = "success"
    source_record.records_ingested = ingested
    db.commit()

    logger.info(f"✓ MITRE ATT&CK: ingested {ingested} threat actors")


def _guess_nation_state(name: str, aliases: list, description: str) -> str | None:
    """Heuristic nation-state detection from actor name/description."""
    text = (name + " " + " ".join(aliases) + " " + description).lower()
    nation_map = {
        "China": ["apt1", "apt10", "apt17", "apt40", "apt41", "bronze", "gothic panda", "double dragon", "stone panda", "axiom", "winnti", "deep panda", "chinese", "china"],
        "Russia": ["apt28", "apt29", "sandworm", "fancy bear", "cozy bear", "voodoo bear", "ember bear", "berserk bear", "russian", "russia", "gru", "fsb", "svr"],
        "North Korea": ["lazarus", "apt38", "kimsuky", "andariel", "bluenoroff", "hidden cobra", "north korea", "dprk"],
        "Iran": ["apt33", "apt34", "apt35", "apt39", "charming kitten", "phosphorus", "cobalt kitty", "iranian", "iran", "irgc"],
        "Vietnam": ["apt32", "ocean lotus", "vietnamese"],
        "Pakistan": ["apt36", "transparent tribe", "pakistani"],
        "India": ["apt-c-35", "donot team", "sidewinder"],
        "Israel": ["aptc-23", "desert falcons"],
        "Turkey": ["sea turtle", "silicon", "turkish"],
    }
    for nation, keywords in nation_map.items():
        if any(kw in text for kw in keywords):
            return nation
    return None
