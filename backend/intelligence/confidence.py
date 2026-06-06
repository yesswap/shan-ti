"""
Confidence corroboration engine.

Raises confidence when evidence agrees:
  - Indicators seen multiple times (corroboration_count) and/or attributed to a
    known actor are scored higher and promoted up the ConfidenceLevel ladder.
  - Actors backed by more independent sources get a higher overall_confidence.
Also de-duplicates indicators that share the same (value, type).
"""
import logging

from sqlalchemy import func
from sqlalchemy.orm import Session

from models import ThreatActor, Indicator, ConfidenceLevel

logger = logging.getLogger(__name__)


def _level_for(score: float) -> ConfidenceLevel:
    if score >= 0.85:
        return ConfidenceLevel.CONFIRMED
    if score >= 0.70:
        return ConfidenceLevel.HIGH
    if score >= 0.50:
        return ConfidenceLevel.MEDIUM
    if score >= 0.30:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.UNKNOWN


def _indicator_score(corroboration: int, actor_linked: bool) -> float:
    # Base ladder on how many times the IOC has been independently seen
    base = {1: 0.35, 2: 0.55, 3: 0.70}.get(corroboration, 0.85 if corroboration >= 4 else 0.30)
    if actor_linked:
        base += 0.05  # attribution to a tracked actor is corroborating signal
    return round(min(base, 0.95), 2)


def _dedupe_indicators(db: Session) -> int:
    """Collapse duplicate (value, type) indicators into one, summing corroboration."""
    dupes = (
        db.query(Indicator.value, Indicator.type, func.count(Indicator.id))
        .group_by(Indicator.value, Indicator.type)
        .having(func.count(Indicator.id) > 1)
        .all()
    )
    removed = 0
    for value, itype, _count in dupes:
        rows = (
            db.query(Indicator)
            .filter(Indicator.value == value, Indicator.type == itype)
            .order_by(Indicator.corroboration_count.desc())
            .all()
        )
        keeper, others = rows[0], rows[1:]
        for o in others:
            keeper.corroboration_count += o.corroboration_count
            if not keeper.actor_id and o.actor_id:
                keeper.actor_id = o.actor_id
            db.delete(o)
            removed += 1
    if removed:
        db.commit()
    return removed


def run_corroboration(db: Session):
    """Recompute confidence across indicators and actors; dedupe indicators."""
    removed = _dedupe_indicators(db)

    # ── Indicators ───────────────────────────────────────────────────────────
    ind_updated = 0
    for ind in db.query(Indicator).all():
        score = _indicator_score(ind.corroboration_count or 1, ind.actor_id is not None)
        level = _level_for(score)
        if ind.confidence_score != score or ind.confidence != level:
            ind.confidence_score = score
            ind.confidence = level
            ind_updated += 1
    db.commit()

    # ── Actors: more independent sources -> higher overall confidence ─────────
    actor_updated = 0
    for actor in db.query(ThreatActor).all():
        n_sources = len(actor.sources or [])
        score = round(min(0.98, max(0.5, 0.82 + 0.04 * n_sources)), 2)
        if actor.overall_confidence != score:
            actor.overall_confidence = score
            actor_updated += 1
    db.commit()

    logger.info(
        f"✓ Corroboration: {ind_updated} indicators rescored, "
        f"{actor_updated} actors rescored, {removed} duplicate IOCs merged"
    )
    return {"indicators": ind_updated, "actors": actor_updated, "deduped": removed}
