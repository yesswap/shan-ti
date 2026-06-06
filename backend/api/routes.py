"""
Core threat intel API routes — all require API key authentication.

GET  /actors                 list + filter actors
GET  /actors/{id}            full actor profile
GET  /actors/{id}/indicators actor indicators with TTL info
GET  /actors/{id}/ttps       actor ATT&CK techniques
GET  /indicators             search/filter all indicators
GET  /indicators/pivot/{value} pivot from IOC to linked actors
GET  /search                 cross-entity search
GET  /stats                  platform statistics
"""
from typing import Optional, List
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_, func, and_

from database import get_db
from core.auth import get_current_user
from models import (
    ThreatActor, Indicator, TTP, MalwareFamily, Campaign,
    IndicatorType, IndicatorStatus, ConfidenceLevel
)

router = APIRouter(tags=["Threat Intelligence"])


# ─── Response Schemas ─────────────────────────────────────────────────────────

class ActorSummary(BaseModel):
    id: int
    name: str
    mitre_id: Optional[str]
    aliases: List[str]
    nation_state: Optional[str]
    motivation: List[str]
    active_status: str
    targeted_sectors: List[str]
    overall_confidence: float
    indicator_count: int
    ttp_count: int
    malware_count: int
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class IndicatorOut(BaseModel):
    id: int
    type: str
    value: str
    confidence: str
    confidence_score: float
    status: str
    tlp_level: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    expires_at: Optional[datetime]
    source: Optional[str]
    source_url: Optional[str]
    corroboration_count: int
    tags: List[str]
    actor_name: Optional[str] = None

    class Config:
        from_attributes = True


class TTPOut(BaseModel):
    technique_id: str
    technique_name: str
    tactic: Optional[str]
    description: Optional[str]
    source: Optional[str]

    class Config:
        from_attributes = True


class MalwareOut(BaseModel):
    name: str
    aliases: List[str]
    type: Optional[str]
    description: Optional[str]

    class Config:
        from_attributes = True


class ActorDetail(BaseModel):
    id: int
    name: str
    mitre_id: Optional[str]
    aliases: List[str]
    nation_state: Optional[str]
    sponsor: Optional[str]
    motivation: List[str]
    active_since: Optional[str]
    active_status: str
    targeted_sectors: List[str]
    targeted_regions: List[str]
    description: Optional[str]
    overall_confidence: float
    sources: List[str]
    source_urls: List[str]
    ttps: List[TTPOut]
    malware_families: List[MalwareOut]
    indicator_count: int
    campaign_count: int
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class PaginatedActors(BaseModel):
    total: int
    page: int
    page_size: int
    results: List[ActorSummary]


class PaginatedIndicators(BaseModel):
    total: int
    page: int
    page_size: int
    results: List[IndicatorOut]


# ─── Actors ───────────────────────────────────────────────────────────────────

@router.get("/actors", response_model=PaginatedActors)
def list_actors(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    nation_state: Optional[str] = Query(None),
    active_status: Optional[str] = Query(None),
    sector: Optional[str] = Query(None),
    search: Optional[str] = Query(None, min_length=2),
    auth=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all threat actors with optional filters."""
    q = db.query(ThreatActor)

    if nation_state:
        q = q.filter(ThreatActor.nation_state.ilike(f"%{nation_state}%"))
    if active_status:
        q = q.filter(ThreatActor.active_status == active_status)
    if sector:
        q = q.filter(ThreatActor.targeted_sectors.contains([sector]))
    if search:
        search_term = f"%{search}%"
        q = q.filter(
            or_(
                ThreatActor.name.ilike(search_term),
                ThreatActor.description.ilike(search_term),
                ThreatActor.nation_state.ilike(search_term),
            )
        )

    total = q.count()
    actors = q.order_by(ThreatActor.name).offset((page - 1) * page_size).limit(page_size).all()

    results = []
    for actor in actors:
        ioc_count = db.query(func.count(Indicator.id)).filter(Indicator.actor_id == actor.id).scalar() or 0
        ttp_count = db.query(func.count(TTP.id)).filter(TTP.actor_id == actor.id).scalar() or 0
        mal_count = db.query(func.count(MalwareFamily.id)).filter(MalwareFamily.actor_id == actor.id).scalar() or 0
        results.append(ActorSummary(
            id=actor.id,
            name=actor.name,
            mitre_id=actor.mitre_id,
            aliases=actor.aliases or [],
            nation_state=actor.nation_state,
            motivation=actor.motivation or [],
            active_status=actor.active_status or "unknown",
            targeted_sectors=actor.targeted_sectors or [],
            overall_confidence=actor.overall_confidence or 0.0,
            indicator_count=ioc_count,
            ttp_count=ttp_count,
            malware_count=mal_count,
            updated_at=actor.updated_at,
        ))

    return PaginatedActors(total=total, page=page, page_size=page_size, results=results)


@router.get("/actors/{actor_id}", response_model=ActorDetail)
def get_actor(actor_id: int, auth=Depends(get_current_user), db: Session = Depends(get_db)):
    """Full actor profile with TTPs and malware families."""
    actor = (
        db.query(ThreatActor)
        .options(joinedload(ThreatActor.ttps), joinedload(ThreatActor.malware_families))
        .filter(ThreatActor.id == actor_id)
        .first()
    )
    if not actor:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": f"Actor {actor_id} not found."})

    ioc_count = db.query(func.count(Indicator.id)).filter(Indicator.actor_id == actor.id).scalar() or 0
    campaign_count = db.query(func.count(Campaign.id)).filter(Campaign.actor_id == actor.id).scalar() or 0

    return ActorDetail(
        id=actor.id,
        name=actor.name,
        mitre_id=actor.mitre_id,
        aliases=actor.aliases or [],
        nation_state=actor.nation_state,
        sponsor=actor.sponsor,
        motivation=actor.motivation or [],
        active_since=actor.active_since,
        active_status=actor.active_status or "unknown",
        targeted_sectors=actor.targeted_sectors or [],
        targeted_regions=actor.targeted_regions or [],
        description=actor.description,
        overall_confidence=actor.overall_confidence or 0.0,
        sources=actor.sources or [],
        source_urls=actor.source_urls or [],
        ttps=[TTPOut(
            technique_id=t.technique_id,
            technique_name=t.technique_name,
            tactic=t.tactic,
            description=t.description,
            source=t.source,
        ) for t in (actor.ttps or [])],
        malware_families=[MalwareOut(
            name=m.name,
            aliases=m.aliases or [],
            type=m.type,
            description=m.description,
        ) for m in (actor.malware_families or [])],
        indicator_count=ioc_count,
        campaign_count=campaign_count,
        updated_at=actor.updated_at,
    )


@router.get("/actors/{actor_id}/indicators", response_model=PaginatedIndicators)
def get_actor_indicators(
    actor_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ioc_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None, description="fresh|stale|expired"),
    include_expired: bool = Query(False),
    auth=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """All indicators associated with a threat actor."""
    actor = db.query(ThreatActor).filter(ThreatActor.id == actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail={"error": "not_found"})

    q = db.query(Indicator).filter(Indicator.actor_id == actor_id)

    if not include_expired:
        q = q.filter(Indicator.status != IndicatorStatus.EXPIRED)
    if ioc_type:
        q = q.filter(Indicator.type == ioc_type)
    if status:
        q = q.filter(Indicator.status == status)

    total = q.count()
    indicators = q.order_by(Indicator.last_seen.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return PaginatedIndicators(
        total=total, page=page, page_size=page_size,
        results=[_indicator_out(ind, actor.name) for ind in indicators]
    )


@router.get("/actors/{actor_id}/ttps", response_model=List[TTPOut])
def get_actor_ttps(actor_id: int, auth=Depends(get_current_user), db: Session = Depends(get_db)):
    """ATT&CK techniques used by the actor."""
    ttps = db.query(TTP).filter(TTP.actor_id == actor_id).order_by(TTP.tactic, TTP.technique_id).all()
    return [TTPOut(
        technique_id=t.technique_id,
        technique_name=t.technique_name,
        tactic=t.tactic,
        description=t.description,
        source=t.source,
    ) for t in ttps]


# ─── Indicators ───────────────────────────────────────────────────────────────

@router.get("/indicators", response_model=PaginatedIndicators)
def list_indicators(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ioc_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    confidence: Optional[str] = Query(None),
    include_expired: bool = Query(False),
    auth=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Indicator)
    if not include_expired:
        q = q.filter(Indicator.status != IndicatorStatus.EXPIRED)
    if ioc_type:
        q = q.filter(Indicator.type == ioc_type)
    if status:
        q = q.filter(Indicator.status == status)
    if confidence:
        q = q.filter(Indicator.confidence == confidence)

    total = q.count()
    indicators = q.order_by(Indicator.last_seen.desc()).offset((page - 1) * page_size).limit(page_size).all()

    actor_names = {}
    for ind in indicators:
        if ind.actor_id and ind.actor_id not in actor_names:
            a = db.query(ThreatActor.name).filter(ThreatActor.id == ind.actor_id).scalar()
            actor_names[ind.actor_id] = a

    return PaginatedIndicators(
        total=total, page=page, page_size=page_size,
        results=[_indicator_out(ind, actor_names.get(ind.actor_id)) for ind in indicators]
    )


@router.get("/indicators/pivot/{value}")
def pivot_indicator(value: str, auth=Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Given any IOC value — find all linked actors, campaigns, and related IOCs.
    The "pivot" feature: from any indicator, jump to everything connected.
    """
    indicators = db.query(Indicator).filter(Indicator.value == value).all()
    if not indicators:
        return {"value": value, "found": False, "actors": [], "campaigns": [], "related_indicators": []}

    actor_ids = {ind.actor_id for ind in indicators if ind.actor_id}
    actors = []
    for aid in actor_ids:
        a = db.query(ThreatActor).filter(ThreatActor.id == aid).first()
        if a:
            actors.append({"id": a.id, "name": a.name, "nation_state": a.nation_state, "mitre_id": a.mitre_id})

    # Related IOCs from same actors
    related = []
    for aid in list(actor_ids)[:3]:
        others = (
            db.query(Indicator)
            .filter(Indicator.actor_id == aid, Indicator.value != value, Indicator.status != IndicatorStatus.EXPIRED)
            .order_by(Indicator.confidence_score.desc())
            .limit(10)
            .all()
        )
        for o in others:
            related.append({"type": o.type, "value": o.value, "confidence": o.confidence, "status": o.status})

    return {
        "value": value,
        "found": True,
        "indicator_types": list({ind.type for ind in indicators}),
        "actors": actors,
        "corroboration_count": max(ind.corroboration_count for ind in indicators),
        "first_seen": min((ind.first_seen for ind in indicators if ind.first_seen), default=None),
        "last_seen": max((ind.last_seen for ind in indicators if ind.last_seen), default=None),
        "sources": list({ind.source for ind in indicators if ind.source}),
        "related_indicators": related[:20],
    }


# ─── Search ───────────────────────────────────────────────────────────────────

@router.get("/search")
def search(
    q: str = Query(..., min_length=2, description="Search actors, IOCs, malware, CVEs"),
    auth=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Cross-entity search across actors, indicators, and malware."""
    term = f"%{q}%"

    actors = db.query(ThreatActor).filter(
        or_(ThreatActor.name.ilike(term), ThreatActor.description.ilike(term))
    ).limit(10).all()

    indicators = db.query(Indicator).filter(
        and_(Indicator.value.ilike(term), Indicator.status != IndicatorStatus.EXPIRED)
    ).limit(20).all()

    malware = db.query(MalwareFamily).filter(MalwareFamily.name.ilike(term)).limit(10).all()

    actor_names = {}
    for ind in indicators:
        if ind.actor_id and ind.actor_id not in actor_names:
            a = db.query(ThreatActor.name).filter(ThreatActor.id == ind.actor_id).scalar()
            actor_names[ind.actor_id] = a

    return {
        "query": q,
        "actors": [{"id": a.id, "name": a.name, "nation_state": a.nation_state, "mitre_id": a.mitre_id} for a in actors],
        "indicators": [_indicator_out(ind, actor_names.get(ind.actor_id)) for ind in indicators],
        "malware": [{"name": m.name, "type": m.type, "description": m.description} for m in malware],
        "total_results": len(actors) + len(indicators) + len(malware),
    }


# ─── Stats ────────────────────────────────────────────────────────────────────

@router.get("/stats")
def get_stats(auth=Depends(get_current_user), db: Session = Depends(get_db)):
    """Platform-wide statistics."""
    actor_count = db.query(func.count(ThreatActor.id)).scalar()
    indicator_count = db.query(func.count(Indicator.id)).scalar()
    fresh_ioc_count = db.query(func.count(Indicator.id)).filter(Indicator.status == IndicatorStatus.FRESH).scalar()
    ttp_count = db.query(func.count(TTP.id)).scalar()
    malware_count = db.query(func.count(MalwareFamily.id)).scalar()

    by_nation = (
        db.query(ThreatActor.nation_state, func.count(ThreatActor.id))
        .filter(ThreatActor.nation_state != None)
        .group_by(ThreatActor.nation_state)
        .order_by(func.count(ThreatActor.id).desc())
        .limit(10)
        .all()
    )

    by_type = (
        db.query(Indicator.type, func.count(Indicator.id))
        .filter(Indicator.status != IndicatorStatus.EXPIRED)
        .group_by(Indicator.type)
        .all()
    )

    return {
        "actors": actor_count,
        "indicators": {"total": indicator_count, "fresh": fresh_ioc_count},
        "ttps": ttp_count,
        "malware_families": malware_count,
        "actors_by_nation": [{"nation": n, "count": c} for n, c in by_nation],
        "indicators_by_type": [{"type": t, "count": c} for t, c in by_type],
    }


# ─── Helper ───────────────────────────────────────────────────────────────────

def _indicator_out(ind: Indicator, actor_name: Optional[str] = None) -> IndicatorOut:
    return IndicatorOut(
        id=ind.id,
        type=ind.type,
        value=ind.value,
        confidence=ind.confidence,
        confidence_score=ind.confidence_score or 0.0,
        status=ind.status,
        tlp_level=ind.tlp_level or "white",
        first_seen=ind.first_seen,
        last_seen=ind.last_seen,
        expires_at=ind.expires_at,
        source=ind.source,
        source_url=ind.source_url,
        corroboration_count=ind.corroboration_count or 1,
        tags=ind.tags or [],
        actor_name=actor_name,
    )
