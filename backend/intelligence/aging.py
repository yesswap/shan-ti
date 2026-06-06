"""
IOC aging engine — marks indicators stale/expired based on their type-specific TTL.
Runs daily via APScheduler.
"""
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import and_
from models import Indicator, IndicatorStatus, IndicatorType

logger = logging.getLogger(__name__)

# Days until an IOC is considered STALE (still usable but degraded confidence)
STALE_AFTER = {
    IndicatorType.IP:      3,
    IndicatorType.DOMAIN:  14,
    IndicatorType.URL:     1,
    IndicatorType.MD5:     180,
    IndicatorType.SHA1:    180,
    IndicatorType.SHA256:  365,
    IndicatorType.EMAIL:   45,
    IndicatorType.CVE:     365,
    IndicatorType.YARA:    730,
}

# Days until EXPIRED (should be filtered out by default)
EXPIRE_AFTER = {
    IndicatorType.IP:      7,
    IndicatorType.DOMAIN:  30,
    IndicatorType.URL:     3,
    IndicatorType.MD5:     365,
    IndicatorType.SHA1:    365,
    IndicatorType.SHA256:  730,
    IndicatorType.EMAIL:   90,
    IndicatorType.CVE:     730,
    IndicatorType.YARA:    1460,
}


def run_aging(db: Session):
    """
    Scans all FRESH/STALE indicators and:
    - Marks as STALE if past stale threshold
    - Marks as EXPIRED if past expiry threshold
    """
    now = datetime.now(timezone.utc)
    stale_count = 0
    expired_count = 0

    active_indicators = (
        db.query(Indicator)
        .filter(Indicator.status != IndicatorStatus.EXPIRED)
        .all()
    )

    for ind in active_indicators:
        if not ind.last_seen:
            continue

        last_seen = ind.last_seen
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        age_days = (now - last_seen).days
        expire_days = EXPIRE_AFTER.get(ind.type, 30)
        stale_days = STALE_AFTER.get(ind.type, 14)

        if age_days >= expire_days:
            ind.status = IndicatorStatus.EXPIRED
            expired_count += 1
        elif age_days >= stale_days and ind.status == IndicatorStatus.FRESH:
            ind.status = IndicatorStatus.STALE
            stale_count += 1

    db.commit()
    logger.info(f"✓ Aging run: {stale_count} stale, {expired_count} expired")
    return stale_count, expired_count
