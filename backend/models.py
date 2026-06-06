from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text,
    ForeignKey, Enum, JSON, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
import enum

Base = declarative_base()


class ConfidenceLevel(str, enum.Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IndicatorStatus(str, enum.Enum):
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"


class IndicatorType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    YARA = "yara"


class TLPLevel(str, enum.Enum):
    WHITE = "white"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


# ─── API Key System ───────────────────────────────────────────────────────────

class APIUser(Base):
    __tablename__ = "api_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=True)
    is_verified = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    plan = Column(String(50), default="free")  # free | pro | enterprise
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    usage_logs = relationship("APIUsageLog", back_populates="user")


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("api_users.id"), nullable=False)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA256 of key
    key_prefix = Column(String(8), nullable=False)                           # first 8 chars (display)
    name = Column(String(100), default="Default Key")
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Rate limit overrides (None = use plan defaults)
    rate_limit_per_minute = Column(Integer, nullable=True)
    rate_limit_per_day = Column(Integer, nullable=True)

    user = relationship("APIUser", back_populates="api_keys")
    usage_logs = relationship("APIUsageLog", back_populates="api_key")


class APIUsageLog(Base):
    __tablename__ = "api_usage_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("api_users.id"), nullable=False)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), nullable=False)
    endpoint = Column(String(255), nullable=False)
    method = Column(String(10), nullable=False)
    status_code = Column(Integer, nullable=False)
    response_time_ms = Column(Integer, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("APIUser", back_populates="usage_logs")
    api_key = relationship("APIKey", back_populates="usage_logs")

    __table_args__ = (
        Index("idx_usage_user_created", "user_id", "created_at"),
        Index("idx_usage_key_created", "api_key_id", "created_at"),
    )


class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("api_users.id"), nullable=False)
    token = Column(String(64), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ─── Threat Intel Models ──────────────────────────────────────────────────────

class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(Integer, primary_key=True, index=True)
    mitre_id = Column(String(20), unique=True, nullable=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    aliases = Column(JSON, default=list)
    nation_state = Column(String(100), nullable=True, index=True)
    sponsor = Column(String(255), nullable=True)
    motivation = Column(JSON, default=list)       # ["espionage", "financial"]
    active_since = Column(String(20), nullable=True)
    active_status = Column(String(20), default="unknown")  # active | inactive | unknown
    targeted_sectors = Column(JSON, default=list)
    targeted_regions = Column(JSON, default=list)
    description = Column(Text, nullable=True)
    overall_confidence = Column(Float, default=0.5)
    sources = Column(JSON, default=list)
    source_urls = Column(JSON, default=list)
    stix_id = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    campaigns = relationship("Campaign", back_populates="actor", cascade="all, delete-orphan")
    indicators = relationship("Indicator", back_populates="actor", cascade="all, delete-orphan")
    ttps = relationship("TTP", back_populates="actor", cascade="all, delete-orphan")
    malware_families = relationship("MalwareFamily", back_populates="actor", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_actor_nation", "nation_state"),
        Index("idx_actor_status", "active_status"),
    )


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    start_date = Column(String(20), nullable=True)
    end_date = Column(String(20), nullable=True)
    status = Column(String(20), default="unknown")  # active | concluded | unknown
    targeted_sectors = Column(JSON, default=list)
    targeted_regions = Column(JSON, default=list)
    sources = Column(JSON, default=list)
    source_urls = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    actor = relationship("ThreatActor", back_populates="campaigns")
    indicators = relationship("Indicator", back_populates="campaign")


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=True)
    type = Column(Enum(IndicatorType), nullable=False, index=True)
    value = Column(Text, nullable=False, index=True)
    confidence = Column(Enum(ConfidenceLevel), default=ConfidenceLevel.LOW)
    confidence_score = Column(Float, default=0.3)
    status = Column(Enum(IndicatorStatus), default=IndicatorStatus.FRESH, index=True)
    tlp_level = Column(Enum(TLPLevel), default=TLPLevel.WHITE)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    source = Column(String(255), nullable=True)
    source_url = Column(Text, nullable=True)
    corroboration_count = Column(Integer, default=1)
    tags = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    actor = relationship("ThreatActor", back_populates="indicators")
    campaign = relationship("Campaign", back_populates="indicators")

    __table_args__ = (
        Index("idx_indicator_value_type", "value", "type"),
        Index("idx_indicator_status_type", "status", "type"),
        Index("idx_indicator_actor_type", "actor_id", "type"),
    )


class TTP(Base):
    __tablename__ = "ttps"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=False)
    technique_id = Column(String(20), nullable=False, index=True)  # T1566.001
    technique_name = Column(String(255), nullable=False)
    tactic = Column(String(100), nullable=True, index=True)         # "Initial Access"
    description = Column(Text, nullable=True)
    source = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    actor = relationship("ThreatActor", back_populates="ttps")

    __table_args__ = (
        UniqueConstraint("actor_id", "technique_id", name="uq_actor_technique"),
    )


class MalwareFamily(Base):
    __tablename__ = "malware_families"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True)
    name = Column(String(255), nullable=False, index=True)
    aliases = Column(JSON, default=list)
    type = Column(String(50), nullable=True)  # RAT, loader, ransomware, stealer
    description = Column(Text, nullable=True)
    malpedia_id = Column(String(255), nullable=True)
    yara_rules = Column(JSON, default=list)
    source = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    actor = relationship("ThreatActor", back_populates="malware_families")


class IngestSource(Base):
    __tablename__ = "ingest_sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    type = Column(String(50), nullable=False)  # api | rss | scraper
    url = Column(Text, nullable=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_run_status = Column(String(20), nullable=True)  # success | error
    records_ingested = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
