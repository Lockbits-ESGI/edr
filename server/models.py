"""SQLAlchemy ORM models for server persistence."""

from datetime import datetime
from sqlalchemy import Column, String, DateTime, Integer, Float, Text, ForeignKey, Index, UniqueConstraint, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class Agent(Base):
    """Registered agent metadata and status."""
    
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True)
    agent_id = Column(String(36), unique=True, nullable=False, index=True)
    hostname = Column(String(255), nullable=False)
    platform = Column(String(50), nullable=False)
    agent_version = Column(String(50), default="")
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    status = Column(String(20), default="unknown")
    ip_address = Column(String(45), default="")

    events = relationship("Event", back_populates="agent", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index("idx_agent_id", "agent_id"),
        Index("idx_hostname", "hostname"),
        Index("idx_last_seen", "last_seen"),
    )


class Event(Base):
    """Stored event from agent."""
    
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    event_id = Column(String(36), unique=True, nullable=False, index=True)
    agent_id = Column(String(36), ForeignKey("agents.agent_id"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False)
    platform = Column(String(50), nullable=False)
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), default="low", index=True)
    source = Column(String(50), default="agent")
    timestamp = Column(DateTime, nullable=False, index=True)
    payload_json = Column(Text, default="{}")
    tags_json = Column(Text, default="[]")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    agent = relationship("Agent", back_populates="events")
    
    vt_status = Column(String(20), default="pending")  # pending | enriched | skipped
    vt_malicious = Column(Integer, default=0)
    vt_suspicious = Column(Integer, default=0)
    vt_undetected = Column(Integer, default=0)
    vt_total = Column(Integer, default=0)
    
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_event_id"),
        Index("idx_event_id", "event_id"),
        Index("idx_event_agent_id", "agent_id"),
        Index("idx_timestamp", "timestamp"),
        Index("idx_event_type_severity", "event_type", "severity"),
    )


class HashCache(Base):
    """VirusTotal hash lookup cache to avoid repeated API calls."""
    
    __tablename__ = "hash_cache"
    
    id = Column(Integer, primary_key=True)
    sha256 = Column(String(64), unique=True, nullable=False, index=True)
    vt_malicious = Column(Integer, default=0)
    vt_suspicious = Column(Integer, default=0)
    vt_undetected = Column(Integer, default=0)
    vt_total = Column(Integer, default=0)
    vt_status = Column(String(20), default="notfound")  # clean | malicious | suspicious | notfound
    queried_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index("idx_sha256", "sha256"),
        Index("idx_queried_at", "queried_at"),
    )
