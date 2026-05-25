"""Pydantic response schemas for FastAPI endpoints."""

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, Field


class EventResponse(BaseModel):
    """Event response with all fields and VT enrichment status."""

    event_id: str
    agent_id: str
    hostname: str
    platform: str
    event_type: str
    severity: str
    source: str
    timestamp: datetime
    payload: dict
    tags: List[str]
    vt_status: str
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_undetected: int = 0
    vt_total: int = 0
    created_at: datetime


class AgentResponse(BaseModel):
    """Agent registration and status response."""

    agent_id: str
    hostname: str
    platform: str
    agent_version: str
    first_seen: datetime
    last_seen: datetime
    status: str
    ip_address: Optional[str] = None


class StatsResponse(BaseModel):
    """Server statistics response."""

    total_events: int
    total_agents: int
    events_24h: int
    vt_alerts: int


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str
    db_ok: bool
    uptime: float
    timestamp: datetime


class BatchIngestResponse(BaseModel):
    """Batch event ingest response."""

    accepted: int
    rejected: int
    errors: List[str] = Field(default_factory=list)
