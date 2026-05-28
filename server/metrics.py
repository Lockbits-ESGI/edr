"""Prometheus metrics for MiniEDR server."""

from datetime import datetime, timedelta
from prometheus_client import Counter, Gauge, Histogram
from sqlalchemy import func
from server.database import SessionLocal
from server.models import Agent

events_ingested_total = Counter(
    "edr_events_ingested_total", "Total events ingested", labelnames=["event_type"]
)
events_ingested_batch_size = Histogram(
    "edr_events_ingested_batch_size",
    "Batch size of ingested events",
    buckets=[1, 5, 10, 25, 50, 100, 250, 500],
)
agents_registered_total = Counter(
    "edr_agents_registered_total", "Total agent heartbeats"
)


def _count_active_agents() -> float:
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(minutes=5)
        return float(
            db.query(func.count(Agent.id)).filter(Agent.last_seen >= cutoff).scalar()
            or 0
        )
    finally:
        db.close()


active_agents = Gauge("edr_active_agents", "Active agents (heartbeat within last 5min)")
active_agents.set_function(_count_active_agents)
vt_enrichments_total = Counter(
    "edr_vt_enrichments_total", "VirusTotal enrichments", labelnames=["status"]
)
db_health = Gauge("edr_db_health", "Database health (1=healthy, 0=unhealthy)")
auth_failures_total = Counter("edr_auth_failures_total", "Authentication failures")
