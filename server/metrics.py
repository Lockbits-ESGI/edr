"""Prometheus metrics for MiniEDR server.

This module defines custom EDR-specific metrics in addition to the
auto-instrumentation provided by prometheus-fastapi-instrumentator.
"""

from prometheus_client import Counter, Gauge, Histogram

# ── Custom EDR Metrics ──────────────────────────────────────────────────────

# Events
events_ingested_total = Counter(
    "edr_events_ingested_total",
    "Total number of events ingested",
    labelnames=["event_type"],
)

events_ingested_batch_size = Histogram(
    "edr_events_ingested_batch_size",
    "Batch size of ingested events",
    buckets=[1, 5, 10, 25, 50, 100, 250, 500],
)

# Heartbeats / Agents
agents_registered_total = Counter(
    "edr_agents_registered_total",
    "Total number of agent heartbeats (registrations)",
)

active_agents = Gauge(
    "edr_active_agents",
    "Number of active agents (heartbeat received within last 5 minutes)",
)

# VirusTotal enrichment
vt_enrichments_total = Counter(
    "edr_vt_enrichments_total",
    "Total number of VirusTotal enrichments performed",
    labelnames=["status"],  # "success" or "failed"
)

# Database
db_health = Gauge(
    "edr_db_health",
    "Database health status (1 = healthy, 0 = unhealthy)",
)

# Authentication
auth_failures_total = Counter(
    "edr_auth_failures_total",
    "Total number of authentication failures",
)
