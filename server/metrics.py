"""Prometheus metrics for MiniEDR server.

Keeps the original metrics intact for backward compatibility and adds:
- Richer event counters with severity/platform labels
- FIM and scan event breakdown
- A custom DB-backed Collector (EDRDatabaseCollector) that yields fresh gauges
  for aggregate statistics (agents, events, VT, hash-cache) on every scrape.
"""

from datetime import datetime, timedelta

from prometheus_client import Counter, Gauge, Histogram
from prometheus_client import REGISTRY as _REGISTRY
from prometheus_client.core import GaugeMetricFamily
from sqlalchemy import func, and_

# ── Kept exactly as before (backward compat) ──────────────────────────────

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
    from server.database import SessionLocal
    from server.models import Agent

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

# ── New richer event counters ──────────────────────────────────────────────

events_ingested_detail_total = Counter(
    "edr_events_ingested_detail_total",
    "Events ingested (single endpoint) with full label set",
    labelnames=["event_type", "severity", "platform"],
)
events_rejected_total = Counter(
    "edr_events_rejected_total",
    "Events rejected by the single-event endpoint (validation or storage errors)",
)
batch_events_accepted_total = Counter(
    "edr_batch_events_accepted_total",
    "Events accepted via the batch endpoint with full label set",
    labelnames=["event_type", "severity", "platform"],
)
batch_events_rejected_total = Counter(
    "edr_batch_events_rejected_total",
    "Events rejected per-item by the batch endpoint (validation or storage errors)",
)

# ── FIM-specific counters ──────────────────────────────────────────────────

fim_events_total = Counter(
    "edr_fim_events_total",
    "File Integrity Monitoring events by action",
    labelnames=["action"],  # created | modified | deleted | moved
)
fim_suspicious_total = Counter(
    "edr_fim_suspicious_total",
    "FIM events on suspicious paths or executable extensions",
)

# ── Scan-specific counters ─────────────────────────────────────────────────

scan_events_total = Counter(
    "edr_scan_events_total",
    "Scan events by severity",
    labelnames=["severity"],
)

# ── Heartbeat / agent management counters ─────────────────────────────────

heartbeat_errors_total = Counter(
    "edr_heartbeat_errors_total",
    "Heartbeat requests that failed processing",
)

# ── VT enrichment detail ───────────────────────────────────────────────────

vt_malicious_found_total = Counter(
    "edr_vt_malicious_found_total",
    "Events enriched by VT with at least one malicious detection",
)
vt_suspicious_found_total = Counter(
    "edr_vt_suspicious_found_total",
    "Events enriched by VT with at least one suspicious detection",
)


# ── DB-backed custom Collector ─────────────────────────────────────────────


class EDRDatabaseCollector:
    """Custom Prometheus collector that queries the database on every scrape.

    Yields GaugeMetricFamily objects reflecting live aggregate statistics.
    Uses its own short-lived SessionLocal so it does not interfere with the
    request-scoped session used by FastAPI endpoints.
    """

    def collect(self):  # noqa: C901
        from server.database import SessionLocal
        from server.models import Agent, Event, HashCache

        db = SessionLocal()
        try:
            now = datetime.utcnow()

            # ── Agents ────────────────────────────────────────────────────
            total_agents = db.query(func.count(Agent.id)).scalar() or 0
            agents_online = (
                db.query(func.count(Agent.id))
                .filter(Agent.status == "online")
                .scalar()
                or 0
            )

            g = GaugeMetricFamily("edr_agents_total", "Total registered agents in DB")
            g.add_metric([], total_agents)
            yield g

            g = GaugeMetricFamily(
                "edr_agents_online_total", "Agents with status=online"
            )
            g.add_metric([], agents_online)
            yield g

            g = GaugeMetricFamily(
                "edr_agents_offline_total", "Agents not currently online"
            )
            g.add_metric([], max(0, total_agents - agents_online))
            yield g

            g = GaugeMetricFamily(
                "edr_agents_by_platform_total",
                "Registered agents grouped by OS platform",
                labels=["platform"],
            )
            for platform, count in (
                db.query(Agent.platform, func.count(Agent.id))
                .group_by(Agent.platform)
                .all()
            ):
                g.add_metric([platform or "unknown"], count)
            yield g

            g = GaugeMetricFamily(
                "edr_agents_by_version_total",
                "Registered agents grouped by agent version",
                labels=["version"],
            )
            for version, count in (
                db.query(Agent.agent_version, func.count(Agent.id))
                .group_by(Agent.agent_version)
                .all()
            ):
                g.add_metric([version or "unknown"], count)
            yield g

            # ── Events aggregate ──────────────────────────────────────────
            total_events = db.query(func.count(Event.id)).scalar() or 0
            g = GaugeMetricFamily(
                "edr_events_db_total", "Total events stored in the database"
            )
            g.add_metric([], total_events)
            yield g

            g = GaugeMetricFamily(
                "edr_events_by_type_total",
                "Stored events grouped by event type",
                labels=["event_type"],
            )
            for event_type, count in (
                db.query(Event.event_type, func.count(Event.id))
                .group_by(Event.event_type)
                .all()
            ):
                g.add_metric([event_type], count)
            yield g

            g = GaugeMetricFamily(
                "edr_events_by_severity_total",
                "Stored events grouped by severity level",
                labels=["severity"],
            )
            for severity, count in (
                db.query(Event.severity, func.count(Event.id))
                .group_by(Event.severity)
                .all()
            ):
                g.add_metric([severity], count)
            yield g

            g = GaugeMetricFamily(
                "edr_events_by_platform_total",
                "Stored events grouped by originating platform",
                labels=["platform"],
            )
            for platform, count in (
                db.query(Event.platform, func.count(Event.id))
                .group_by(Event.platform)
                .all()
            ):
                g.add_metric([platform or "unknown"], count)
            yield g

            # ── Time-windowed counts ───────────────────────────────────────
            g = GaugeMetricFamily(
                "edr_events_24h_total", "Events ingested in the last 24 hours"
            )
            g.add_metric(
                [],
                db.query(func.count(Event.id))
                .filter(Event.created_at >= now - timedelta(hours=24))
                .scalar()
                or 0,
            )
            yield g

            g = GaugeMetricFamily(
                "edr_events_1h_total", "Events ingested in the last hour"
            )
            g.add_metric(
                [],
                db.query(func.count(Event.id))
                .filter(Event.created_at >= now - timedelta(hours=1))
                .scalar()
                or 0,
            )
            yield g

            g = GaugeMetricFamily(
                "edr_events_5m_total", "Events ingested in the last 5 minutes"
            )
            g.add_metric(
                [],
                db.query(func.count(Event.id))
                .filter(Event.created_at >= now - timedelta(minutes=5))
                .scalar()
                or 0,
            )
            yield g

            # ── VirusTotal enrichment breakdown ───────────────────────────
            g = GaugeMetricFamily(
                "edr_vt_malicious_events_db_total",
                "Events with at least one VT malicious detection (DB aggregate)",
            )
            g.add_metric(
                [],
                db.query(func.count(Event.id))
                .filter(
                    and_(Event.vt_status == "enriched", Event.vt_malicious > 0)
                )
                .scalar()
                or 0,
            )
            yield g

            g = GaugeMetricFamily(
                "edr_vt_suspicious_events_db_total",
                "Events with at least one VT suspicious detection (DB aggregate)",
            )
            g.add_metric(
                [],
                db.query(func.count(Event.id))
                .filter(
                    and_(Event.vt_status == "enriched", Event.vt_suspicious > 0)
                )
                .scalar()
                or 0,
            )
            yield g

            g = GaugeMetricFamily(
                "edr_events_by_vt_status_total",
                "Stored events grouped by VirusTotal enrichment status",
                labels=["vt_status"],
            )
            for vt_status, count in (
                db.query(Event.vt_status, func.count(Event.id))
                .group_by(Event.vt_status)
                .all()
            ):
                g.add_metric([vt_status or "unknown"], count)
            yield g

            # ── Hash cache ────────────────────────────────────────────────
            g = GaugeMetricFamily(
                "edr_hash_cache_entries_total",
                "Total VirusTotal hash lookup cache entries",
            )
            g.add_metric([], db.query(func.count(HashCache.id)).scalar() or 0)
            yield g

            g = GaugeMetricFamily(
                "edr_hash_cache_by_verdict_total",
                "Cached hash entries grouped by VirusTotal verdict",
                labels=["verdict"],
            )
            for verdict, count in (
                db.query(HashCache.vt_status, func.count(HashCache.id))
                .group_by(HashCache.vt_status)
                .all()
            ):
                g.add_metric([verdict or "unknown"], count)
            yield g

        finally:
            db.close()


# Register the DB collector to the global registry once at import time.
# Guard against duplicate registration when the module is reloaded in tests.
try:
    _REGISTRY.register(EDRDatabaseCollector())
except ValueError:
    pass  # already registered (module reimported in the same process)
