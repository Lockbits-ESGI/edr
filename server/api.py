"""FastAPI router with all server endpoints."""

import logging
import time
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from server.database import get_db
from server.config import get_settings
from server.ratelimit import limiter
from server.schemas import (
    EventResponse,
    AgentResponse,
    StatsResponse,
    HealthResponse,
    BatchIngestResponse,
)
from server import storage, vt_worker
from server.metrics import (
    events_ingested_total,
    events_ingested_batch_size,
    agents_registered_total,
    db_health,
    auth_failures_total,
)
from shared.event_schema import MiniEDREvent

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter()

_startup_time = time.time()
_vt_worker: Optional[vt_worker.VTWorker] = None


def _extract_event_view_fields(
    event_type: str, platform_name: str, payload: dict, tags: list[str]
) -> dict:
    """Build derived event fields for API consumers and dashboard views."""
    filepath = None
    event_action = None
    suspicious_file = False

    if isinstance(payload, dict):
        filepath = payload.get("filepath")
        event_action = payload.get("event_action")

    # Simple first-pass suspicious heuristics for FIM and scan events.
    suspicious_suffixes = (
        ".exe",
        ".dll",
        ".bat",
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".scr",
        ".dmg",
        ".pkg",
        ".app",
        ".command",
        ".sh",
    )
    suspicious_path_markers = (
        "/tmp/",
        "/var/tmp/",
        "/private/tmp/",
        "\\temp\\",
        "\\appdata\\local\\temp\\",
        "startup",
        "launchagents",
        "launchdaemons",
    )

    if isinstance(filepath, str) and filepath:
        lower_path = filepath.lower()
        suspicious_file = lower_path.endswith(suspicious_suffixes) or any(
            marker in lower_path for marker in suspicious_path_markers
        )

    if event_type == "fim" and isinstance(event_action, str):
        if event_action in {"created", "moved"} and any(
            t in tags for t in ["created", "moved"]
        ):
            suspicious_file = True

    return {
        "os": platform_name,
        "event_action": event_action,
        "filepath": filepath,
        "suspicious_file": suspicious_file,
    }


def get_vt_worker() -> Optional[vt_worker.VTWorker]:
    """Get VirusTotal worker instance."""
    global _vt_worker
    if _vt_worker is None and settings.VT_ENABLED and settings.VT_API_KEY:
        _vt_worker = vt_worker.VTWorker(settings.VT_API_KEY)
    return _vt_worker


def verify_auth(authorization: Optional[str] = None) -> bool:
    if not settings.AUTH_TOKEN:
        return True

    if not authorization:
        auth_failures_total.inc()
        raise HTTPException(status_code=401, detail="Missing authorization header")

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer" or token != settings.AUTH_TOKEN:
            auth_failures_total.inc()
            raise HTTPException(status_code=401, detail="Invalid token")
    except ValueError:
        auth_failures_total.inc()
        raise HTTPException(status_code=401, detail="Invalid authorization format")

    return True


@router.get("/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db)) -> HealthResponse:
    uptime = time.time() - _startup_time

    try:
        db.execute(text("SELECT 1"))
        db_ok = True
        db_health.set(1)
    except Exception:
        db_ok = False
        db_health.set(0)

    return HealthResponse(
        status="ok",
        version="1.0.0",
        db_ok=db_ok,
        uptime=uptime,
        timestamp=datetime.utcnow(),
    )


@router.post("/api/v1/events", status_code=201)
@limiter.limit("60/minute")
async def ingest_event(
    request: Request,
    event_data: dict,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(None),
) -> dict:
    """Receive and store single event from agent."""
    verify_auth(authorization)

    try:
        event = MiniEDREvent(**event_data)
        stored = storage.store_event(db, event)

        # Schedule VT enrichment if hash present
        if settings.VT_ENABLED:
            payload = event.payload
            if isinstance(payload, dict) and "hash_sha256" in payload:
                vt = get_vt_worker()
                if vt:
                    import asyncio

                    asyncio.create_task(
                        vt.enrich_event(db, event.event_id, payload.get("hash_sha256"))
                    )

        events_ingested_total.labels(event_type=event.event_type).inc()
        logger.info(f"Event stored: {event.event_id} from {event.agent_id}")
        return {"event_id": stored.event_id, "accepted": True}

    except Exception as e:
        events_ingested_total.labels(event_type="error").inc()
        logger.error(f"Event ingest failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post(
    "/api/v1/events/batch", status_code=201, response_model=BatchIngestResponse
)
@limiter.limit("30/minute")
async def ingest_batch(
    request: Request,
    batch_data: dict,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(None),
) -> BatchIngestResponse:
    """Receive and store batch of events."""
    verify_auth(authorization)

    events = batch_data.get("events", [])
    accepted = 0
    rejected = 0
    errors = []

    for event_data in events:
        try:
            event = MiniEDREvent(**event_data)
            storage.store_event(db, event)
            accepted += 1

            # Schedule VT enrichment
            if settings.VT_ENABLED:
                payload = event.payload
                if isinstance(payload, dict) and "hash_sha256" in payload:
                    vt = get_vt_worker()
                    if vt:
                        import asyncio

                        asyncio.create_task(
                            vt.enrich_event(
                                db, event.event_id, payload.get("hash_sha256")
                            )
                        )

        except Exception as e:
            rejected += 1
            errors.append(str(e))
            logger.error(f"Batch event rejected: {e}")

    events_ingested_total.labels(event_type="batch").inc(accepted)
    events_ingested_batch_size.observe(accepted)
    logger.info(f"Batch processed: {accepted} accepted, {rejected} rejected")
    return BatchIngestResponse(accepted=accepted, rejected=rejected, errors=errors)


@router.post("/api/v1/heartbeat")
@limiter.limit("30/minute")
def heartbeat(
    request: Request,
    hb_data: dict,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(None),
) -> dict:
    """Agent heartbeat and registration."""
    verify_auth(authorization)

    try:
        agent_id = hb_data.get("agent_id")
        hostname = hb_data.get("hostname")
        platform = hb_data.get("platform")
        version = hb_data.get("agent_version", "1.0.0")

        storage.upsert_agent(db, agent_id, hostname, platform, version)
        agents_registered_total.inc()
        logger.info(f"Heartbeat from {agent_id} ({hostname})")

        return {
            "acknowledged": True,
            "server_time": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        logger.error(f"Heartbeat failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/api/v1/events", response_model=list[EventResponse])
@limiter.limit("60/minute")
def list_events(
    request: Request,
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    hostname: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[EventResponse]:
    """List events with optional filters."""
    filters = {}
    if agent_id:
        filters["agent_id"] = agent_id
    if event_type:
        filters["event_type"] = event_type
    if severity:
        filters["severity"] = severity
    if hostname:
        filters["hostname"] = hostname

    events = storage.get_events(db, filters, page, page_size)

    return [
        EventResponse(
            event_id=e.event_id,
            agent_id=e.agent_id,
            hostname=e.hostname,
            platform=e.platform,
            event_type=e.event_type,
            severity=e.severity,
            source=e.source,
            timestamp=e.timestamp,
            payload=payload,
            tags=tags,
            vt_status=e.vt_status,
            vt_malicious=e.vt_malicious,
            vt_suspicious=e.vt_suspicious,
            vt_undetected=e.vt_undetected,
            vt_total=e.vt_total,
            created_at=e.created_at,
            **_extract_event_view_fields(e.event_type, e.platform, payload, tags),
        )
        for e in events
        for payload, tags in [(json.loads(e.payload_json), json.loads(e.tags_json))]
    ]


@router.get("/api/v1/events/{event_id}", response_model=EventResponse)
def get_event(event_id: str, db: Session = Depends(get_db)) -> EventResponse:
    """Get single event by ID."""
    event = storage.get_event_by_id(db, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    payload = json.loads(event.payload_json)
    tags = json.loads(event.tags_json)

    return EventResponse(
        event_id=event.event_id,
        agent_id=event.agent_id,
        hostname=event.hostname,
        platform=event.platform,
        event_type=event.event_type,
        severity=event.severity,
        source=event.source,
        timestamp=event.timestamp,
        payload=payload,
        tags=tags,
        vt_status=event.vt_status,
        vt_malicious=event.vt_malicious,
        vt_suspicious=event.vt_suspicious,
        vt_undetected=event.vt_undetected,
        vt_total=event.vt_total,
        created_at=event.created_at,
        **_extract_event_view_fields(event.event_type, event.platform, payload, tags),
    )


@router.get("/api/v1/agents", response_model=list[AgentResponse])
@limiter.limit("30/minute")
def list_agents(request: Request, db: Session = Depends(get_db)) -> list[AgentResponse]:
    """List all registered agents."""
    agents = storage.get_agents(db)
    return [
        AgentResponse(
            agent_id=a.agent_id,
            hostname=a.hostname,
            platform=a.platform,
            agent_version=a.agent_version,
            first_seen=a.first_seen,
            last_seen=a.last_seen,
            status=a.status,
            ip_address=a.ip_address,
        )
        for a in agents
    ]


@router.get("/api/v1/agents/{agent_id}", response_model=AgentResponse)
def get_agent(agent_id: str, db: Session = Depends(get_db)) -> AgentResponse:
    """Get agent by ID."""
    agent = storage.get_agent_by_id(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    return AgentResponse(
        agent_id=agent.agent_id,
        hostname=agent.hostname,
        platform=agent.platform,
        agent_version=agent.agent_version,
        first_seen=agent.first_seen,
        last_seen=agent.last_seen,
        status=agent.status,
        ip_address=agent.ip_address,
    )


@router.get("/api/v1/stats", response_model=StatsResponse)
@limiter.limit("30/minute")
def get_stats(request: Request, db: Session = Depends(get_db)) -> StatsResponse:
    """Get server statistics."""
    stats = storage.get_stats(db)
    return StatsResponse(**stats)


@router.get("/dashboard", response_class=HTMLResponse)
@limiter.limit("10/minute")
def dashboard(request: Request) -> HTMLResponse:
    """Serve inline HTML dashboard."""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MiniEDR Dashboard</title>
        <style>
            body {
                margin: 0;
                padding: 20px;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                background: #1a1a1a;
                color: #e0e0e0;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            h1 {
                margin-top: 0;
                color: #64b5f6;
            }
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .stat-card {
                background: #2a2a2a;
                border: 1px solid #444;
                border-radius: 8px;
                padding: 20px;
                text-align: center;
            }
            .stat-value {
                font-size: 32px;
                font-weight: bold;
                color: #64b5f6;
            }
            .stat-label {
                font-size: 14px;
                color: #999;
                margin-top: 5px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                background: #2a2a2a;
                border-radius: 8px;
                overflow: hidden;
            }
            th {
                background: #333;
                padding: 12px;
                text-align: left;
                color: #64b5f6;
                border-bottom: 1px solid #444;
            }
            td {
                padding: 12px;
                border-bottom: 1px solid #444;
            }
            tr:hover {
                background: #333;
            }
            .severity-low { color: #4caf50; }
            .severity-medium { color: #ffc107; }
            .severity-high { color: #ff9800; }
            .severity-critical { color: #f44336; }
            .status-online { color: #4caf50; }
            .status-offline { color: #999; }
            .refresh-info {
                color: #666;
                font-size: 12px;
                margin-top: 10px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>MiniEDR Dashboard</h1>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value" id="stat-agents">0</div>
                    <div class="stat-label">Agents</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-events">0</div>
                    <div class="stat-label">Total Events</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-events-24h">0</div>
                    <div class="stat-label">Events (24h)</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-alerts">0</div>
                    <div class="stat-label">VT Alerts</div>
                </div>
            </div>
            
            <h2>Recent Events</h2>
            <table id="events-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Agent</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>Type</th>
                        <th>Action</th>
                        <th>Suspicious File</th>
                        <th>Filepath</th>
                        <th>Severity</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
            
            <div class="refresh-info">Auto-refreshing every 30 seconds...</div>
        </div>
        
        <script>
            async function refreshDashboard() {
                try {
                    const statsRes = await fetch('/api/v1/stats');
                    const stats = await statsRes.json();
                    document.getElementById('stat-agents').textContent = stats.total_agents;
                    document.getElementById('stat-events').textContent = stats.total_events;
                    document.getElementById('stat-events-24h').textContent = stats.events_24h;
                    document.getElementById('stat-alerts').textContent = stats.vt_alerts;
                    
                    const eventsRes = await fetch('/api/v1/events?page=1&page_size=20');
                    const events = await eventsRes.json();
                    
                    const tbody = document.querySelector('#events-table tbody');
                    tbody.innerHTML = '';
                    
                    for (const event of events) {
                        const row = document.createElement('tr');
                        const ts = new Date(event.timestamp).toLocaleString();
                        const severityClass = `severity-${event.severity}`;
                        const suspiciousLabel = event.suspicious_file ? 'yes' : 'no';
                        const suspiciousColor = event.suspicious_file ? '#f44336' : '#4caf50';
                        const action = event.event_action || '-';
                        const filepath = event.filepath || '-';
                        
                        row.innerHTML = `
                            <td>${ts}</td>
                            <td>${event.agent_id.substring(0, 8)}</td>
                            <td>${event.hostname}</td>
                            <td>${event.os || event.platform}</td>
                            <td>${event.event_type}</td>
                            <td>${action}</td>
                            <td style="color:${suspiciousColor}; font-weight:600;">${suspiciousLabel}</td>
                            <td>${filepath}</td>
                            <td class="${severityClass}">${event.severity}</td>
                            <td>${event.vt_status}</td>
                        `;
                        tbody.appendChild(row);
                    }
                } catch (e) {
                    console.error('Dashboard refresh failed:', e);
                }
            }
            
            refreshDashboard();
            setInterval(refreshDashboard, 30000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)
