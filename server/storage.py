"""CRUD operations for database persistence."""

from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_

from server.models import Agent, Event, HashCache
from shared.event_schema import MiniEDREvent, VTResult


def upsert_agent(
    db: Session,
    agent_id: str,
    hostname: str,
    platform: str,
    version: str
) -> Agent:
    """Create or update agent record."""
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if agent:
        agent.hostname = hostname
        agent.platform = platform
        agent.agent_version = version
        agent.last_seen = datetime.utcnow()
        agent.status = "online"
    else:
        agent = Agent(
            agent_id=agent_id,
            hostname=hostname,
            platform=platform,
            agent_version=version,
            status="online"
        )
        db.add(agent)
    
    db.commit()
    db.refresh(agent)
    return agent


def store_event(db: Session, event: MiniEDREvent) -> Event:
    """Store event in database with vt_status pending."""
    import json
    
    event_record = Event(
        event_id=event.event_id,
        agent_id=event.agent_id,
        hostname=event.hostname,
        platform=event.platform,
        event_type=event.event_type,
        severity=event.severity,
        source=event.source,
        timestamp=datetime.fromisoformat(event.timestamp.replace('Z', '+00:00')),
        payload_json=json.dumps(event.payload),
        tags_json=json.dumps(event.tags),
        vt_status="pending"
    )
    db.add(event_record)
    db.commit()
    db.refresh(event_record)
    return event_record


def get_events(
    db: Session,
    filters: dict | None = None,
    page: int = 1,
    page_size: int = 50
) -> list[Event]:
    """Get paginated events with optional filters."""
    query = db.query(Event)
    
    if filters:
        if "agent_id" in filters:
            query = query.filter(Event.agent_id == filters["agent_id"])
        if "event_type" in filters:
            query = query.filter(Event.event_type == filters["event_type"])
        if "severity" in filters:
            query = query.filter(Event.severity == filters["severity"])
        if "hostname" in filters:
            query = query.filter(Event.hostname == filters["hostname"])
    
    query = query.order_by(Event.timestamp.desc())
    offset = (page - 1) * page_size
    return query.offset(offset).limit(page_size).all()


def get_event_by_id(db: Session, event_id: str) -> Event | None:
    """Get single event by ID."""
    return db.query(Event).filter(Event.event_id == event_id).first()


def get_agents(db: Session) -> list[Agent]:
    """Get all registered agents."""
    return db.query(Agent).order_by(Agent.last_seen.desc()).all()


def get_agent_by_id(db: Session, agent_id: str) -> Agent | None:
    """Get agent by ID."""
    return db.query(Agent).filter(Agent.agent_id == agent_id).first()


def get_hash_cache(db: Session, sha256: str) -> HashCache | None:
    """Get cached VirusTotal result for hash."""
    return db.query(HashCache).filter(HashCache.sha256 == sha256).first()


def store_hash_cache(
    db: Session,
    sha256: str,
    vt_result: VTResult
) -> HashCache:
    """Store or update hash cache entry."""
    cache = db.query(HashCache).filter(HashCache.sha256 == sha256).first()
    if cache:
        cache.vt_malicious = vt_result.malicious
        cache.vt_suspicious = vt_result.suspicious
        cache.vt_undetected = vt_result.undetected
        cache.vt_total = vt_result.total
        cache.vt_status = vt_result.status
        cache.queried_at = datetime.utcnow()
    else:
        cache = HashCache(
            sha256=sha256,
            vt_malicious=vt_result.malicious,
            vt_suspicious=vt_result.suspicious,
            vt_undetected=vt_result.undetected,
            vt_total=vt_result.total,
            vt_status=vt_result.status
        )
        db.add(cache)
    
    db.commit()
    db.refresh(cache)
    return cache


def update_event_vt_status(
    db: Session,
    event_id: str,
    status: str,
    vt_result: VTResult | None = None
) -> Event | None:
    """Update event VT enrichment status."""
    event = db.query(Event).filter(Event.event_id == event_id).first()
    if not event:
        return None
    
    event.vt_status = status
    if vt_result:
        event.vt_malicious = vt_result.malicious
        event.vt_suspicious = vt_result.suspicious
        event.vt_undetected = vt_result.undetected
        event.vt_total = vt_result.total
    
    db.commit()
    db.refresh(event)
    return event


def get_stats(db: Session) -> dict:
    """Get server statistics."""
    total_events = db.query(func.count(Event.id)).scalar() or 0
    total_agents = db.query(func.count(Agent.id)).scalar() or 0
    
    last_24h = datetime.utcnow() - timedelta(days=1)
    events_24h = db.query(func.count(Event.id)).filter(
        Event.created_at >= last_24h
    ).scalar() or 0
    
    vt_alerts = db.query(func.count(Event.id)).filter(
        and_(Event.vt_status == "enriched", Event.vt_malicious > 0)
    ).scalar() or 0
    
    return {
        "total_events": total_events,
        "total_agents": total_agents,
        "events_24h": events_24h,
        "vt_alerts": vt_alerts
    }
