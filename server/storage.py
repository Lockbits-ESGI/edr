"""CRUD operations for database persistence."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from sqlalchemy.exc import IntegrityError

from server.models import Agent, Event, HashCache
from shared.event_schema import MiniEDREvent, VTResult
from shared.tags import extract_company_from_tags, merge_company_tag, normalize_company


@dataclass(frozen=True)
class StoreEventResult:
    """Result of an idempotent event insert."""

    record: Event
    event: MiniEDREvent
    created: bool


def upsert_agent(
    db: Session,
    agent_id: str,
    hostname: str,
    platform: str,
    version: str,
    company: str = "",
) -> Agent:
    """Create or update agent record."""
    company = normalize_company(company)
    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if agent:
        agent.hostname = hostname
        agent.platform = platform
        agent.agent_version = version
        if company:
            agent.company = company
        agent.last_seen = datetime.utcnow()
        agent.status = "online"
    else:
        agent = Agent(
            agent_id=agent_id,
            hostname=hostname,
            platform=platform,
            agent_version=version,
            company=company,
            status="online",
        )
        db.add(agent)

    db.commit()
    db.refresh(agent)
    return agent


def store_event(db: Session, event: MiniEDREvent) -> Event:
    """Store event in database with vt_status pending."""
    return store_event_once(db, event).record


def store_event_once(db: Session, event: MiniEDREvent) -> StoreEventResult:
    """Store an event once, treating duplicate event_ids as already accepted."""
    import json

    enriched_event = enrich_event_company_from_agent(db, event)
    existing = get_event_by_id(db, enriched_event.event_id)
    if existing:
        return StoreEventResult(record=existing, event=enriched_event, created=False)

    upsert_agent(
        db,
        agent_id=enriched_event.agent_id,
        hostname=enriched_event.hostname,
        platform=enriched_event.platform,
        version=str(enriched_event.payload.get("agent_version", "1.0.0")),
        company=extract_company_from_tags(enriched_event.tags),
    )

    event_record = Event(
        event_id=enriched_event.event_id,
        agent_id=enriched_event.agent_id,
        hostname=enriched_event.hostname,
        platform=enriched_event.platform,
        event_type=enriched_event.event_type,
        severity=enriched_event.severity,
        source=enriched_event.source,
        timestamp=datetime.fromisoformat(
            enriched_event.timestamp.replace("Z", "+00:00")
        ),
        payload_json=json.dumps(enriched_event.payload),
        tags_json=json.dumps(enriched_event.tags),
        vt_status="pending",
    )
    db.add(event_record)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = get_event_by_id(db, enriched_event.event_id)
        if existing:
            return StoreEventResult(
                record=existing, event=enriched_event, created=False
            )
        raise
    db.refresh(event_record)
    return StoreEventResult(record=event_record, event=enriched_event, created=True)


def enrich_event_company_from_agent(db: Session, event: MiniEDREvent) -> MiniEDREvent:
    """Attach the registered agent company when an event lacks a company tag."""
    if extract_company_from_tags(event.tags):
        return event

    agent = get_agent_by_id(db, event.agent_id)
    if not agent or not agent.company:
        return event

    event_data = event.model_dump()
    event_data["tags"] = merge_company_tag(event.tags, agent.company)
    return MiniEDREvent(**event_data)


def get_events(
    db: Session, filters: dict | None = None, page: int = 1, page_size: int = 50
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


def store_hash_cache(db: Session, sha256: str, vt_result: VTResult) -> HashCache:
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
            vt_status=vt_result.status,
        )
        db.add(cache)

    db.commit()
    db.refresh(cache)
    return cache


def update_event_vt_status(
    db: Session, event_id: str, status: str, vt_result: VTResult | None = None
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


def mark_stale_agents_offline(db: Session, timeout_seconds: int) -> int:
    """Mark agents as offline if last_seen exceeds timeout. Returns count updated."""
    cutoff = datetime.utcnow() - timedelta(seconds=timeout_seconds)
    updated = (
        db.query(Agent).filter(Agent.status == "online", Agent.last_seen < cutoff).all()
    )
    for agent in updated:
        agent.status = "offline"
    if updated:
        db.commit()
    return len(updated)


def get_stats(db: Session) -> dict:
    """Get server statistics."""
    total_events = db.query(func.count(Event.id)).scalar() or 0
    total_agents = db.query(func.count(Agent.id)).scalar() or 0

    last_24h = datetime.utcnow() - timedelta(days=1)
    events_24h = (
        db.query(func.count(Event.id)).filter(Event.created_at >= last_24h).scalar()
        or 0
    )

    vt_alerts = (
        db.query(func.count(Event.id))
        .filter(and_(Event.vt_status == "enriched", Event.vt_malicious > 0))
        .scalar()
        or 0
    )

    return {
        "total_events": total_events,
        "total_agents": total_agents,
        "events_24h": events_24h,
        "vt_alerts": vt_alerts,
    }
