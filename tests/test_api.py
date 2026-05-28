"""Tests for FastAPI server endpoints."""

import pytest
import uuid
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from server.main import app
from server.database import get_db
from server.models import Base

TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
EVENT_ID = "11111111-1111-4111-8111-111111111111"
AGENT_ID = "22222222-2222-4222-8222-222222222222"
HEARTBEAT_PAYLOAD = {"agent_version": "1.0.0", "status": "online", "hostname": "test"}


@pytest.fixture(scope="function")
def db_engine():
    """Create test engine with fresh schema each test."""
    engine = create_engine(
        TEST_SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def override_get_db(db_engine):
    """Override get_db to use test database."""
    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=db_engine
    )

    def _override_get_db():
        database = TestingSessionLocal()
        try:
            yield database
        finally:
            database.close()

    return _override_get_db


@pytest.fixture
def client(override_get_db):
    """Create test client with dependency override."""
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


class TestHealthEndpoint:
    """Test /health endpoint."""

    def test_health_check(self, client):
        """Test health check returns 200."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "db_ok" in data


class TestEventEndpoints:
    """Test event ingestion endpoints."""

    def test_post_single_event(self, client):
        """Test POST /api/v1/events with valid event."""
        event_data = {
            "event_id": EVENT_ID,
            "agent_id": AGENT_ID,
            "hostname": "test",
            "platform": "Linux",
            "event_type": "heartbeat",
            "severity": "low",
            "timestamp": "2026-05-07T10:00:00Z",
            "source": "agent",
            "payload": HEARTBEAT_PAYLOAD,
            "tags": [],
        }

        response = client.post("/api/v1/events", json=event_data)
        assert response.status_code == 201
        data = response.json()
        assert data["accepted"] is True
        assert data["event_id"] == EVENT_ID

    def test_post_batch_events(self, client):
        """Test POST /api/v1/events/batch."""
        batch_data = {
            "events": [
                {
                    "event_id": str(uuid.uuid4()),
                    "agent_id": AGENT_ID,
                    "hostname": "test",
                    "platform": "Linux",
                    "event_type": "heartbeat",
                    "severity": "low",
                    "timestamp": "2026-05-07T10:00:00Z",
                    "source": "agent",
                    "payload": HEARTBEAT_PAYLOAD,
                    "tags": [],
                }
                for i in range(3)
            ]
        }

        response = client.post("/api/v1/events/batch", json=batch_data)
        assert response.status_code == 201
        data = response.json()
        assert data["accepted"] == 3
        assert data["rejected"] == 0

    def test_get_events_list(self, client):
        """Test GET /api/v1/events."""
        event_data = {
            "event_id": EVENT_ID,
            "agent_id": AGENT_ID,
            "hostname": "test",
            "platform": "Linux",
            "event_type": "heartbeat",
            "severity": "low",
            "timestamp": "2026-05-07T10:00:00Z",
            "source": "agent",
            "payload": HEARTBEAT_PAYLOAD,
            "tags": [],
        }

        client.post("/api/v1/events", json=event_data)

        response = client.get("/api/v1/events")
        assert response.status_code == 200
        events = response.json()
        assert len(events) >= 1
        assert events[0]["event_id"] == EVENT_ID

    def test_get_single_event(self, client):
        """Test GET /api/v1/events/{event_id}."""
        event_data = {
            "event_id": EVENT_ID,
            "agent_id": AGENT_ID,
            "hostname": "test",
            "platform": "Linux",
            "event_type": "heartbeat",
            "severity": "low",
            "timestamp": "2026-05-07T10:00:00Z",
            "source": "agent",
            "payload": HEARTBEAT_PAYLOAD,
            "tags": [],
        }

        client.post("/api/v1/events", json=event_data)

        response = client.get(f"/api/v1/events/{EVENT_ID}")
        assert response.status_code == 200
        event = response.json()
        assert event["event_id"] == EVENT_ID

    def test_get_nonexistent_event(self, client):
        """Test GET nonexistent event returns 404."""
        response = client.get("/api/v1/events/nonexistent")
        assert response.status_code == 404


class TestAgentEndpoints:
    """Test agent management endpoints."""

    def test_post_heartbeat(self, client):
        """Test POST /api/v1/heartbeat."""
        hb_data = {
            "agent_id": "a1",
            "hostname": "test",
            "platform": "Linux",
            "agent_version": "1.0.0",
            "status": "online",
        }

        response = client.post("/api/v1/heartbeat", json=hb_data)
        assert response.status_code == 200
        data = response.json()
        assert data["acknowledged"] is True
        assert "server_time" in data

    def test_get_agents(self, client):
        """Test GET /api/v1/agents."""
        hb_data = {
            "agent_id": "a1",
            "hostname": "test",
            "platform": "Linux",
            "agent_version": "1.0.0",
            "status": "online",
        }

        client.post("/api/v1/heartbeat", json=hb_data)

        response = client.get("/api/v1/agents")
        assert response.status_code == 200
        agents = response.json()
        assert len(agents) >= 1
        assert agents[0]["agent_id"] == "a1"

    def test_get_single_agent(self, client):
        """Test GET /api/v1/agents/{agent_id}."""
        hb_data = {
            "agent_id": "a1",
            "hostname": "test",
            "platform": "Linux",
            "agent_version": "1.0.0",
            "status": "online",
        }

        client.post("/api/v1/heartbeat", json=hb_data)

        response = client.get("/api/v1/agents/a1")
        assert response.status_code == 200
        agent = response.json()
        assert agent["agent_id"] == "a1"


class TestStatsEndpoint:
    """Test statistics endpoint."""

    def test_get_stats(self, client):
        """Test GET /api/v1/stats."""
        response = client.get("/api/v1/stats")
        assert response.status_code == 200
        stats = response.json()
        assert "total_events" in stats
        assert "total_agents" in stats
        assert "events_24h" in stats
        assert "vt_alerts" in stats


class TestDashboard:
    """Test dashboard endpoint."""

    def test_get_dashboard(self, client):
        """Test GET /dashboard returns HTML."""
        response = client.get("/dashboard")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "MiniEDR Dashboard" in response.text


class TestMetricsEndpoint:
    """Test /metrics Prometheus endpoint."""

    def test_metrics_returns_200(self, client):
        """GET /metrics returns HTTP 200."""
        response = client.get("/metrics")
        assert response.status_code == 200

    def test_metrics_content_type(self, client):
        """GET /metrics returns Prometheus text content-type."""
        response = client.get("/metrics")
        assert "text/plain" in response.headers.get("content-type", "")

    def test_metrics_legacy_counters_present(self, client):
        """Original metric families are present for backward compatibility."""
        body = client.get("/metrics").text
        assert "edr_events_ingested_total" in body
        assert "edr_events_ingested_batch_size" in body
        assert "edr_agents_registered_total" in body
        assert "edr_active_agents" in body
        assert "edr_vt_enrichments_total" in body
        assert "edr_db_health" in body
        assert "edr_auth_failures_total" in body

    def test_metrics_new_counters_present(self, client):
        """Newly added metric families are present."""
        body = client.get("/metrics").text
        assert "edr_events_ingested_detail_total" in body
        assert "edr_events_rejected_total" in body
        assert "edr_batch_events_accepted_total" in body
        assert "edr_batch_events_rejected_total" in body
        assert "edr_fim_events_total" in body
        assert "edr_fim_suspicious_total" in body
        assert "edr_scan_events_total" in body
        assert "edr_heartbeat_errors_total" in body
        assert "edr_vt_malicious_found_total" in body
        assert "edr_vt_suspicious_found_total" in body

    def test_metrics_db_gauges_present(self, client):
        """Database-backed gauge families appear in the output."""
        body = client.get("/metrics").text
        assert "edr_agents_total" in body
        assert "edr_agents_online_total" in body
        assert "edr_agents_offline_total" in body
        assert "edr_agents_by_platform_total" in body
        assert "edr_agents_by_version_total" in body
        assert "edr_events_db_total" in body
        assert "edr_events_by_type_total" in body
        assert "edr_events_by_severity_total" in body
        assert "edr_events_by_platform_total" in body
        assert "edr_events_24h_total" in body
        assert "edr_events_1h_total" in body
        assert "edr_events_5m_total" in body
        assert "edr_vt_malicious_events_db_total" in body
        assert "edr_vt_suspicious_events_db_total" in body
        assert "edr_events_by_vt_status_total" in body
        assert "edr_hash_cache_entries_total" in body
        assert "edr_hash_cache_by_verdict_total" in body

    def test_metrics_db_counts_after_events(self, client):
        """edr_events_db_total reflects stored events."""
        for _ in range(2):
            client.post(
                "/api/v1/events",
                json={
                    "event_id": str(uuid.uuid4()),
                    "agent_id": AGENT_ID,
                    "hostname": "test",
                    "platform": "Linux",
                    "event_type": "heartbeat",
                    "severity": "low",
                    "timestamp": "2026-05-07T10:00:00Z",
                    "source": "agent",
                    "payload": HEARTBEAT_PAYLOAD,
                    "tags": [],
                },
            )
        body = client.get("/metrics").text
        assert "edr_events_db_total 2.0" in body

    def test_metrics_agents_by_platform_label(self, client):
        """edr_agents_by_platform_total carries a platform label after heartbeat."""
        client.post(
            "/api/v1/heartbeat",
            json={
                "agent_id": "a1",
                "hostname": "test-host",
                "platform": "Linux",
                "agent_version": "1.0.0",
                "status": "online",
            },
        )
        body = client.get("/metrics").text
        assert "edr_agents_by_platform_total" in body
        assert 'platform="Linux"' in body

    def test_metrics_events_by_severity_label(self, client):
        """edr_events_by_severity_total carries a severity label after a high event."""
        client.post(
            "/api/v1/events",
            json={
                "event_id": str(uuid.uuid4()),
                "agent_id": AGENT_ID,
                "hostname": "test",
                "platform": "Linux",
                "event_type": "scan",
                "severity": "high",
                "timestamp": "2026-05-07T10:00:00Z",
                "source": "agent",
                "payload": {"scan_result": "threat_found"},
                "tags": [],
            },
        )
        body = client.get("/metrics").text
        assert 'severity="high"' in body
