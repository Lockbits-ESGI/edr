"""Tests for EventSender with mock HTTP and local queue."""

import json
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.sender import EventSender
from shared.event_schema import MiniEDREvent


class TestEventSender:
    """Test EventSender with queue fallback."""

    @pytest.fixture
    def temp_queue(self):
        """Create temporary queue file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir) / "pending_events.jsonl"

    @pytest.fixture
    def sender(self, temp_queue):
        """Create EventSender instance."""
        return EventSender(
            server_url="http://localhost:8000",
            auth_token="test_token",
            timeout=5,
            queue_path=str(temp_queue),
        )

    def test_send_event_success(self, sender):
        """Test successful event send."""
        event = MiniEDREvent(
            event_id=str(uuid.uuid4()),
            agent_id=str(uuid.uuid4()),
            hostname="test",
            platform="Linux",
            event_type="heartbeat",
            severity="low",
            timestamp="2026-05-07T10:00:00Z",
            source="agent",
            payload={"agent_version": "1.0", "status": "online", "hostname": "test"},
            tags=[],
        )

        with patch("agent.sender.requests.post") as mock_post:
            mock_post.return_value.status_code = 201
            result = sender.send_event(event)
            assert result is True
            mock_post.assert_called_once()

    def test_send_event_failure_queues_locally(self, sender, temp_queue):
        """Test event is queued locally on send failure."""
        event_uuid = str(uuid.uuid4())
        event = MiniEDREvent(
            event_id=event_uuid,
            agent_id=str(uuid.uuid4()),
            hostname="test",
            platform="Linux",
            event_type="heartbeat",
            severity="low",
            timestamp="2026-05-07T10:00:00Z",
            source="agent",
            payload={"agent_version": "1.0", "status": "online", "hostname": "test"},
            tags=[],
        )

        with patch("agent.sender.requests.post") as mock_post:
            mock_post.side_effect = Exception("Connection error")
            result = sender.send_event(event)
            assert result is False

        assert temp_queue.exists()
        lines = temp_queue.read_text().strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["event_id"] == event_uuid

    def test_send_batch(self, sender):
        """Test batch send."""
        agent_uuid = str(uuid.uuid4())
        events = [
            MiniEDREvent(
                event_id=str(uuid.uuid4()),
                agent_id=agent_uuid,
                hostname="test",
                platform="Linux",
                event_type="heartbeat",
                severity="low",
                timestamp="2026-05-07T10:00:00Z",
                source="agent",
                payload={
                    "agent_version": "1.0",
                    "status": "online",
                    "hostname": "test",
                },
                tags=[],
            )
            for i in range(3)
        ]

        with patch("agent.sender.requests.post") as mock_post:
            mock_post.return_value.status_code = 201
            result = sender.send_batch(events)
            assert result is True
            mock_post.assert_called_once()

            args, kwargs = mock_post.call_args
            payload = kwargs["json"]
            assert "events" in payload
            assert len(payload["events"]) == 3

    def test_auth_header(self, sender):
        """Test authorization header included."""
        event = MiniEDREvent(
            event_id=str(uuid.uuid4()),
            agent_id=str(uuid.uuid4()),
            hostname="test",
            platform="Linux",
            event_type="heartbeat",
            severity="low",
            timestamp="2026-05-07T10:00:00Z",
            source="agent",
            payload={"agent_version": "1.0", "status": "online", "hostname": "test"},
            tags=[],
        )

        with patch("agent.sender.requests.post") as mock_post:
            mock_post.return_value.status_code = 201
            sender.send_event(event)

            args, kwargs = mock_post.call_args
            headers = kwargs["headers"]
            assert "Authorization" in headers
            assert headers["Authorization"] == "Bearer test_token"

    def test_flush_queue(self, sender, temp_queue):
        """Test flushing pending events from queue."""
        temp_queue.parent.mkdir(parents=True, exist_ok=True)

        with open(temp_queue, "w") as f:
            json.dump({"event_id": "e1", "agent_id": "a1"}, f)
            f.write("\n")
            json.dump({"event_id": "e2", "agent_id": "a1"}, f)
            f.write("\n")

        with patch("requests.post") as mock_post:
            mock_post.return_value.status_code = 201
            count = sender.flush_queue()
            assert count == 2

        assert not temp_queue.exists()

    def test_no_token_when_not_set(self):
        """Test no auth header when token not set."""
        sender = EventSender(server_url="http://localhost:8000", timeout=5)

        event = MiniEDREvent(
            event_id=str(uuid.uuid4()),
            agent_id=str(uuid.uuid4()),
            hostname="test",
            platform="Linux",
            event_type="heartbeat",
            severity="low",
            timestamp="2026-05-07T10:00:00Z",
            source="agent",
            payload={"agent_version": "1.0", "status": "online", "hostname": "test"},
            tags=[],
        )

        with patch("agent.sender.requests.post") as mock_post:
            mock_post.return_value.status_code = 201
            sender.send_event(event)

            args, kwargs = mock_post.call_args
            headers = kwargs["headers"]
            assert "Authorization" not in headers
