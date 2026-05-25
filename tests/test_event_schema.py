"""Tests for event schema validation and serialization."""

import pytest
import uuid
from pydantic import ValidationError

from shared.event_schema import (
    MiniEDREvent,
    VTResult,
    FIMPayload,
    HeartbeatPayload,
)


class TestVTResult:
    """Test VirusTotal result model."""

    def test_valid_vt_result(self):
        """Test creating valid VT result."""
        result = VTResult(
            malicious=1, suspicious=0, undetected=2, total=3, status="malicious"
        )
        assert result.malicious == 1
        assert result.status == "malicious"

    def test_vt_status_validation(self):
        """Test VT status enum validation."""
        with pytest.raises(ValidationError):
            VTResult(malicious=0, suspicious=0, undetected=0, total=0, status="invalid")

    def test_vt_total_validation(self):
        """Test VT total sum validation."""
        with pytest.raises(ValidationError):
            VTResult(
                malicious=1, suspicious=1, undetected=1, total=2, status="malicious"
            )


class TestFIMPayload:
    """Test FIM payload model."""

    def test_valid_fim_payload(self):
        """Test creating valid FIM payload."""
        payload = FIMPayload(
            filepath="/etc/passwd", event_action="modified", hash_sha256="abc123"
        )
        assert payload.filepath == "/etc/passwd"
        assert payload.event_action == "modified"

    def test_fim_with_vt_result(self):
        """Test FIM payload with VT result."""
        vt = VTResult(malicious=0, suspicious=0, undetected=0, total=0, status="clean")
        payload = FIMPayload(
            filepath="/bin/bash", event_action="modified", hash_sha256="xyz789", vt=vt
        )
        assert payload.vt.status == "clean"


class TestMiniEDREvent:
    """Test MiniEDR event model."""

    def test_minimal_event(self):
        """Test creating minimal event."""
        test_uuid_event = str(uuid.uuid4())
        test_uuid_agent = str(uuid.uuid4())
        event = MiniEDREvent(
            event_id=test_uuid_event,
            agent_id=test_uuid_agent,
            hostname="test",
            platform="Linux",
            event_type="heartbeat",
            severity="low",
            timestamp="2026-05-07T10:00:00Z",
            source="agent",
            payload={"agent_version": "1.0", "status": "online", "hostname": "test"},
            tags=[],
        )
        assert event.event_id == test_uuid_event
        assert event.event_type == "heartbeat"

    def test_event_auto_generates_ids(self):
        """Test event auto-generates event_id and timestamp."""
        test_uuid_agent = str(uuid.uuid4())
        event = MiniEDREvent(
            agent_id=test_uuid_agent,
            hostname="test",
            platform="Linux",
            event_type="scan",
            severity="medium",
            source="agent",
            payload={"files_scanned": 10, "detections": 0},
            tags=[],
        )
        assert event.event_id is not None
        assert len(event.event_id) == 36
        assert event.timestamp is not None
        assert event.timestamp.endswith("Z")

    def test_event_with_fim_payload(self):
        """Test event with FIM payload."""
        test_uuid_agent = str(uuid.uuid4())
        payload = FIMPayload(
            filepath="/etc/shadow", event_action="created", hash_sha256="hash123"
        )
        event = MiniEDREvent(
            agent_id=test_uuid_agent,
            hostname="test",
            platform="Linux",
            event_type="fim",
            severity="high",
            source="agent",
            payload=payload.model_dump(),
            tags=["security"],
        )
        assert event.event_type == "fim"
        assert event.payload["filepath"] == "/etc/shadow"

    def test_event_serialization(self):
        """Test event serializes to dict and JSON."""
        test_uuid_event = str(uuid.uuid4())
        test_uuid_agent = str(uuid.uuid4())
        event = MiniEDREvent(
            event_id=test_uuid_event,
            agent_id=test_uuid_agent,
            hostname="test",
            platform="Linux",
            event_type="heartbeat",
            severity="low",
            timestamp="2026-05-07T10:00:00Z",
            source="agent",
            payload={"agent_version": "1.0", "status": "online", "hostname": "test"},
            tags=["heartbeat"],
        )

        event_dict = event.model_dump()
        assert isinstance(event_dict, dict)
        assert event_dict["event_id"] == test_uuid_event
        assert event_dict["payload"]["status"] == "online"

        event_json = event.model_dump_json()
        assert isinstance(event_json, str)
        assert test_uuid_event in event_json


class TestHeartbeatPayload:
    """Test heartbeat payload model."""

    def test_valid_heartbeat(self):
        """Test creating valid heartbeat."""
        hb = HeartbeatPayload(agent_version="1.0.0", status="online", hostname="myhost")
        assert hb.status == "online"
        assert hb.agent_version == "1.0.0"
