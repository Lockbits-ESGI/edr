"""Tests for agent event construction."""

import uuid

from agent.main import MiniEDRAgent


def test_monitor_snapshot_event_uses_valid_system_info_payload(tmp_path):
    """Monitor snapshots must satisfy the system_info event contract."""
    config_path = tmp_path / "config.yaml"
    agent_id_file = tmp_path / "agent_id"
    queue_path = tmp_path / "queue" / "pending_events.jsonl"
    config_path.write_text(
        "\n".join(
            [
                "agent:",
                f"  id_file: {agent_id_file}",
                "server:",
                "  url: http://127.0.0.1:8000",
                "queue:",
                f"  path: {queue_path}",
            ]
        )
    )

    agent = MiniEDRAgent(config_path=config_path, output_dir=tmp_path)
    snapshot = {
        "timestamp": "2026-05-28T11:58:00",
        "platform": "Linux",
        "hostname": "debian-test-edragent",
        "os": "Linux-6.1.0",
        "kernel": "6.1.0",
        "uptime": 123.0,
        "cpu_count": 2,
        "cpu_percent": 3.0,
        "memory_total_gb": 4.0,
        "memory_available_gb": 2.0,
        "memory_percent": 50.0,
        "disk_info": [],
        "processes": [],
    }

    event = agent._snapshot_to_event(
        snapshot, event_type="system_info", tags=["monitor", "snapshot"]
    )

    uuid.UUID(event.event_id, version=4)
    assert event.event_type == "system_info"
    assert event.payload == snapshot
    assert event.tags == ["monitor", "snapshot"]


def test_agent_adds_normalized_company_tag(tmp_path, monkeypatch):
    """Deployment company is attached to every emitted event."""
    config_path = tmp_path / "config.yaml"
    agent_id_file = tmp_path / "agent_id"
    queue_path = tmp_path / "queue" / "pending_events.jsonl"
    config_path.write_text(
        "\n".join(
            [
                "agent:",
                f"  id_file: {agent_id_file}",
                "  company: EntrepriseA",
                "server:",
                "  url: http://127.0.0.1:8000",
                "queue:",
                f"  path: {queue_path}",
            ]
        )
    )
    monkeypatch.delenv("MINIEDR_AGENT_COMPANY", raising=False)
    monkeypatch.delenv("AGENT_COMPANY", raising=False)

    agent = MiniEDRAgent(config_path=config_path, output_dir=tmp_path)
    event = agent.create_event(
        event_type="scan",
        severity="low",
        payload={"ok": True},
        tags=["scan"],
    )

    assert event.tags == ["scan", "company:EntrepriseA"]
