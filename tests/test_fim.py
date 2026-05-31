"""Tests for file integrity monitoring event filtering."""

import threading
from collections import deque

import logging

from fim import FIMEventHandler


def test_fim_event_handler_ignores_configured_runtime_paths(tmp_path):
    """Alerts under ignored runtime paths must not be queued."""
    alerts = deque()
    lock = threading.Lock()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    queue_file = tmp_path / "queue" / "pending_events.jsonl"
    queue_file.parent.mkdir()
    queue_file.write_text("")

    handler = FIMEventHandler(alerts, lock, ignored_paths=[logs_dir, queue_file])

    handler._add_alert("modified", str(logs_dir / "agent.log"))
    handler._add_alert("modified", str(queue_file))
    handler._add_alert("created", str(tmp_path / "watched.txt"))

    assert list(alerts) == [
        {
            "timestamp": alerts[0]["timestamp"],
            "event_type": "created",
            "file_path": str(tmp_path / "watched.txt"),
        }
    ]


def test_fim_event_handler_does_not_log_ignored_paths(tmp_path, caplog):
    """Logging ignored runtime events would retrigger FIM on the log file."""
    alerts = deque()
    lock = threading.Lock()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    handler = FIMEventHandler(alerts, lock, ignored_paths=[logs_dir])

    with caplog.at_level(logging.DEBUG, logger="miniedr"):
        handler._add_alert("modified", str(logs_dir / "agent.log"))

    assert not alerts
    assert "Ignored FIM alert" not in caplog.text
