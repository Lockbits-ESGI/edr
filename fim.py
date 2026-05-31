"""File integrity monitoring using watchdog with thread-safe alert accumulation."""

import logging
import threading
from collections import deque
from pathlib import Path
from typing import Iterable, Tuple

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger("miniedr")


class FIMEventHandler(FileSystemEventHandler):
    """Handles file system events and accumulates alerts in thread-safe deque."""

    def __init__(
        self,
        alerts_deque: deque[dict[str, object]],
        lock: threading.Lock,
        ignored_paths: Iterable[str | Path] | None = None,
    ):
        super().__init__()
        self.alerts = alerts_deque
        self.lock = lock
        self.ignored_paths = _normalize_ignored_paths(ignored_paths)

    def on_created(self, event):
        if not event.is_directory:
            self._add_alert("created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._add_alert("deleted", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._add_alert("modified", event.src_path)

    def _add_alert(self, event_type: str, file_path: str):
        from datetime import datetime

        if _is_ignored_path(file_path, self.ignored_paths):
            return

        alert: dict[str, object] = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "file_path": file_path,
        }
        with self.lock:
            self.alerts.append(alert)
        logger.debug(f"FIM alert: {event_type} {file_path}")


def start_fim_monitor(
    watch_dirs: list[str],
    ignored_paths: Iterable[str | Path] | None = None,
) -> Tuple[Observer, deque[dict[str, object]], threading.Lock]:
    """Start watchdog observer for FIM monitoring.

    Args:
        watch_dirs: List of directories to monitor.
        ignored_paths: Files or directories that should not generate alerts.

    Returns:
        Tuple of (Observer instance, alerts deque, thread lock).
    """
    alerts = deque(maxlen=10000)
    lock = threading.Lock()

    observer = Observer()
    normalized_ignored_paths = _normalize_ignored_paths(ignored_paths)
    for watch_dir in watch_dirs:
        path = Path(watch_dir)
        if path.exists() and path.is_dir():
            handler = FIMEventHandler(alerts, lock, normalized_ignored_paths)
            observer.schedule(handler, str(path), recursive=True)
            logger.info(f"Watching directory: {path}")

    if normalized_ignored_paths:
        ignored_display = ", ".join(str(path) for path in normalized_ignored_paths)
        logger.info(f"Ignoring FIM paths: {ignored_display}")

    observer.start()
    logger.info("FIM monitor started")
    return observer, alerts, lock


def get_alerts(
    alerts_deque: deque[dict[str, object]], lock: threading.Lock
) -> list[dict[str, object]]:
    """Retrieve and clear accumulated alerts (thread-safe)."""
    with lock:
        current_alerts = list(alerts_deque)
        alerts_deque.clear()
    return current_alerts


def stop_fim_monitor(observer: Observer):
    """Stop FIM monitoring gracefully."""
    try:
        observer.stop()
        observer.join(timeout=5)
        logger.info("FIM monitor stopped")
    except Exception as e:
        logger.error(f"Error stopping FIM monitor: {e}")


def _normalize_ignored_paths(
    ignored_paths: Iterable[str | Path] | None,
) -> tuple[Path, ...]:
    normalized = []
    for ignored_path in ignored_paths or []:
        if not ignored_path:
            continue
        try:
            normalized.append(Path(ignored_path).expanduser().resolve())
        except OSError:
            normalized.append(Path(ignored_path).expanduser().absolute())
    return tuple(normalized)


def _is_ignored_path(file_path: str | Path, ignored_paths: Iterable[Path]) -> bool:
    try:
        candidate = Path(file_path).expanduser().resolve()
    except OSError:
        candidate = Path(file_path).expanduser().absolute()

    for ignored_path in ignored_paths:
        if candidate == ignored_path:
            return True
        if ignored_path.exists() and ignored_path.is_dir():
            try:
                candidate.relative_to(ignored_path)
                return True
            except ValueError:
                continue
    return False
