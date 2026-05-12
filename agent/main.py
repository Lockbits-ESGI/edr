#!/usr/bin/env python3
"""
MiniEDR Agent — Client component for central server architecture

Collects local events (FIM, system snapshots) and sends to central server.
Operates in two modes:
- scan: Single system snapshot without FIM
- monitor: Continuous FIM with periodic snapshots and heartbeat
"""

import argparse
import logging
import os
import platform
import socket
import sys
import time
from pathlib import Path
from typing import Optional

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import load_config
from logger import setup_logging
from collector import get_system_snapshot, snapshot_to_dict
from fim import start_fim_monitor, get_alerts, stop_fim_monitor
from hasher import compute_both_hashes
from reporter import generate_json_report, generate_html_report

from shared.utils import (
    get_config_dir,
    get_queue_file,
    load_agent_id,
    generate_uuid,
    resource_path,
    utc_now_iso,
)
from shared.event_schema import MiniEDREvent
from agent.sender import EventSender
from agent.heartbeat import HeartbeatWorker

logger = logging.getLogger("miniedr.agent")


class MiniEDRAgent:
    """Agent that collects events and sends to server."""
    
    def __init__(self, config_path: Path, output_dir: Path):
        self.config_path = config_path
        self.output_dir = output_dir
        self.config = _load_agent_config(config_path)
        agent_id_file = os.environ.get("MINIEDR_AGENT_ID_FILE") or self.config.get("agent", {}).get("id_file")
        self.agent_id = load_agent_id(Path(agent_id_file) if agent_id_file else get_config_dir() / "agent_id")
        
        server_config = self.config.get("server", {})
        queue_config = self.config.get("queue", {})
        server_url = os.environ.get("MINIEDR_SERVER_URL") or server_config.get("url", "http://127.0.0.1:8000")
        auth_token = os.environ.get("MINIEDR_AUTH_TOKEN") or server_config.get("auth_token")
        queue_path = queue_config.get("path")
        if not queue_path:
            queue_path = str(get_queue_file())

        self.sender = EventSender(
            server_url=server_url,
            auth_token=auth_token,
            timeout=server_config.get("timeout", 10),
            queue_path=queue_path
        )
        
        self.heartbeat_worker: Optional[HeartbeatWorker] = None
        self.observer = None
    
    def create_event(
        self,
        event_type: str,
        severity: str,
        payload: dict,
        tags: list[str] | None = None
    ) -> MiniEDREvent:
        """Create MiniEDREvent with standard fields."""
        return MiniEDREvent(
            event_id=generate_uuid(),
            agent_id=self.agent_id,
            hostname=socket.gethostname(),
            platform=platform.system(),
            event_type=event_type,
            severity=severity,
            timestamp=utc_now_iso(),
            source="agent",
            payload=payload,
            tags=tags or []
        )
    
    def run_scan_mode(self) -> int:
        """Run single snapshot mode."""
        logger.info("Running in SCAN mode (single snapshot)")
        
        try:
            snapshot = get_system_snapshot()
            snapshot_dict = snapshot_to_dict(snapshot)
            
            event = self.create_event(
                event_type="scan",
                severity="low",
                payload=snapshot_dict,
                tags=["scan", "snapshot"]
            )
            
            if self.sender.send_batch([event]):
                self.sender.flush_queue()
            
            if self.config.get("agent", {}).get("generate_local_report", False):
                generate_json_report(snapshot_dict, [], self.output_dir / "report.json")
                generate_html_report(
                    snapshot_dict,
                    [],
                    self.output_dir / "report.html",
                    template_dir=resource_path("templates"),
                )
                logger.info(f"Reports generated in {self.output_dir}")
            
            return 0
        
        except Exception as e:
            logger.error(f"Scan mode failed: {e}", exc_info=True)
            return 1
    
    def run_monitor_mode(self) -> int:
        """Run continuous monitoring mode with FIM and heartbeat."""
        logger.info("Running in MONITOR mode (continuous FIM)")
        
        try:
            fim_config = self.config.get("fim", {})
            watch_dirs = fim_config.get("watch_dirs", {}).get(self._platform_config_key(), [])
            
            if not watch_dirs:
                logger.warning(f"No watch directories configured for {sys.platform}")
                return 1
            
            logger.info(f"Watching directories: {watch_dirs}")
            
            self.observer, alerts, alerts_lock = start_fim_monitor(watch_dirs)
            
            self.heartbeat_worker = HeartbeatWorker(
                sender=self.sender,
                agent_id=self.agent_id,
                hostname=socket.gethostname(),
                platform=platform.system(),
                interval_s=self.config.get("agent", {}).get("heartbeat_interval", 300)
            )
            self.heartbeat_worker.start()
            
            snapshot_interval = self.config.get("agent", {}).get("snapshot_interval", 600)
            last_snapshot = time.time()
            last_flush = time.time()
            
            logger.info("Monitor mode started. Press Ctrl+C to stop.")
            
            while True:
                time.sleep(1)

                fim_alerts = get_alerts(alerts, alerts_lock)
                if fim_alerts:
                    events = [self._fim_alert_to_event(alert) for alert in fim_alerts]
                    self.sender.send_batch(events)
                
                if time.time() - last_snapshot >= snapshot_interval:
                    try:
                        snapshot = get_system_snapshot()
                        event = self.create_event(
                            event_type="system_info",
                            severity="low",
                            payload=snapshot_to_dict(snapshot),
                            tags=["monitor", "snapshot"]
                        )
                        self.sender.send_event(event)
                        last_snapshot = time.time()
                    except Exception as e:
                        logger.error(f"Snapshot send failed: {e}")
                
                if time.time() - last_flush >= 60:
                    self.sender.flush_queue()
                    last_flush = time.time()
        
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        
        except Exception as e:
            logger.error(f"Monitor mode error: {e}", exc_info=True)
            return 1
        
        finally:
            self.stop()
        
        return 0
    
    def stop(self) -> None:
        """Stop monitoring and cleanup."""
        logger.info("Stopping agent...")
        
        if self.heartbeat_worker:
            self.heartbeat_worker.stop()
            self.heartbeat_worker.join(timeout=5)
        
        self.sender.flush_queue()
        if self.observer:
            stop_fim_monitor(self.observer)
        logger.info("Agent stopped")

    def _platform_config_key(self) -> str:
        """Return config key for the current platform."""
        current = platform.system()
        if current == "Windows":
            return "windows"
        if current == "Darwin":
            return "darwin"
        return "linux"

    def _fim_alert_to_event(self, alert: dict) -> MiniEDREvent:
        """Convert a watchdog alert to a MiniEDR event."""
        filepath = str(alert.get("file_path", ""))
        action = str(alert.get("event_type", "modified"))
        payload = {
            "filepath": filepath,
            "event_action": action,
        }

        if action in {"created", "modified"} and filepath:
            md5_hash, sha256_hash = compute_both_hashes(Path(filepath))
            if md5_hash:
                payload["hash_md5"] = md5_hash
            if sha256_hash:
                payload["hash_sha256"] = sha256_hash

        severity = "medium" if action in {"created", "modified"} else "low"
        return self.create_event(
            event_type="fim",
            severity=severity,
            payload=payload,
            tags=["fim", action],
        )


def _default_config_path() -> Path:
    """Find the best default agent config path for source and PyInstaller runs."""
    user_config = get_config_dir() / "config.yaml"
    if user_config.exists():
        return user_config

    local_agent_config = Path("agent") / "config.yaml"
    if local_agent_config.exists():
        return local_agent_config

    local_config = Path("config.yaml")
    if local_config.exists() and (Path.cwd() / "agent").exists():
        return local_config

    return resource_path("agent/config.yaml")


def _deep_merge(defaults: dict, overrides: dict) -> dict:
    """Merge nested dictionaries without mutating inputs."""
    merged = dict(defaults)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_agent_config(config_path: Path) -> dict:
    """Load bundled defaults, then overlay the selected config file."""
    default_path = resource_path("agent/config.yaml")
    defaults = load_config(default_path)
    selected = load_config(config_path)
    return _deep_merge(defaults, selected)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MiniEDR Agent — Endpoint Detection & Response Client"
    )
    parser.add_argument(
        "--mode",
        choices=["scan", "monitor"],
        default="monitor",
        help="Operation mode (scan=single snapshot, monitor=continuous FIM)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Output directory for reports",
    )
    
    args = parser.parse_args()

    config_path = args.config or _default_config_path()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    pre_config = _load_agent_config(config_path)
    log_config = pre_config.get("logging", {})
    log_file = log_config.get("log_file")
    setup_logging(
        level=log_config.get("level", "INFO"),
        log_file=Path(log_file) if log_file else args.output_dir / "agent.log",
    )

    agent = MiniEDRAgent(config_path, args.output_dir)
    
    if args.mode == "scan":
        return agent.run_scan_mode()
    else:
        return agent.run_monitor_mode()


if __name__ == "__main__":
    sys.exit(main())
