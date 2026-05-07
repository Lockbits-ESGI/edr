#!/usr/bin/env python3
"""
MiniEDR Agent — Client component for central server architecture

Collects local events (FIM, system snapshots) and sends to central server.
Operates in two modes:
- scan: Single system snapshot without FIM
- monitor: Continuous FIM with periodic snapshots and heartbeat
"""

import argparse
import json
import logging
import platform
import sys
import time
from pathlib import Path
from typing import Optional

try:
    from config import load_config
    from logger import setup_logging
    from collector import get_system_snapshot, snapshot_to_dict
    from fim import start_fim_monitor, get_alerts
    from reporter import generate_json_report, generate_html_report
except ImportError:
    from .config import load_config
    from .logger import setup_logging
    from .collector import get_system_snapshot, snapshot_to_dict
    from .fim import start_fim_monitor, get_alerts
    from .reporter import generate_json_report, generate_html_report

from shared.utils import load_agent_id, generate_uuid, utc_now_iso, get_config_dir
from shared.event_schema import MiniEDREvent
from agent.sender import EventSender
from agent.heartbeat import HeartbeatWorker

logger = logging.getLogger(__name__)


class MiniEDRAgent:
    """Agent that collects events and sends to server."""
    
    def __init__(self, config_path: Path, output_dir: Path):
        self.config_path = config_path
        self.output_dir = output_dir
        self.config = load_config(config_path)
        self.agent_id = load_agent_id(get_config_dir() / "agent_id")
        
        server_config = self.config.get("server", {})
        self.sender = EventSender(
            server_url=server_config.get("url", "http://127.0.0.1:8000"),
            auth_token=server_config.get("auth_token"),
            timeout=server_config.get("timeout", 10),
            queue_path=self.config.get("queue", {}).get("path")
        )
        
        self.heartbeat_worker: Optional[HeartbeatWorker] = None
    
    def create_event(
        self,
        event_type: str,
        severity: str,
        payload: dict,
        tags: list[str] | None = None
    ) -> MiniEDREvent:
        """Create MiniEDREvent with standard fields."""
        import socket
        
        return MiniEDREvent(
            event_id=generate_uuid(),
            agent_id=self.agent_id,
            hostname=socket.gethostname(),
            platform=sys.platform.capitalize() if sys.platform != "win32" else "Windows",
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
            
            self.sender.send_batch([event])
            
            if self.config.get("agent", {}).get("generate_local_report", False):
                generate_json_report(self.output_dir, snapshot)
                generate_html_report(self.output_dir, snapshot)
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
            watch_dirs = fim_config.get("watch_dirs", {}).get(sys.platform, [])
            
            if not watch_dirs:
                logger.warning(f"No watch directories configured for {sys.platform}")
                return 1
            
            logger.info(f"Watching directories: {watch_dirs}")
            
            observer = start_fim_monitor(watch_dirs)
            
            self.heartbeat_worker = HeartbeatWorker(
                sender=self.sender,
                agent_id=self.agent_id,
                hostname=sys.stdout.isatty() and "localhost" or "agent",
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
        logger.info("Agent stopped")


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
        default=Path("config.yaml"),
        help="Path to configuration file",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./reports"),
        help="Output directory for reports",
    )
    
    args = parser.parse_args()
    
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    setup_logging()
    
    agent = MiniEDRAgent(args.config, args.output_dir)
    
    if args.mode == "scan":
        return agent.run_scan_mode()
    else:
        return agent.run_monitor_mode()


if __name__ == "__main__":
    sys.exit(main())
