"""Background heartbeat worker for periodic agent health checks."""

import logging
import threading
import time

from shared.event_schema import MiniEDREvent, HeartbeatPayload
from shared.utils import generate_uuid, utc_now_iso

logger = logging.getLogger(__name__)


class HeartbeatWorker(threading.Thread):
    """Daemon thread that sends periodic heartbeat events."""
    
    def __init__(
        self,
        sender,
        agent_id: str,
        hostname: str,
        platform: str,
        interval_s: int = 300
    ):
        super().__init__(daemon=True)
        self.sender = sender
        self.agent_id = agent_id
        self.hostname = hostname
        self.platform = platform
        self.interval_s = interval_s
        self.stop_event = threading.Event()
    
    def run(self) -> None:
        """Loop: send heartbeat, sleep interval."""
        logger.info(f"Heartbeat worker started (interval: {self.interval_s}s)")
        
        while not self.stop_event.is_set():
            try:
                event = MiniEDREvent(
                    event_id=generate_uuid(),
                    agent_id=self.agent_id,
                    hostname=self.hostname,
                    platform=self.platform,
                    event_type="heartbeat",
                    severity="low",
                    timestamp=utc_now_iso(),
                    source="agent",
                    payload=HeartbeatPayload(
                        agent_version="1.0.0",
                        status="online",
                        ip=None,
                        hostname=self.hostname
                    ).dict(),
                    tags=["heartbeat"]
                )
                self.sender.send_event(event)
            except Exception as e:
                logger.error(f"Heartbeat send failed: {e}")
            
            self.stop_event.wait(self.interval_s)
        
        logger.info("Heartbeat worker stopped")
    
    def stop(self) -> None:
        """Stop cleanly."""
        self.stop_event.set()
