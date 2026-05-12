"""Background heartbeat worker for periodic agent health checks."""

import logging
import threading
import time

from shared.event_schema import HeartbeatPayload

logger = logging.getLogger("miniedr.agent.heartbeat")


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
                payload = HeartbeatPayload(
                    agent_version="1.0.0",
                    status="online",
                    ip=None,
                    hostname=self.hostname
                ).model_dump()
                payload.update({
                    "agent_id": self.agent_id,
                    "hostname": self.hostname,
                    "platform": self.platform,
                    "agent_version": payload["agent_version"],
                })
                self.sender.send_heartbeat(payload)
            except Exception as e:
                logger.error(f"Heartbeat send failed: {e}")
            
            self.stop_event.wait(self.interval_s)
        
        logger.info("Heartbeat worker stopped")
    
    def stop(self) -> None:
        """Stop cleanly."""
        self.stop_event.set()
