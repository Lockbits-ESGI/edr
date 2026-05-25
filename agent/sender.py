"""HTTP client with queue fallback for reliable event transmission."""

import json
import logging
import time
from pathlib import Path
from typing import Optional

import requests

from shared.event_schema import MiniEDREvent

logger = logging.getLogger("miniedr.agent.sender")


class EventSender:
    """Send events to server with local queue fallback on failure."""

    def __init__(
        self,
        server_url: str,
        auth_token: Optional[str] = None,
        timeout: int = 10,
        queue_path: Optional[str] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.auth_token = auth_token or None
        self.timeout = timeout
        self.queue_path = (
            Path(queue_path) if queue_path else Path("queue") / "pending_events.jsonl"
        )

    def send_event(self, event: MiniEDREvent) -> bool:
        """Send single event, return True on success."""
        return self._post("/api/v1/events", event.model_dump())

    def send_batch(self, events: list[MiniEDREvent]) -> bool:
        """Send batch of events."""
        return self._post(
            "/api/v1/events/batch", {"events": [e.model_dump() for e in events]}
        )

    def send_heartbeat(self, payload: dict) -> bool:
        """Send heartbeat/registration payload to the dedicated endpoint."""
        return self._post("/api/v1/heartbeat", payload, queue_on_failure=False)

    def _post(
        self, endpoint: str, payload: dict, queue_on_failure: bool = True
    ) -> bool:
        """POST with retry logic (3 attempts, backoff: 2s, 4s, 8s)."""
        for attempt in range(3):
            try:
                response = requests.post(
                    f"{self.server_url}{endpoint}",
                    json=payload,
                    timeout=self.timeout,
                    headers=self._headers(),
                )
                if response.status_code in [200, 201, 202]:
                    logger.debug(f"Event sent successfully to {endpoint}")
                    return True
                else:
                    logger.warning(
                        f"Send failed (HTTP {response.status_code}): {response.text[:100]}"
                    )
            except requests.exceptions.Timeout:
                logger.warning(f"Send attempt {attempt + 1} timed out")
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Send attempt {attempt + 1} failed (connection): {e}")
            except Exception as e:
                logger.error(f"Send attempt {attempt + 1} failed: {e}")

            if attempt < 2:
                sleep_duration = 2 ** (attempt + 1)
                logger.debug(f"Retrying in {sleep_duration}s...")
                time.sleep(sleep_duration)

        if queue_on_failure:
            self._queue_locally(payload)
        return False

    def _headers(self) -> dict:
        """Build request headers."""
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    def _queue_locally(self, payload: dict) -> None:
        """Append to JSONL queue file."""
        try:
            self.queue_path.parent.mkdir(exist_ok=True, parents=True)
            with open(self.queue_path, "a") as f:
                if isinstance(payload.get("events"), list):
                    for event in payload["events"]:
                        json.dump(event, f)
                        f.write("\n")
                else:
                    json.dump(payload, f)
                    f.write("\n")
            logger.info(f"Event queued locally: {self.queue_path}")
        except Exception as e:
            logger.error(f"Failed to queue event locally: {e}")

    def flush_queue(self) -> int:
        """Retry all pending events from JSONL."""
        if not self.queue_path.exists():
            return 0

        events = self._load_queue()
        if not events:
            return 0

        logger.info(f"Flushing queue ({len(events)} pending events)...")
        sent = 0

        for event_data in events:
            if self._post("/api/v1/events", event_data):
                sent += 1

        if sent == len(events):
            try:
                self.queue_path.unlink()
                logger.info(f"Queue cleared ({sent}/{len(events)} events sent)")
            except Exception as e:
                logger.error(f"Failed to remove queue file: {e}")
        else:
            logger.warning(
                f"Queue not fully flushed ({sent}/{len(events)} events sent)"
            )

        return sent

    def _load_queue(self) -> list[dict]:
        """Read JSONL queue file."""
        if not self.queue_path.exists():
            return []

        events = []
        try:
            with open(self.queue_path) as f:
                for line in f:
                    if line.strip():
                        payload = json.loads(line)
                        if isinstance(payload.get("events"), list):
                            events.extend(payload["events"])
                        else:
                            events.append(payload)
        except Exception as e:
            logger.error(f"Failed to load queue: {e}")

        return events
