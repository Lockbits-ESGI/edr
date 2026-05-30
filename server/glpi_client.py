"""GLPI ticket creation client."""

import json
import logging
import time
from html import escape
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests

from shared.event_schema import MiniEDREvent

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GLPIConfig:
    """Runtime configuration needed to create GLPI tickets."""

    web_url: str
    api_url: str
    oauth_client_id: str
    oauth_client_secret: str
    api_username: str
    api_password: str
    timeout_seconds: float = 10.0
    ticket_entity_id: int | None = None
    ticket_category_id: int | None = None
    requester_id: int | None = None


class GLPIClient:
    """Small wrapper around GLPI's OAuth2 high-level REST API."""

    def __init__(self, config: GLPIConfig) -> None:
        self.config = config
        self.web_url = config.web_url.rstrip("/") + "/"
        self.api_url = config.api_url.rstrip("/") + "/"
        self._access_token: str | None = None
        self._access_token_expires_at = 0.0
        self._user_email_cache: dict[str, int] = {}
        self._user_email_cache_expires_at = 0.0

    def create_ticket_for_event(self, event: MiniEDREvent) -> int | None:
        """Create one GLPI ticket for an accepted EDR event."""
        payload = self._build_ticket_payload(event)
        response = self._post_ticket(payload)
        response.raise_for_status()

        data = response.json()
        ticket_id = self._extract_created_id(data)
        logger.info(
            "GLPI ticket created for event %s: %s",
            event.event_id,
            ticket_id if ticket_id is not None else data,
        )
        return ticket_id

    def test_connection(self) -> None:
        """Fail fast if OAuth authentication is not usable."""
        self._get_access_token()

    def _post_ticket(self, payload: dict[str, Any]) -> requests.Response:
        candidate_paths = ("Assistance/Ticket", "Ticket")
        fallback_statuses = {400, 404, 405, 422}
        last_response: requests.Response | None = None

        for path in candidate_paths:
            response = requests.post(
                self._api_url(path),
                headers=self._bearer_headers(),
                json=payload,
                timeout=self.config.timeout_seconds,
            )
            if response.status_code not in fallback_statuses:
                return response
            last_response = response

            legacy_shape_response = requests.post(
                self._api_url(path),
                headers=self._bearer_headers(),
                json={"input": payload},
                timeout=self.config.timeout_seconds,
            )
            if legacy_shape_response.status_code not in fallback_statuses:
                return legacy_shape_response
            last_response = legacy_shape_response

        if last_response is None:
            raise RuntimeError("No GLPI ticket endpoint was attempted")
        return last_response

    def _get_access_token(self) -> str:
        if self._access_token and time.time() < self._access_token_expires_at:
            return self._access_token

        response = requests.post(
            self._token_url(),
            data={
                "grant_type": "password",
                "client_id": self.config.oauth_client_id,
                "client_secret": self.config.oauth_client_secret,
                "username": self.config.api_username,
                "password": self.config.api_password,
                "scope": "api",
            },
            timeout=self.config.timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        access_token = data.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ValueError("GLPI token response did not include access_token")

        try:
            expires_in_seconds = int(data.get("expires_in", 3600))
        except (TypeError, ValueError):
            expires_in_seconds = 3600

        self._access_token = access_token
        self._access_token_expires_at = time.time() + max(expires_in_seconds - 60, 60)
        return access_token

    def _bearer_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _token_url(self) -> str:
        return urljoin(self.web_url, "api.php/token")

    def _api_url(self, path: str) -> str:
        return urljoin(self.api_url, path.lstrip("/"))

    def _resolve_requester_by_email(self, email: str) -> int | None:
        """Search GLPI user by email via search API, return user ID or None."""
        # Cache check (TTL 5 minutes)
        now = time.time()
        if now < self._user_email_cache_expires_at and email in self._user_email_cache:
            return self._user_email_cache[email]

        # Search GLPI User by email (field 9 = email)
        try:
            response = requests.get(
                self._api_url("search/User"),
                headers=self._bearer_headers(),
                params={
                    "criteria[0][field]": 9,
                    "criteria[0][searchtype]": "equals",
                    "criteria[0][value]": email,
                },
                timeout=self.config.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            logger.warning("GLPI user search failed for %s: %s", email, exc)
            return None

        total = data.get("totalcount", 0) if isinstance(data, dict) else 0
        if total > 0 and isinstance(data.get("data"), list) and len(data["data"]) > 0:
            user_id = data["data"][0].get("1")  # field "1" = GLPI user ID
            if isinstance(user_id, int):
                self._user_email_cache[email] = user_id
                self._user_email_cache_expires_at = now + 300  # 5 min TTL
                logger.info("Resolved GLPI user %s → ID %d", email, user_id)
                return user_id

        logger.warning("No GLPI user found for email %s", email)
        return None

    def _build_ticket_payload(self, event: MiniEDREvent) -> dict[str, Any]:
        payload = event.payload if isinstance(event.payload, dict) else {}
        event_action = payload.get("event_action")
        filepath = payload.get("filepath")

        name = (
            f"[MiniEDR] {event.severity.upper()} {event.event_type} on {event.hostname}"
        )

        summary_parts = [
            f"<h2>MiniEDR Security Alert — {event.severity.upper()}</h2>",
            f"<p><strong>Hostname:</strong> {escape(event.hostname)}</p>",
            f"<p><strong>Platform:</strong> {escape(event.platform)}</p>",
            f"<p><strong>Event Type:</strong> {escape(event.event_type)}</p>",
            f"<p><strong>Severity:</strong> {escape(event.severity)}</p>",
            f"<p><strong>Timestamp:</strong> {escape(event.timestamp)}</p>",
            f"<p><strong>Agent ID:</strong> {escape(event.agent_id)}</p>",
        ]
        if event_action:
            summary_parts.append(
                f"<p><strong>Action:</strong> {escape(event_action)}</p>"
            )
        if filepath:
            summary_parts.append(
                f"<p><strong>File:</strong> {escape(filepath)}</p>"
            )
        if event.tags:
            summary_parts.append(
                f"<p><strong>Tags:</strong> {', '.join(escape(t) for t in event.tags)}</p>"
            )

        detail = {
            "event_id": event.event_id,
            "agent_id": event.agent_id,
            "hostname": event.hostname,
            "platform": event.platform,
            "event_type": event.event_type,
            "severity": event.severity,
            "source": event.source,
            "timestamp": event.timestamp,
            "tags": event.tags,
            "event_action": event_action,
            "filepath": filepath,
            "payload": payload,
        }
        json_block = f"<pre>{escape(json.dumps(detail, indent=2, sort_keys=True))}</pre>"
        content_html = "<br/>".join(summary_parts) + "<br/><br/><hr/>" + json_block

        ticket: dict[str, Any] = {
            "name": name,
            "content": content_html,
            "type": 1,
            "urgency": self._severity_to_glpi_level(event.severity),
            "impact": self._severity_to_glpi_level(event.severity),
            "priority": self._severity_to_glpi_level(event.severity),
        }
        if self.config.ticket_entity_id is not None:
            ticket["entities_id"] = self.config.ticket_entity_id
        if self.config.ticket_category_id is not None:
            ticket["itilcategories_id"] = self.config.ticket_category_id
        requester_id = None
        if event.glpi_requester_email:
            requester_id = self._resolve_requester_by_email(event.glpi_requester_email)
        if requester_id is None:
            requester_id = self.config.requester_id
        if requester_id is not None:
            ticket["_users_id_requester"] = requester_id
        return ticket

    @staticmethod
    def _severity_to_glpi_level(severity: str) -> int:
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }.get(severity.lower(), 3)

    @staticmethod
    def _extract_created_id(data: Any) -> int | None:
        if isinstance(data, dict):
            item_id = data.get("id")
            return item_id if isinstance(item_id, int) else None
        if isinstance(data, list) and data and isinstance(data[0], dict):
            item_id = data[0].get("id")
            return item_id if isinstance(item_id, int) else None
        return None


def build_glpi_client(settings: Any) -> GLPIClient | None:
    """Create a GLPI client when ticket creation is enabled and configured."""
    if not settings.GLPI_ENABLED:
        return None

    required_settings = {
        "GLPI_OAUTH_CLIENT_ID": settings.GLPI_OAUTH_CLIENT_ID,
        "GLPI_OAUTH_CLIENT_SECRET": settings.GLPI_OAUTH_CLIENT_SECRET,
        "GLPI_API_USERNAME": settings.GLPI_API_USERNAME,
        "GLPI_API_PASSWORD": settings.GLPI_API_PASSWORD,
    }
    missing = [key for key, value in required_settings.items() if not value]
    if missing:
        logger.warning(
            "GLPI ticket creation enabled but missing settings: %s",
            ", ".join(missing),
        )
        return None

    return GLPIClient(
        GLPIConfig(
            web_url=settings.GLPI_WEB_URL,
            api_url=settings.GLPI_API_URL,
            oauth_client_id=settings.GLPI_OAUTH_CLIENT_ID,
            oauth_client_secret=settings.GLPI_OAUTH_CLIENT_SECRET,
            api_username=settings.GLPI_API_USERNAME,
            api_password=settings.GLPI_API_PASSWORD,
            timeout_seconds=settings.GLPI_TIMEOUT_SECONDS,
            ticket_entity_id=settings.GLPI_TICKET_ENTITY_ID,
            ticket_category_id=settings.GLPI_TICKET_CATEGORY_ID,
            requester_id=settings.GLPI_REQUESTER_ID,
        )
    )
