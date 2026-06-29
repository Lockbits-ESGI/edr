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
from shared.tags import extract_company_from_tags

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
    oauth_scope: str = "api"
    timeout_seconds: float = 10.0
    ticket_entity_id: int | None = None
    ticket_category_id: int | None = None
    requester_id: int | None = None
    company_requester_type: str = "Group"
    entity_recursive: bool = True


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
        company = extract_company_from_tags(event.tags)
        requester_user = self._event_requester_user(event)
        requester_user_id = (
            self._resolve_requester_actor_id("User", requester_user)
            if requester_user
            else None
        )
        payload = self._build_ticket_payload(event, requester_user_id=requester_user_id)
        response = self._post_ticket(payload)
        response.raise_for_status()

        data = response.json()
        ticket_id = self._extract_created_id(data)
        if requester_user and requester_user_id is None and ticket_id is not None:
            self._try_add_user_requester(ticket_id, requester_user, event.event_id)
        elif requester_user and requester_user_id is None:
            logger.warning(
                "GLPI ticket created for event %s but no ticket id was returned; "
                "user requester '%s' could not be added",
                event.event_id,
                requester_user,
            )

        if company and ticket_id is not None:
            self._try_add_company_requester(ticket_id, company, event.event_id)
        elif company:
            logger.warning(
                "GLPI ticket created for event %s but no ticket id was returned; "
                "company requester '%s' could not be added",
                event.event_id,
                company,
            )

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

    def _try_add_company_requester(
        self, ticket_id: int, company: str, event_id: str
    ) -> None:
        try:
            self._add_company_requester(ticket_id, company)
        except Exception as exc:
            logger.error(
                "GLPI requester assignment failed for event %s ticket %s company %s: %s",
                event_id,
                ticket_id,
                company,
                exc,
            )

    def _try_add_user_requester(
        self, ticket_id: int, username: str, event_id: str
    ) -> None:
        try:
            self._add_user_requester(ticket_id, username)
        except Exception as exc:
            logger.error(
                "GLPI requester assignment failed for event %s ticket %s user %s: %s",
                event_id,
                ticket_id,
                username,
                exc,
            )

    def _add_company_requester(self, ticket_id: int, company: str) -> None:
        requester_type = self._normalize_requester_type(
            self.config.company_requester_type
        )
        self._add_named_requester(ticket_id, requester_type, company)

    def _add_user_requester(self, ticket_id: int, username: str) -> None:
        self._add_named_requester(ticket_id, "User", username)

    def _add_named_requester(
        self, ticket_id: int, requester_type: str, requester_name: str
    ) -> None:
        requester_id = self._resolve_requester_actor_id(requester_type, requester_name)
        if requester_id is None:
            logger.warning(
                "GLPI requester '%s' of type '%s' was not found; ticket %s left "
                "without resolved requester id; trying direct requester name assignment",
                requester_name,
                requester_type,
                ticket_id,
            )
            response = self._post_team_member_requester(
                ticket_id,
                {
                    "type": requester_type,
                    "name": requester_name,
                    "role": "requester",
                },
            )
            if response.status_code < 400:
                logger.info(
                    "GLPI requester added to ticket %s by name: %s %s",
                    ticket_id,
                    requester_type,
                    requester_name,
                )
                return
            raise RuntimeError(
                "direct requester name assignment failed: "
                f"{self._response_error_detail(response)}"
            )

        id_payload = {
            "type": requester_type,
            "id": requester_id,
            "role": "requester",
        }
        response = self._post_team_member_requester(ticket_id, id_payload)
        if response.status_code < 400:
            logger.info(
                "GLPI requester added to ticket %s: %s %s",
                ticket_id,
                requester_type,
                requester_name,
            )
            return

        id_error = self._response_error_detail(response)
        name_response = self._post_team_member_requester(
            ticket_id,
            {
                "type": requester_type,
                "name": requester_name,
                "role": "requester",
            },
        )
        if name_response.status_code < 400:
            logger.info(
                "GLPI requester added to ticket %s by name after id assignment "
                "failed: %s %s",
                ticket_id,
                requester_type,
                requester_name,
            )
            return

        raise RuntimeError(
            "requester id assignment failed: "
            f"{id_error}; requester name assignment failed: "
            f"{self._response_error_detail(name_response)}"
        )

    def _resolve_requester_actor_id(self, actor_type: str, company: str) -> int | None:
        stripped_company = company.strip()
        if stripped_company.isdigit():
            return int(stripped_company)

        rsql_field = "name" if actor_type.lower() != "user" else "username"

        for path in self._requester_collection_paths(actor_type):
            exact_filter = f'{rsql_field}=="{self._escape_rsql_value(stripped_company)}"'
            try:
                filtered = self._get_collection(
                    path, params={"filter": exact_filter, "limit": 20}
                )
                actor_id = self._find_actor_id_by_name(filtered, stripped_company)
                if actor_id is not None:
                    return actor_id

                start = 0
                limit = 100
                while start < 500:
                    page = self._get_collection(
                        path, params={"start": start, "limit": limit}
                    )
                    actor_id = self._find_actor_id_by_name(page, stripped_company)
                    if actor_id is not None:
                        return actor_id
                    if len(page) < limit:
                        break
                    start += limit
            except requests.RequestException as exc:
                logger.warning(
                    "GLPI requester lookup failed on %s for %s '%s': %s",
                    path,
                    actor_type,
                    stripped_company,
                    exc,
                )

        return None

    def _post_team_member_requester(
        self, ticket_id: int, payload: dict[str, Any]
    ) -> requests.Response:
        candidate_paths = (
            f"Assistance/Ticket/{ticket_id}/TeamMember",
            f"Ticket/{ticket_id}/TeamMember",
        )
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

        if last_response is None:
            raise RuntimeError("No GLPI TeamMember endpoint was attempted")
        return last_response

    def _get_collection(
        self, path: str, params: dict[str, Any]
    ) -> list[dict[str, Any]]:
        response = requests.get(
            self._api_url(path),
            headers=self._bearer_headers(),
            params=params,
            timeout=self.config.timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            for key in ("data", "items"):
                items = data.get(key)
                if isinstance(items, list):
                    return [item for item in items if isinstance(item, dict)]
        return []

    @staticmethod
    def _normalize_requester_type(actor_type: str) -> str:
        types = {
            "group": "Group",
            "supplier": "Supplier",
            "user": "User",
        }
        normalized = types.get(actor_type.strip().lower())
        if normalized is None:
            raise ValueError(
                "GLPI_COMPANY_REQUESTER_TYPE must be one of Group, Supplier, User"
            )
        return normalized

    @staticmethod
    def _requester_collection_paths(actor_type: str) -> tuple[str, str]:
        paths = {
            "group": ("Administration/Group", "Group"),
            "supplier": ("Management/Supplier", "Supplier"),
            "user": ("Administration/User", "User"),
        }
        candidate_paths = paths.get(actor_type.strip().lower())
        if candidate_paths is None:
            raise ValueError(
                "GLPI_COMPANY_REQUESTER_TYPE must be one of Group, Supplier, User"
            )
        return candidate_paths

    @staticmethod
    def _find_actor_id_by_name(
        items: list[dict[str, Any]], expected_name: str
    ) -> int | None:
        expected = expected_name.casefold()
        for item in items:
            names = [item.get("name"), item.get("completename"), item.get("username")]
            for name in names:
                if isinstance(name, str) and name.casefold() == expected:
                    item_id = item.get("id")
                    if isinstance(item_id, int):
                        return item_id
                    if isinstance(item_id, str) and item_id.isdigit():
                        return int(item_id)
        return None

    @staticmethod
    def _escape_rsql_value(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

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
                "scope": self.config.oauth_scope,
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
        headers = {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.config.ticket_entity_id is not None:
            headers["GLPI-Entity"] = str(self.config.ticket_entity_id)
        headers["GLPI-Entity-Recursive"] = (
            "true" if self.config.entity_recursive else "false"
        )
        return headers

    def _token_url(self) -> str:
        return urljoin(self.web_url, "api.php/token")

    def _api_url(self, path: str) -> str:
        return urljoin(self.api_url, path.lstrip("/"))

    @staticmethod
    def _event_requester_user(event: MiniEDREvent) -> str | None:
        user = getattr(event, "user", None)
        if isinstance(user, str):
            stripped = user.strip()
            if stripped:
                return stripped
        return None

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

    def _build_ticket_payload(
        self, event: MiniEDREvent, requester_user_id: int | None = None
    ) -> dict[str, Any]:
        payload = event.payload if isinstance(event.payload, dict) else {}
        event_action = payload.get("event_action")
        filepath = payload.get("filepath")
        company = extract_company_from_tags(event.tags)
        requester_user = self._event_requester_user(event)

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
            summary_parts.append(f"<p><strong>File:</strong> {escape(filepath)}</p>")
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
            "user": requester_user,
            "company": company,
            "event_action": event_action,
            "filepath": filepath,
            "payload": payload,
        }
        json_block = (
            f"<pre>{escape(json.dumps(detail, indent=2, sort_keys=True))}</pre>"
        )
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
        requester_id = requester_user_id
        if (
            requester_id is None
            and requester_user is None
            and event.glpi_requester_email
        ):
            requester_id = self._resolve_requester_by_email(event.glpi_requester_email)
        if requester_user is None and requester_id is None:
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
            if isinstance(item_id, int):
                return item_id
            if isinstance(item_id, str) and item_id.isdigit():
                return int(item_id)
            href = data.get("href")
            if isinstance(href, str):
                tail = href.rstrip("/").rsplit("/", 1)[-1]
                return int(tail) if tail.isdigit() else None
            return None
        if isinstance(data, list) and data and isinstance(data[0], dict):
            item_id = data[0].get("id")
            if isinstance(item_id, int):
                return item_id
            if isinstance(item_id, str) and item_id.isdigit():
                return int(item_id)
        return None

    @staticmethod
    def _response_error_detail(response: requests.Response) -> str:
        body = response.text.strip()
        if not body:
            try:
                body = json.dumps(response.json(), sort_keys=True)
            except ValueError:
                body = ""
        if len(body) > 1000:
            body = body[:1000] + "...[truncated]"
        return f"HTTP {response.status_code}: {body}"


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
            oauth_scope=settings.GLPI_OAUTH_SCOPE,
            api_username=settings.GLPI_API_USERNAME,
            api_password=settings.GLPI_API_PASSWORD,
            timeout_seconds=settings.GLPI_TIMEOUT_SECONDS,
            ticket_entity_id=settings.GLPI_TICKET_ENTITY_ID,
            ticket_category_id=settings.GLPI_TICKET_CATEGORY_ID,
            requester_id=settings.GLPI_REQUESTER_ID,
            company_requester_type=settings.GLPI_COMPANY_REQUESTER_TYPE,
            entity_recursive=settings.GLPI_ENTITY_RECURSIVE,
        )
    )
