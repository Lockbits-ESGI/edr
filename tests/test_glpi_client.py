"""Tests for GLPI ticket creation payloads."""

from html import unescape

import server.glpi_client as glpi_module
from shared.event_schema import MiniEDREvent
from server.glpi_client import GLPIClient, GLPIConfig


def test_build_ticket_payload_from_event():
    event = MiniEDREvent(
        event_id="11111111-1111-4111-8111-111111111111",
        agent_id="22222222-2222-4222-8222-222222222222",
        hostname="endpoint-01",
        platform="Linux",
        event_type="fim",
        severity="high",
        timestamp="2026-05-07T10:00:00Z",
        source="agent",
        payload={
            "filepath": "/tmp/suspicious.sh",
            "event_action": "created",
            "hash_sha256": "abc123",
        },
        tags=["fim", "created"],
    )
    client = GLPIClient(
        GLPIConfig(
            web_url="https://glpi.lockbits.pro",
            api_url="https://glpi.lockbits.pro/api.php/v2.2",
            oauth_client_id="client-id",
            oauth_client_secret="client-secret",
            api_username="api-bot",
            api_password="password",
            ticket_entity_id=1,
            ticket_category_id=2,
        )
    )

    payload = client._build_ticket_payload(event)

    assert payload["name"] == "[MiniEDR] HIGH fim on endpoint-01"
    assert payload["type"] == 1
    assert payload["urgency"] == 4
    assert payload["impact"] == 4
    assert payload["priority"] == 4
    assert payload["entities_id"] == 1
    assert payload["itilcategories_id"] == 2
    assert "11111111-1111-4111-8111-111111111111" in payload["content"]
    assert "/tmp/suspicious.sh" in payload["content"]


class FakeResponse:
    def __init__(self, status_code=200, data=None, text=""):
        self.status_code = status_code
        self._data = data if data is not None else {}
        self.text = text

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_create_ticket_adds_company_as_requester_actor(monkeypatch):
    event = MiniEDREvent(
        event_id="11111111-1111-4111-8111-111111111111",
        agent_id="22222222-2222-4222-8222-222222222222",
        hostname="endpoint-01",
        platform="Linux",
        event_type="fim",
        severity="high",
        timestamp="2026-05-07T10:00:00Z",
        source="agent",
        payload={
            "filepath": "/tmp/suspicious.sh",
            "event_action": "created",
        },
        tags=["fim", "created", "company:EntrepriseA"],
    )
    client = GLPIClient(
        GLPIConfig(
            web_url="https://glpi.lockbits.pro",
            api_url="https://glpi.lockbits.pro/api.php/v2.2",
            oauth_client_id="client-id",
            oauth_client_secret="client-secret",
            api_username="api-bot",
            api_password="password",
        )
    )
    client._access_token = "cached-token"
    client._access_token_expires_at = 9999999999.0

    post_calls = []

    def fake_post(url, headers, json, timeout):
        post_calls.append((url, json))
        if url.endswith("/Assistance/Ticket"):
            return FakeResponse(status_code=201, data={"id": 123})
        if url.endswith("/Assistance/Ticket/123/TeamMember"):
            return FakeResponse(status_code=201, data={"id": 456})
        raise AssertionError(f"unexpected POST {url}")

    def fake_get(url, headers, params, timeout):
        assert url.endswith("/Administration/Group")
        assert "Content-Type" not in headers
        assert params["filter"] == 'name=="EntrepriseA"'
        return FakeResponse(status_code=200, data=[{"id": 42, "name": "EntrepriseA"}])

    monkeypatch.setattr(glpi_module.requests, "post", fake_post)
    monkeypatch.setattr(glpi_module.requests, "get", fake_get)

    ticket_id = client.create_ticket_for_event(event)

    assert ticket_id == 123
    assert "team" not in post_calls[0][1]
    assert post_calls[1][1] == {"type": "Group", "id": 42, "role": "requester"}

    payload = client._build_ticket_payload(event)

    assert "team" not in payload
    assert '"company": "EntrepriseA"' in unescape(payload["content"])


def test_create_ticket_adds_company_requester_by_name_when_lookup_misses(
    monkeypatch,
):
    event = MiniEDREvent(
        event_id="11111111-1111-4111-8111-111111111111",
        agent_id="22222222-2222-4222-8222-222222222222",
        hostname="endpoint-01",
        platform="Linux",
        event_type="fim",
        severity="high",
        timestamp="2026-05-07T10:00:00Z",
        source="agent",
        payload={
            "filepath": "/tmp/suspicious.sh",
            "event_action": "created",
        },
        tags=["fim", "company:test"],
    )
    client = GLPIClient(
        GLPIConfig(
            web_url="https://glpi.lockbits.pro",
            api_url="https://glpi.lockbits.pro/api.php/v2.2",
            oauth_client_id="client-id",
            oauth_client_secret="client-secret",
            api_username="api-bot",
            api_password="password",
            ticket_entity_id=7,
            company_requester_type="group",
        )
    )
    client._access_token = "cached-token"
    client._access_token_expires_at = 9999999999.0

    post_calls = []

    def fake_post(url, headers, json, timeout):
        assert headers["GLPI-Entity"] == "7"
        assert headers["GLPI-Entity-Recursive"] == "true"
        post_calls.append((url, json))
        if url.endswith("/Assistance/Ticket"):
            return FakeResponse(status_code=201, data={"id": "123"})
        if url.endswith("/Assistance/Ticket/123/TeamMember"):
            return FakeResponse(status_code=201, data={"id": 456})
        raise AssertionError(f"unexpected POST {url}")

    def fake_get(url, headers, params, timeout):
        assert headers["GLPI-Entity"] == "7"
        assert headers["GLPI-Entity-Recursive"] == "true"
        assert "Content-Type" not in headers
        assert url.endswith("/Administration/Group") or url.endswith("/Group")
        return FakeResponse(status_code=200, data=[])

    monkeypatch.setattr(glpi_module.requests, "post", fake_post)
    monkeypatch.setattr(glpi_module.requests, "get", fake_get)

    ticket_id = client.create_ticket_for_event(event)

    assert ticket_id == 123
    assert post_calls[1][1] == {"type": "Group", "name": "test", "role": "requester"}


def test_glpi_v2_urls():
    client = GLPIClient(
        GLPIConfig(
            web_url="https://glpi.lockbits.pro",
            api_url="https://glpi.lockbits.pro/api.php/v2.2",
            oauth_client_id="client-id",
            oauth_client_secret="client-secret",
            api_username="api-bot",
            api_password="password",
        )
    )

    assert client._token_url() == "https://glpi.lockbits.pro/api.php/token"
    assert (
        client._api_url("Assistance/Ticket")
        == "https://glpi.lockbits.pro/api.php/v2.2/Assistance/Ticket"
    )
