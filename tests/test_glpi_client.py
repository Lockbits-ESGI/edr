"""Tests for GLPI ticket creation payloads."""

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
