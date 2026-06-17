"""Tests for server settings parsing."""

from server.config import Settings


def test_empty_glpi_optional_ids_are_unset(monkeypatch):
    monkeypatch.setenv("GLPI_TICKET_ENTITY_ID", "")
    monkeypatch.setenv("GLPI_TICKET_CATEGORY_ID", "")

    settings = Settings(_env_file=None)

    assert settings.GLPI_TICKET_ENTITY_ID is None
    assert settings.GLPI_TICKET_CATEGORY_ID is None


def test_glpi_oauth_scope_can_be_configured(monkeypatch):
    monkeypatch.setenv("GLPI_OAUTH_SCOPE", "api user email")

    settings = Settings(_env_file=None)

    assert settings.GLPI_OAUTH_SCOPE == "api user email"
