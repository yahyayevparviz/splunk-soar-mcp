"""Shared fixtures: env config, temp audit log, fake SOAR session (no network)."""
from __future__ import annotations

import json

import pytest

from soar_analyst_mcp.core import config

from .fake_soar import route, route_post

TOKEN = "secret-test-token"


class FakeResponse:
    def __init__(self, status: int, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class FakeSession:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.posts: list[tuple[str, dict]] = []
        self.status_override: int | None = None

    def get(self, url: str, params=None, timeout=None):
        params = dict(params or {})
        path = url.split("/rest/", 1)[1]
        self.calls.append((path, params))
        if self.status_override:
            return FakeResponse(self.status_override, {"message": "forced"})
        return FakeResponse(*route(path, params))

    def post(self, url: str, json=None, timeout=None):  # noqa: A002 - mirrors requests API
        path = url.split("/rest/", 1)[1]
        self.posts.append((path, json))
        if self.status_override:
            return FakeResponse(self.status_override, {"message": "forced"})
        return FakeResponse(*route_post(path, json))


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("SOAR_URL", "https://soar.example.com")
    monkeypatch.setenv("SOAR_TOKEN", TOKEN)
    monkeypatch.setenv("SOAR_VERIFY_SSL", "false")
    monkeypatch.setenv("SOAR_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    for var in ("SOAR_MCP_MODE", "SOAR_ALLOWED_LABELS", "SOAR_PLAYBOOK_ALLOWLIST",
                "SOAR_ACTION_ALLOWLIST"):
        monkeypatch.delenv(var, raising=False)
    config.reset_cache()
    yield tmp_path / "audit.jsonl"
    config.reset_cache()


@pytest.fixture
def soar(env):
    """Real SoarClient whose HTTP session methods are replaced by the fake router."""
    fake = FakeSession()
    client = config.get_client()
    client.session.get = fake.get    # type: ignore[assignment]
    client.session.post = fake.post  # type: ignore[assignment]
    return fake


@pytest.fixture
def scoped(monkeypatch):
    """Only label 'edr' is accessible (container 1001 = edr, 990 = siem, 2002 = other_team)."""
    monkeypatch.setenv("SOAR_ALLOWED_LABELS", "edr")


@pytest.fixture
def allow_run(monkeypatch):
    monkeypatch.setenv("SOAR_PLAYBOOK_ALLOWLIST", "edr_ip_hash_enrichment")
    monkeypatch.setenv("SOAR_ACTION_ALLOWLIST", "ip reputation, geolocate ip")
