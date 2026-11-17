"""Full-mode execution tools: allowlists, payloads, validation."""
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from soar_analyst_mcp.tools.run import run_action, run_playbook


# ---------- run_playbook ----------

def test_run_playbook_disabled_without_allowlist(soar):
    with pytest.raises(ToolError, match="SOAR_PLAYBOOK_ALLOWLIST is empty"):
        run_playbook(1001, "edr_ip_hash_enrichment")
    assert soar.posts == []


def test_run_playbook_not_in_allowlist(soar, allow_run):
    with pytest.raises(ToolError, match="not in SOAR_PLAYBOOK_ALLOWLIST"):
        run_playbook(1001, "phishing_triage")
    assert soar.posts == []


def test_run_playbook_payload(soar, allow_run):
    out = run_playbook(1001, "edr_ip_hash_enrichment")
    assert soar.posts[-1] == ("playbook_run", {"container_id": 1001, "playbook_id": 31,
                                               "scope": "new", "run": True})
    assert out["started"] is True and out["playbook_run_id"] == 88100


def test_run_playbook_validation(soar, allow_run):
    with pytest.raises(ToolError, match="run_scope"):
        run_playbook(1001, "edr_ip_hash_enrichment", run_scope="everything")
    with pytest.raises(ToolError, match="not found or not accessible"):
        run_playbook(4242, "edr_ip_hash_enrichment")
    assert soar.posts == []


# ---------- run_action ----------

def test_run_action_disabled_without_allowlist(soar):
    with pytest.raises(ToolError, match="SOAR_ACTION_ALLOWLIST is empty"):
        run_action(1001, "ip reputation", "abuseipdb", [{"ip": "203.0.113.45"}])


def test_run_action_not_in_allowlist(soar, allow_run):
    with pytest.raises(ToolError, match="not in SOAR_ACTION_ALLOWLIST"):
        run_action(1001, "block ip", "abuseipdb", [{"ip": "203.0.113.45"}])
    assert soar.posts == []


def test_run_action_resolves_app_and_sends_payload(soar, allow_run):
    out = run_action(1001, "IP Reputation", "abuseipdb", [{"ip": "203.0.113.45"}])
    path, body = soar.posts[-1]
    assert path == "action_run"
    assert body == {"action": "ip reputation", "container_id": 1001, "name": "mcp_ip_reputation",
                    "targets": [{"assets": ["abuseipdb"], "parameters": [{"ip": "203.0.113.45"}],
                                 "app_id": 190}]}
    assert out["action_run_id"] == 5100 and out["app_id"] == 190


def test_run_action_explicit_app_id(soar, allow_run):
    run_action(1001, "ip reputation", "virustotal", [{"ip": "203.0.113.45"}], app_id=55)
    assert soar.posts[-1][1]["targets"][0]["app_id"] == 55


@pytest.mark.parametrize("params,msg", [
    ([], "non-empty list"),
    ([{}], "non-empty object"),
    ([{"ip": ["a", "b"]}], "scalars"),
])
def test_run_action_parameter_validation(soar, allow_run, params, msg):
    with pytest.raises(ToolError, match=msg):
        run_action(1001, "ip reputation", "abuseipdb", params)


def test_run_action_unknown_asset_or_app(soar, allow_run):
    with pytest.raises(ToolError, match="asset not found"):
        run_action(1001, "ip reputation", "ghost", [{"ip": "x"}])
    with pytest.raises(ToolError, match="cannot resolve app"):
        run_action(1001, "ip reputation", "virustotal", [{"ip": "x"}])  # no app in fake
    assert soar.posts == []


def test_execute_audit_kind(soar, allow_run, env):
    run_playbook(1001, "edr_ip_hash_enrichment")
    rec = json.loads(env.read_text().splitlines()[-1])
    assert rec["kind"] == "execute" and rec["tool"] == "run_playbook"
