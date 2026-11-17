import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from soar_analyst_mcp.core.shaping import UNTRUSTED_NOTICE
from soar_analyst_mcp.tools.assets import get_asset, list_assets
from soar_analyst_mcp.tools.cases import get_container, list_containers, search_containers
from soar_analyst_mcp.tools.evidence import get_action_run, get_action_runs, get_artifacts, get_notes
from soar_analyst_mcp.tools.lists import get_custom_list, list_custom_lists
from soar_analyst_mcp.tools.playbooks import (get_playbook_run, get_playbook_run_log,
                                              get_playbook_runs, list_playbooks)

from .conftest import TOKEN


def last(soar, path):
    return next(p for pth, p in reversed(soar.calls) if pth == path)


# ---------- cases ----------

def test_list_containers_builds_filters(soar):
    out = list_containers(status="new", severity="high", label="edr", since_hours=24)
    assert out["count"] == 3  # fake ignores filters; we assert the filters sent
    p = last(soar, "container")
    assert p["_filter_status"] == '"new"' and p["_filter_severity"] == '"high"'
    assert p["_filter_label"] == '"edr"' and "_filter_create_time__gt" in p
    assert p["page_size"] == 20 and p["order"] == "desc"


def test_list_containers_limit_clamped(soar):
    list_containers(limit=9999)
    assert last(soar, "container")["page_size"] == 200


def test_get_container(soar):
    assert get_container(1001)["container"]["name"].startswith("Suspicious PowerShell")


def test_errors_become_tool_errors(soar):
    with pytest.raises(ToolError, match="not found"):
        get_container(99999)
    with pytest.raises(ToolError, match="severity"):
        list_containers(severity="critical")


def test_search_by_name(soar):
    out = search_containers("PowerShell")
    assert out["count"] == 3
    assert last(soar, "container")["_filter_name__icontains"] == '"PowerShell"'


def test_search_by_ioc_dedups_containers(soar):
    out = search_containers("203.0.113.45", mode="ioc", cef_field="destinationAddress")
    assert [c["id"] for c in out["items"]] == [1001, 990]
    assert last(soar, "artifact")["_filter_cef__destinationAddress"] == '"203.0.113.45"'


def test_search_ioc_requires_allowed_field(soar):
    with pytest.raises(ToolError, match="cef_field"):
        search_containers("1.2.3.4", mode="ioc")
    with pytest.raises(ToolError, match="not allowed"):
        search_containers("1.2.3.4", mode="ioc", cef_field="deviceCustomString1")


# ---------- evidence ----------

def test_get_artifacts_marked_untrusted(soar):
    out = get_artifacts(1001)
    assert out["_notice"] == UNTRUSTED_NOTICE and out["count"] == 3
    assert last(soar, "artifact")["_filter_container"] == 1001


def test_get_notes(soar):
    out = get_notes(1001)
    assert out["items"][0]["title"] == "L1 check" and out["_notice"] == UNTRUSTED_NOTICE


def test_get_action_runs_joins_results(soar):
    out = get_action_runs(1001)
    assert out["count"] == 2 and out["failed"] == 1
    ip = next(i for i in out["items"] if i["id"] == 5001)
    assert ip["app_runs"][0]["results"][0]["summary"]["abuseConfidenceScore"] == 95
    vt = next(i for i in out["items"] if i["id"] == 5002)
    assert "quota" in vt["app_runs"][0]["message"]


def test_get_action_runs_without_results(soar):
    out = get_action_runs(1001, include_results=False)
    assert all("app_runs" not in i for i in out["items"])
    assert all(p != "app_run" for p, _ in soar.calls)


# ---------- playbooks ----------

def test_list_playbooks_active_and_name(soar):
    out = list_playbooks(name_contains="enrich")
    p = last(soar, "playbook")
    assert p["_filter_active"] == "true" and p["_filter_name__icontains"] == '"enrich"'
    assert "internal_junk" not in out["items"][0]


def test_list_playbooks_label_filter_includes_wildcard(soar):
    names = {p["name"] for p in list_playbooks(label="edr")["items"]}
    assert names == {"edr_ip_hash_enrichment", "generic_notify"}  # '*' matches every label


def test_get_playbook_runs_resolves_names(soar):
    out = get_playbook_runs(container_id=1001, status="failed")
    p = last(soar, "playbook_run")
    assert p["_filter_container"] == 1001 and p["_filter_status"] == '"failed"'
    assert out["failed"] == 1
    assert out["items"][0]["playbook_name"] == "edr_ip_hash_enrichment"


def test_get_playbook_runs_by_playbook_name(soar):
    get_playbook_runs(playbook_name="edr_ip_hash_enrichment")
    assert last(soar, "playbook_run")["_filter_playbook"] == 31
    with pytest.raises(ToolError, match="playbook not found"):
        get_playbook_runs(playbook_name="nope")
    with pytest.raises(ToolError, match="status"):
        get_playbook_runs(status="exploded")


def test_get_playbook_run_log_filter(soar):
    out = get_playbook_run_log(88001, contains="traceback")
    assert out["total"] == 1 and "KeyError" in out["items"][0]["message"]
    assert out["_notice"] == UNTRUSTED_NOTICE
    assert get_playbook_run_log(88001)["total"] == 4


# ---------- custom lists ----------

def test_list_custom_lists_counts_rows(soar):
    out = list_custom_lists()
    assert {i["name"]: i["rows"] for i in out["items"]} == {"vip_users": 2, "ip_allowlist": 2}
    assert "content" not in json.dumps(out)


def test_get_custom_list_filter(soar):
    out = get_custom_list("vip_users", contains="JDOE")
    assert out["items"] == [{"row_index": 0, "values": ["jdoe", "Finance"]}]
    assert out["total_rows"] == 1
    assert out["_notice"] == UNTRUSTED_NOTICE
    with pytest.raises(ToolError, match="not found"):
        get_custom_list("missing_list")


# ---------- assets ----------

def test_list_assets_hides_credentials(soar):
    out = list_assets()
    dumped = json.dumps(out)
    assert out["count"] == 2
    assert "FAKE" not in dumped and "configuration" not in dumped


# ---------- audit ----------

def test_audit_log_written(soar, env):
    get_container(1001)
    with pytest.raises(ToolError):
        get_container(99999)
    lines = [json.loads(x) for x in env.read_text().splitlines()]
    assert lines[-2]["tool"] == "get_container" and lines[-2]["status"] == "ok"
    assert lines[-1]["status"] == "error" and "duration_ms" in lines[-1]
    assert TOKEN not in env.read_text()


def test_get_action_run_with_results(soar):
    out = get_action_run(5002)
    assert out["items"]["status"] == "failed"
    assert last(soar, "app_run")["_filter_action_run"] == 5002


def test_get_playbook_run_has_name(soar):
    assert get_playbook_run(88001)["run"]["playbook_name"] == "edr_ip_hash_enrichment"


def test_get_asset_redacts_nested_secrets(soar):
    out = get_asset("virustotal")
    dumped = json.dumps(out)
    assert "FAKE" not in dumped
    cfg = out["asset"]["configuration"]
    assert cfg["server"] == "https://vt.example" and cfg["auth"]["username"] == "svc"
    assert cfg["apiKey"] == cfg["auth"]["password"] == cfg["ph-auth-token"] == "«redacted»"
    with pytest.raises(ToolError, match="asset not found"):
        get_asset("nope")
