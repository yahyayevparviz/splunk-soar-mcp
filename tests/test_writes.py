"""Standard-mode write tools: exact payloads sent to SOAR + validation."""
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from soar_analyst_mcp.tools.cases import add_comment, add_note, update_container
from soar_analyst_mcp.tools.evidence import add_artifact
from soar_analyst_mcp.tools.lists import append_to_custom_list, update_custom_list_row


def last_post(soar):
    return soar.posts[-1]


# ---------- update_container ----------

def test_update_container_payload_and_diff(soar):
    out = update_container(1001, status="open", severity="medium")
    path, body = last_post(soar)
    assert path == "container/1001" and body == {"status": "open", "severity": "medium"}
    assert out["changes"]["status"] == {"from": "new", "to": "open"}
    assert out["changes"]["severity"] == {"from": "high", "to": "medium"}


def test_update_container_owner_and_sensitivity(soar):
    update_container(1001, sensitivity="RED", owner_id=7)
    assert last_post(soar)[1] == {"sensitivity": "red", "owner_id": 7}


def test_update_container_validation(soar):
    with pytest.raises(ToolError, match="nothing to update"):
        update_container(1001)
    with pytest.raises(ToolError, match="severity"):
        update_container(1001, severity="critical")
    with pytest.raises(ToolError, match="sensitivity"):
        update_container(1001, sensitivity="black")
    with pytest.raises(ToolError, match="not found or not accessible"):
        update_container(4242, status="open")
    assert soar.posts == []  # nothing was sent for any invalid call


# ---------- notes / comments ----------

def test_add_note_payload(soar):
    out = add_note(1001, "Triage summary", "Likely TP. Evidence: ...")
    assert last_post(soar) == ("note", {"container_id": 1001, "title": "Triage summary",
                                        "content": "Likely TP. Evidence: ...",
                                        "note_type": "general"})
    assert out == {"created": True, "container_id": 1001, "note_id": 701}


def test_add_note_validation(soar):
    with pytest.raises(ToolError, match="title"):
        add_note(1001, "", "x")
    with pytest.raises(ToolError, match="content too long"):
        add_note(1001, "t", "x" * 20001)


def test_add_comment_payload(soar):
    add_comment(1001, "Escalated to L2")
    assert last_post(soar) == ("container_comment",
                               {"container_id": 1001, "comment": "Escalated to L2"})


# ---------- artifacts ----------

def test_add_artifact_never_runs_automation(soar):
    out = add_artifact(1001, "New C2 IP", {"destinationAddress": "203.0.113.77"}, severity="high")
    path, body = last_post(soar)
    assert path == "artifact"
    assert body["run_automation"] is False and body["label"] == "event"
    assert body["cef"] == {"destinationAddress": "203.0.113.77"} and body["severity"] == "high"
    assert out["artifact_id"] == 904


@pytest.mark.parametrize("cef,msg", [
    ({}, "non-empty"),
    ({"bad key!": "x"}, "invalid cef key"),
    ({"ok": {"nested": 1}}, "scalar"),
    ({f"k{i}": "v" for i in range(51)}, "too many"),
])
def test_add_artifact_validation(soar, cef, msg):
    with pytest.raises(ToolError, match=msg):
        add_artifact(1001, "x", cef)


# ---------- custom lists ----------

def test_append_to_custom_list(soar):
    out = append_to_custom_list("vip_users", ["ckim", 42])
    assert last_post(soar) == ("decided_list/5", {"append_rows": [["ckim", "42"]]})
    assert out["rows_before"] == 3


def test_update_custom_list_row(soar):
    out = update_custom_list_row("vip_users", 1, ["asmith", "Board"])
    assert last_post(soar) == ("decided_list/5", {"update_rows": {"1": ["asmith", "Board"]}})
    assert out["from"] == ["asmith", "CEO office"]


def test_custom_list_write_validation(soar):
    with pytest.raises(ToolError, match="out of range"):
        update_custom_list_row("vip_users", 99, ["x"])
    with pytest.raises(ToolError, match="non-empty list"):
        append_to_custom_list("vip_users", [])
    with pytest.raises(ToolError, match="not found"):
        append_to_custom_list("ghost_list", ["x"])
    with pytest.raises(ToolError, match="scalar"):
        append_to_custom_list("vip_users", [{"a": 1}])
    assert soar.posts == []


def test_write_audit_kind(soar, env):
    import json
    add_comment(1001, "hi")
    rec = json.loads(env.read_text().splitlines()[-1])
    assert rec["tool"] == "add_comment" and rec["kind"] == "write" and rec["status"] == "ok"
