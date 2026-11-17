"""SOAR_ALLOWED_LABELS: reads and writes outside the allowed labels are refused, without
revealing the label. Fixtures: 1001=edr (allowed), 990=siem, 2002=other_team."""
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from soar_analyst_mcp.tools.cases import (add_note, get_container, list_containers,
                                          search_containers, update_container)
from soar_analyst_mcp.tools.evidence import get_artifacts, get_notes
from soar_analyst_mcp.tools.playbooks import get_playbook_run_log, get_playbook_runs
from soar_analyst_mcp.tools.system import server_info

DENIED = "not found or not accessible"


def test_get_container_allowed_and_denied(soar, scoped):
    assert get_container(1001)["container"]["label"] == "edr"
    with pytest.raises(ToolError, match=DENIED) as e:
        get_container(2002)
    assert "other_team" not in str(e.value)


def test_missing_and_denied_look_identical(soar, scoped):
    with pytest.raises(ToolError) as missing:
        get_container(4242)
    with pytest.raises(ToolError) as denied:
        get_container(2002)
    assert str(missing.value).replace("4242", "N") == str(denied.value).replace("2002", "N")


def test_list_containers_filtered(soar, scoped):
    out = list_containers()
    assert {c["label"] for c in out["items"]} == {"edr"}
    # single allowed label is pushed down to SOAR as a filter
    assert next(p for path, p in reversed(soar.calls) if path == "container")["_filter_label"] == '"edr"'


def test_list_containers_other_label_returns_nothing(soar, scoped):
    assert list_containers(label="other_team") == {"count": 0, "items": []}


def test_search_filtered(soar, scoped):
    assert {c["label"] for c in search_containers("case")["items"]} <= {"edr"}
    ioc = search_containers("203.0.113.45", mode="ioc", cef_field="destinationAddress")
    assert [c["id"] for c in ioc["items"]] == [1001]  # 990 (siem) dropped


@pytest.mark.parametrize("fn", [get_artifacts, get_notes])
def test_evidence_denied(soar, scoped, fn):
    with pytest.raises(ToolError, match=DENIED):
        fn(2002)
    assert fn(1001)["count"] >= 1


def test_playbook_runs_filtered(soar, scoped):
    runs = get_playbook_runs()["items"]
    assert {r["container"] for r in runs} <= {1001}
    with pytest.raises(ToolError, match=DENIED):
        get_playbook_runs(container_id=2002)


def test_playbook_run_log_scoped(soar, scoped):
    assert get_playbook_run_log(88001)["total"] == 4  # run 88001 is on container 1001 (edr)


def test_writes_denied_outside_scope(soar, scoped):
    with pytest.raises(ToolError, match=DENIED):
        update_container(2002, status="closed")
    with pytest.raises(ToolError, match=DENIED):
        add_note(2002, "t", "c")
    assert soar.posts == []


def test_server_info_reports_count_not_labels(soar, scoped):
    info = server_info()
    assert info["label_scoped"] is True and info["allowed_label_count"] == 1
    assert "edr" not in str(info)
