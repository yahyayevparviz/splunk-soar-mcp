"""What an MCP client sees in each mode: registered tools, annotations, resources, prompts."""
import asyncio
import json

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from soar_analyst_mcp.core.modes import Mode
from soar_analyst_mcp.server import build_server

READ_TOOLS = {
    "server_info",
    "list_containers", "get_container", "search_containers",
    "get_artifacts", "get_notes", "get_action_runs", "get_action_run",
    "list_playbooks", "get_playbook_runs", "get_playbook_run", "get_playbook_run_log",
    "list_custom_lists", "get_custom_list", "list_assets", "get_asset",
}
WRITE_TOOLS = {"update_container", "add_note", "add_comment", "add_artifact",
               "append_to_custom_list", "update_custom_list_row"}
EXEC_TOOLS = {"run_playbook", "run_action"}


def run(coro):
    return asyncio.run(coro)


def tools(mode):
    return {t.name: t for t in run(build_server(mode).list_tools())}


def test_readonly_exposes_no_mutating_tool(env):
    t = tools(Mode.READONLY)
    assert set(t) == READ_TOOLS
    assert all(x.annotations.read_only_hint for x in t.values())


def test_standard_adds_writes_only(env):
    t = tools(Mode.STANDARD)
    assert set(t) == READ_TOOLS | WRITE_TOOLS
    for name in WRITE_TOOLS:
        assert t[name].annotations.read_only_hint is False


def test_full_adds_execution(env):
    t = tools(Mode.FULL)
    assert set(t) == READ_TOOLS | WRITE_TOOLS | EXEC_TOOLS
    for name in EXEC_TOOLS:
        assert t[name].annotations.destructive_hint is True
        assert t[name].annotations.read_only_hint is False


def test_default_mode_from_env_is_readonly(env):
    assert {t.name for t in run(build_server().list_tools())} == READ_TOOLS


def test_instructions_follow_mode(env):
    assert "READ-ONLY" in build_server(Mode.READONLY).instructions
    assert "EXECUTE" in build_server(Mode.FULL).instructions


def test_every_tool_has_a_real_description(env):
    for t in tools(Mode.FULL).values():
        assert t.description and len(t.description) > 40


def test_resource_and_prompts(env):
    s = build_server()
    assert [str(r.uri) for r in run(s.list_resources())] == ["soar://playbooks/catalog"]
    assert {p.name for p in run(s.list_prompts())} == {"triage_case", "debug_playbook_run"}


def test_call_tool_through_server(soar):
    result = run(build_server().call_tool("get_container", {"container_id": 1001}))
    assert json.loads(result.content[0].text)["container"]["id"] == 1001


def test_call_tool_error_raises_tool_error(soar):
    with pytest.raises(ToolError, match="not found"):
        run(build_server().call_tool("get_container", {"container_id": 99999}))


def test_catalog_resource(soar):
    body = json.loads(list(run(build_server().read_resource("soar://playbooks/catalog")))[0].content)
    assert body["count"] == 3


def test_server_info(soar):
    info = run(build_server().call_tool("server_info", {}))
    data = json.loads(info.content[0].text)
    assert data["soar_version"] == "6.4.0.0" and data["mode"] == "readonly"
    assert data["can_write"] is False and data["can_execute"] is False
