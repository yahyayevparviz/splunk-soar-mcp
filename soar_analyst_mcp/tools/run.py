"""Execution tools (full mode only): run_playbook, run_action.

Both are limited by an allowlist from the environment. An empty allowlist means NOTHING can be
run, even in full mode. Both are asynchronous: they return a run id; poll it with
get_playbook_run / get_action_run. 'Started' does not mean 'succeeded'.
"""
from __future__ import annotations

from ..core import guards, scope
from ..core.audit import audited
from ..core.client import SoarError
from ..core.config import get_client
from ..core.modes import Mode, action_allowlist, playbook_allowlist
from ._common import EXECUTE, register
from .playbooks import find_playbook

MAX_PARAMS = 20


@audited("execute")
def run_playbook(container_id: int, playbook_name: str, run_scope: str = "new") -> dict:
    cid = guards.positive_id(container_id, "container_id")
    name = guards.check_text(playbook_name, "playbook_name", max_len=256)
    allowed = playbook_allowlist()
    if not allowed:
        raise SoarError("run_playbook is disabled: SOAR_PLAYBOOK_ALLOWLIST is empty")
    if name not in allowed:
        raise SoarError(f"playbook '{name}' is not in SOAR_PLAYBOOK_ALLOWLIST")
    if run_scope not in ("new", "all"):
        raise SoarError("run_scope must be 'new' or 'all'")
    c = get_client()
    scope.require_container(c, cid)
    pb = find_playbook(c, name)
    if pb.get("active") is False:
        raise SoarError(f"playbook '{name}' is not active")
    res = c.post("playbook_run", {"container_id": cid, "playbook_id": pb["id"],
                                  "scope": run_scope, "run": True})
    return {"started": True, "container_id": cid, "playbook": name,
            "playbook_run_id": res.get("playbook_run_id"),
            "next": "poll get_playbook_run(run_id) and read get_playbook_run_log(run_id)"}


def _check_parameters(parameters: list) -> list[dict]:
    if not isinstance(parameters, list) or not parameters:
        raise SoarError("parameters must be a non-empty list of objects, e.g. [{\"ip\": \"203.0.113.5\"}]")
    if len(parameters) > MAX_PARAMS:
        raise SoarError(f"too many parameter sets (max {MAX_PARAMS})")
    for p in parameters:
        if not isinstance(p, dict) or not p:
            raise SoarError("each parameter set must be a non-empty object")
        for k, v in p.items():
            if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
                raise SoarError("parameter keys must be strings and values scalars")
    return parameters


@audited("execute")
def run_action(container_id: int, action: str, asset_name: str, parameters: list,
               app_id: int | None = None) -> dict:
    cid = guards.positive_id(container_id, "container_id")
    act = guards.check_text(action, "action", max_len=128).lower()
    allowed = action_allowlist()
    if not allowed:
        raise SoarError("run_action is disabled: SOAR_ACTION_ALLOWLIST is empty")
    if act not in allowed:
        raise SoarError(f"action '{act}' is not in SOAR_ACTION_ALLOWLIST")
    params = _check_parameters(parameters)
    asset = guards.check_text(asset_name, "asset_name", max_len=128)

    c = get_client()
    scope.require_container(c, cid)
    found = c.get_list("asset", limit=1, _filter_name=guards.soar_str(asset))
    if not found:
        raise SoarError(f"asset not found: {asset}")
    if app_id is None:
        product = found[0].get("product_name")
        apps = c.get_list("app", limit=1, _filter_product_name=guards.soar_str(product)) if product else []
        if not apps:
            raise SoarError(f"cannot resolve app for asset '{asset}'; pass app_id")
        app_id = apps[0]["id"]
    else:
        app_id = guards.positive_id(app_id, "app_id")

    res = c.post("action_run", {
        "action": act, "container_id": cid, "name": f"mcp_{act.replace(' ', '_')}",
        "targets": [{"assets": [asset], "parameters": params, "app_id": app_id}],
    })
    return {"started": True, "container_id": cid, "action": act, "asset": asset,
            "app_id": app_id, "action_run_id": res.get("action_run_id"),
            "next": "poll get_action_run(run_id)"}


def register_tools(server, mode: Mode) -> list[str]:
    return register(server, mode,
                    (run_playbook, Mode.FULL, EXECUTE),
                    (run_action, Mode.FULL, EXECUTE))
