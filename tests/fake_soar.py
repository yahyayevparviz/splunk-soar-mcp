"""Fake SOAR REST routing shared by unit tests (in-process) and e2e tests (real HTTP).

All data is synthetic: documentation IP ranges (RFC 5737), example.com, invented names.
"""
from __future__ import annotations

import json
from pathlib import Path

FIX = Path(__file__).parent / "fixtures"


def load(name: str):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def _one(obj):
    return {"count": 1, "num_pages": 1, "data": [obj]}


EMPTY = {"count": 0, "num_pages": 0, "data": []}

FIXED_GET = {
    "version": {"version": "6.4.0.0"},
    "container/1001": "container_1001.json",
    "container/990": "container_0990.json",
    "container/2002": "container_2002.json",
    "container": "containers_list.json",
    "note": "notes_1001.json",
    "action_run": "action_runs_1001.json",
    "action_run/5002": "action_run_5002.json",
    "app_run": "app_runs_1001.json",
    "playbook": "playbooks.json",
    "playbook/31": "playbook_31.json",
    "playbook_run": "playbook_runs.json",
    "playbook_run/88001": "playbook_run_88001.json",
    "playbook_run/88001/log": "playbook_run_log_88001.json",
    "asset": "assets.json",
    "decided_list": "decided_lists.json",
}


def route(path: str, params: dict) -> tuple[int, object]:
    """GET /rest/<path> -> (status, json)."""
    name = params.get("_filter_name")
    if path == "artifact":
        if any(str(k).startswith("_filter_cef__") for k in params):
            return 200, load("artifacts_ioc_search.json")
        return 200, load("artifacts_1001.json")
    if path == "playbook" and name is not None:
        pbs = {f'"{p["name"]}"': p for p in load("playbooks.json")["data"]}
        return 200, _one(pbs[name]) if name in pbs else EMPTY
    if path == "decided_list" and name is not None:
        return 200, load("decided_list_vip.json") if name == '"vip_users"' else EMPTY
    if path == "asset" and name is not None:
        assets = {f'"{a["name"]}"': a for a in load("assets.json")["data"]}
        return 200, _one(assets[name]) if name in assets else EMPTY
    if path == "app":
        if params.get("_filter_product_name") == '"AbuseIPDB"':
            return 200, _one({"id": 190, "name": "AbuseIPDB", "product_name": "AbuseIPDB"})
        return 200, EMPTY
    if path in FIXED_GET:
        v = FIXED_GET[path]
        return 200, (load(v) if isinstance(v, str) else v)
    return 404, {"message": "not found"}


def route_post(path: str, body: dict) -> tuple[int, object]:
    """POST /rest/<path> -> (status, json). Mimics SOAR's success / failed envelopes."""
    if path.startswith("container/") and path.split("/")[1].isdigit():
        if path.split("/")[1] not in ("1001", "990", "2002"):
            return 404, {"failed": True, "message": "not found"}
        return 200, {"success": True, "id": int(path.split("/")[1])}
    if path == "note":
        return 200, {"success": True, "id": 701}
    if path == "container_comment":
        return 200, {"success": True, "id": 801}
    if path == "artifact":
        return 200, {"success": True, "id": 904}
    if path.startswith("decided_list/"):
        return 200, {"success": True}
    if path == "playbook_run":
        return 200, {"playbook_run_id": 88100, "message": "playbook run started"}
    if path == "action_run":
        return 200, {"action_run_id": 5100, "success": True}
    return 404, {"failed": True, "message": "not found"}
