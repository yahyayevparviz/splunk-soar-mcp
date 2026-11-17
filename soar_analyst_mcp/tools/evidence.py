"""Evidence tools.

read:     get_artifacts, get_notes, get_action_runs, get_action_run
standard: add_artifact
"""
from __future__ import annotations

import re

from ..core import guards, scope
from ..core.audit import audited
from ..core.client import SoarError
from ..core.config import get_client
from ..core.modes import Mode
from ..core.shaping import (shape_action_run, shape_app_run, shape_artifact, shape_note,
                            wrap_untrusted)
from ._common import READ, WRITE, register

_CEF_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
MAX_CEF_KEYS = 50


# ---------------------------------------------------------------- read

@audited()
def get_artifacts(container_id: int, limit: int = 50) -> dict:
    cid = guards.positive_id(container_id, "container_id")
    c = get_client()
    scope.check_container_id(c, cid)
    data = c.get_list("artifact", limit=guards.clamp_limit(limit, 50),
                      sort="id", order="asc", _filter_container=cid)
    return wrap_untrusted([shape_artifact(a) for a in data], container_id=cid, count=len(data))


@audited()
def get_notes(container_id: int, limit: int = 50) -> dict:
    cid = guards.positive_id(container_id, "container_id")
    c = get_client()
    scope.check_container_id(c, cid)
    data = c.get_list("note", limit=guards.clamp_limit(limit, 50),
                      sort="create_time", order="asc", _filter_container=cid)
    return wrap_untrusted([shape_note(x) for x in data], container_id=cid, count=len(data))


def _attach_app_runs(c, items: list[dict], **app_filter) -> None:
    app_runs = c.get_list("app_run", limit=guards.MAX_LIMIT, sort="id", order="desc", **app_filter)
    by_action: dict[int, list[dict]] = {}
    for ar in app_runs:
        by_action.setdefault(ar.get("action_run"), []).append(shape_app_run(ar))
    for item in items:
        if item.get("id") in by_action:
            item["app_runs"] = by_action[item["id"]]


@audited()
def get_action_runs(container_id: int, include_results: bool = True, limit: int = 30) -> dict:
    cid = guards.positive_id(container_id, "container_id")
    c = get_client()
    scope.check_container_id(c, cid)
    runs = c.get_list("action_run", limit=guards.clamp_limit(limit, 30),
                      sort="id", order="desc", _filter_container=cid)
    items = [shape_action_run(r) for r in runs]
    if include_results and runs:
        _attach_app_runs(c, items, _filter_container=cid)
    failed = sum(1 for r in items if r.get("status") == "failed")
    return wrap_untrusted(items, container_id=cid, count=len(items), failed=failed)


@audited()
def get_action_run(run_id: int) -> dict:
    rid = guards.positive_id(run_id, "run_id")
    c = get_client()
    run = c.get(f"action_run/{rid}")
    if run.get("container"):
        scope.check_container_id(c, run["container"])
    item = shape_action_run(run)
    _attach_app_runs(c, [item], _filter_action_run=rid)
    return wrap_untrusted(item, run_id=rid)


# ---------------------------------------------------------------- write (standard)

@audited("write")
def add_artifact(container_id: int, name: str, cef: dict, label: str = "event",
                 severity: str | None = None) -> dict:
    cid = guards.positive_id(container_id, "container_id")
    art_name = guards.check_text(name, "name", max_len=128)
    lbl = guards.check_label(label) or "event"
    if not isinstance(cef, dict) or not cef:
        raise SoarError("cef must be a non-empty object, e.g. {\"destinationAddress\": \"1.2.3.4\"}")
    if len(cef) > MAX_CEF_KEYS:
        raise SoarError(f"too many cef fields (max {MAX_CEF_KEYS})")
    for k, v in cef.items():
        if not _CEF_KEY.match(str(k)):
            raise SoarError(f"invalid cef key: {k!r}")
        if not isinstance(v, (str, int, float, bool)) or (isinstance(v, str) and len(v) > 4096):
            raise SoarError(f"cef value for {k!r} must be a scalar (string ≤ 4096 chars)")
    body = {"container_id": cid, "name": art_name, "label": lbl, "cef": cef,
            "run_automation": False}  # never trigger active playbooks from an AI-added artifact
    if sev := guards.check_severity(severity):
        body["severity"] = sev
    c = get_client()
    scope.require_container(c, cid)
    res = c.post("artifact", body)
    return {"created": True, "container_id": cid, "artifact_id": res.get("id"),
            "run_automation": False}


def register_tools(server, mode: Mode) -> list[str]:
    return register(server, mode,
                    (get_artifacts, Mode.READONLY, READ),
                    (get_notes, Mode.READONLY, READ),
                    (get_action_runs, Mode.READONLY, READ),
                    (get_action_run, Mode.READONLY, READ),
                    (add_artifact, Mode.STANDARD, WRITE))
