"""Case (container) tools.

read:     list_containers, get_container, search_containers
standard: update_container, add_note, add_comment
"""
from __future__ import annotations

from typing import Literal

from ..core import guards, scope
from ..core.audit import audited
from ..core.client import SoarError
from ..core.config import get_client
from ..core.modes import Mode
from ..core.shaping import shape_container
from ._common import READ, UPDATE, WRITE, register

VALID_SENSITIVITY = {"white", "green", "amber", "red"}
MAX_NOTE = 20000


# ---------------------------------------------------------------- read

@audited()
def list_containers(status: str | None = None, severity: str | None = None,
                    label: str | None = None, since_hours: int | None = 24,
                    limit: int = 20) -> dict:
    n = guards.clamp_limit(limit)
    params = {"sort": "create_time", "order": "desc"}
    if s := guards.check_status(status):
        params["_filter_status"] = guards.soar_str(s)
    if sev := guards.check_severity(severity):
        params["_filter_severity"] = guards.soar_str(sev)
    if since := guards.since_iso(since_hours):
        params["_filter_create_time__gt"] = guards.soar_str(since)

    lbl = guards.check_label(label)
    allowed = scope.allowed_labels()
    if allowed is not None:
        if lbl and lbl not in allowed:
            return {"count": 0, "items": []}          # do not reveal whether the label exists
        if not lbl and len(allowed) == 1:
            lbl = next(iter(allowed))
    if lbl:
        params["_filter_label"] = guards.soar_str(lbl)

    fetch = guards.MAX_LIMIT if (allowed is not None and not lbl) else n
    data = scope.filter_containers(get_client().get_list("container", limit=fetch, **params))[:n]
    return {"count": len(data), "items": [shape_container(x) for x in data]}


@audited()
def get_container(container_id: int) -> dict:
    cid = guards.positive_id(container_id, "container_id")
    return {"container": shape_container(scope.require_container(get_client(), cid))}


@audited()
def search_containers(query: str, mode: Literal["name", "ioc"] = "name",
                      cef_field: str | None = None, limit: int = 20) -> dict:
    q = guards.check_text(query)
    n = guards.clamp_limit(limit)
    c = get_client()

    if mode == "name":
        data = c.get_list("container", limit=guards.MAX_LIMIT if scope.allowed_labels() else n,
                          sort="create_time", order="desc",
                          _filter_name__icontains=guards.soar_str(q))
        data = scope.filter_containers(data)[:n]
        return {"mode": mode, "query": q, "count": len(data),
                "items": [shape_container(x) for x in data]}

    if mode == "ioc":
        if not cef_field:
            raise SoarError("mode='ioc' requires cef_field (e.g. sourceAddress)")
        field = guards.check_cef_field(cef_field)
        arts = c.get_list("artifact", limit=guards.MAX_LIMIT, sort="create_time", order="desc",
                          **{f"_filter_cef__{field}": guards.soar_str(q)})
        ids: list[int] = []
        for a in arts:
            cid = a.get("container")
            if cid and cid not in ids:
                ids.append(cid)
        items = []
        for cid in ids:
            if len(items) >= n:
                break
            try:
                container = c.get(f"container/{cid}")
            except SoarError:
                continue
            if scope.is_allowed(container):
                items.append(shape_container(container))
        return {"mode": mode, "cef_field": field, "query": q, "count": len(items), "items": items}

    raise SoarError("mode must be 'name' or 'ioc'")


# ---------------------------------------------------------------- write (standard)

@audited("write")
def update_container(container_id: int, status: str | None = None,
                     severity: str | None = None, sensitivity: str | None = None,
                     owner_id: int | None = None) -> dict:
    cid = guards.positive_id(container_id, "container_id")
    changes: dict = {}
    if s := guards.check_status(status):
        changes["status"] = s
    if sev := guards.check_severity(severity):
        changes["severity"] = sev
    if sensitivity:
        sen = sensitivity.lower().strip()
        if sen not in VALID_SENSITIVITY:
            raise SoarError(f"sensitivity must be one of {sorted(VALID_SENSITIVITY)}")
        changes["sensitivity"] = sen
    if owner_id is not None:
        changes["owner_id"] = guards.positive_id(owner_id, "owner_id")
    if not changes:
        raise SoarError("nothing to update: give status, severity, sensitivity or owner_id")

    c = get_client()
    before = scope.require_container(c, cid)
    c.post(f"container/{cid}", changes)
    diff = {k: {"from": before.get("owner" if k == "owner_id" else k), "to": v}
            for k, v in changes.items()}
    return {"updated": True, "container_id": cid, "changes": diff}


@audited("write")
def add_note(container_id: int, title: str, content: str) -> dict:
    cid = guards.positive_id(container_id, "container_id")
    t = guards.check_text(title, "title", max_len=256)
    body = guards.check_text(content, "content", max_len=MAX_NOTE)
    c = get_client()
    scope.require_container(c, cid)
    res = c.post("note", {"container_id": cid, "title": t, "content": body,
                          "note_type": "general"})
    return {"created": True, "container_id": cid, "note_id": res.get("id")}


@audited("write")
def add_comment(container_id: int, comment: str) -> dict:
    cid = guards.positive_id(container_id, "container_id")
    text = guards.check_text(comment, "comment", max_len=MAX_NOTE)
    c = get_client()
    scope.require_container(c, cid)
    res = c.post("container_comment", {"container_id": cid, "comment": text})
    return {"created": True, "container_id": cid, "comment_id": res.get("id")}


def register_tools(server, mode: Mode) -> list[str]:
    return register(server, mode,
                    (list_containers, Mode.READONLY, READ),
                    (get_container, Mode.READONLY, READ),
                    (search_containers, Mode.READONLY, READ),
                    (update_container, Mode.STANDARD, UPDATE),
                    (add_note, Mode.STANDARD, WRITE),
                    (add_comment, Mode.STANDARD, WRITE))
