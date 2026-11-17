"""Playbook tools (read): list_playbooks, get_playbook_runs, get_playbook_run, get_playbook_run_log."""
from __future__ import annotations

from ..core import guards, scope
from ..core.audit import audited
from ..core.client import SoarClient, SoarError
from ..core.config import get_client
from ..core.modes import Mode
from ..core.shaping import _trim, shape_playbook, shape_playbook_run, wrap_untrusted
from ._common import READ, register

RUN_STATUSES = {"running", "success", "failed", "cancelled"}
LOG_MAX = 500


def playbook_names(c: SoarClient, ids: set[int]) -> dict[int, str]:
    names: dict[int, str] = {}
    for pid in list(ids)[:30]:
        try:
            names[pid] = c.get(f"playbook/{pid}").get("name", "")
        except SoarError:
            names[pid] = ""
    return names


def find_playbook(c: SoarClient, name: str) -> dict:
    found = c.get_list("playbook", limit=1, _filter_name=guards.soar_str(name))
    if not found:
        raise SoarError(f"playbook not found: {name}")
    return found[0]


def _containers_allowed(c: SoarClient, ids: set[int]) -> set[int]:
    ok = set()
    for cid in list(ids)[:50]:
        try:
            if scope.is_allowed(c.get(f"container/{cid}")):
                ok.add(cid)
        except SoarError:
            pass
    return ok


@audited()
def list_playbooks(name_contains: str | None = None, label: str | None = None,
                   active_only: bool = True, limit: int = 50) -> dict:
    q = guards.check_text(name_contains, "name_contains", required=False)
    lbl = guards.check_label(label)
    params = {"sort": "name", "order": "asc"}
    if q:
        params["_filter_name__icontains"] = guards.soar_str(q)
    if active_only:
        params["_filter_active"] = "true"
    n = guards.clamp_limit(limit, 50)
    fetch = guards.MAX_LIMIT if lbl else n
    data = [shape_playbook(p) for p in get_client().get_list("playbook", limit=fetch, **params)]
    if lbl:  # a playbook's 'labels' is a list; '*' means every label
        data = [p for p in data if lbl in (p.get("labels") or []) or "*" in (p.get("labels") or [])]
    data = data[:n]
    return {"count": len(data), "items": data}


@audited()
def get_playbook_runs(container_id: int | None = None, playbook_name: str | None = None,
                      status: str | None = None, limit: int = 20) -> dict:
    c = get_client()
    params: dict = {"sort": "id", "order": "desc"}
    if container_id is not None:
        cid = guards.positive_id(container_id, "container_id")
        scope.check_container_id(c, cid)
        params["_filter_container"] = cid
    if status:
        s = status.lower().strip()
        if s not in RUN_STATUSES:
            raise SoarError(f"status must be one of {sorted(RUN_STATUSES)}")
        params["_filter_status"] = guards.soar_str(s)
    if name := guards.check_text(playbook_name, "playbook_name", required=False):
        params["_filter_playbook"] = find_playbook(c, name)["id"]

    runs = [shape_playbook_run(r) for r in
            c.get_list("playbook_run", limit=guards.clamp_limit(limit), **params)]
    if scope.allowed_labels() is not None and container_id is None:
        ok = _containers_allowed(c, {r["container"] for r in runs if r.get("container")})
        runs = [r for r in runs if r.get("container") in ok]
    names = playbook_names(c, {r["playbook"] for r in runs if isinstance(r.get("playbook"), int)})
    for r in runs:
        if names.get(r.get("playbook")):
            r["playbook_name"] = names[r["playbook"]]
    failed = sum(1 for r in runs if r.get("status") == "failed")
    return {"count": len(runs), "failed": failed, "items": runs}


def _scoped_run(c: SoarClient, rid: int) -> dict:
    run = c.get(f"playbook_run/{rid}")
    if run.get("container"):
        scope.check_container_id(c, run["container"])
    return run


@audited()
def get_playbook_run(run_id: int) -> dict:
    rid = guards.positive_id(run_id, "run_id")
    c = get_client()
    run = shape_playbook_run(_scoped_run(c, rid))
    if isinstance(run.get("playbook"), int):
        run["playbook_name"] = playbook_names(c, {run["playbook"]}).get(run["playbook"], "")
    return {"run": run}


@audited()
def get_playbook_run_log(run_id: int, contains: str | None = None, limit: int = 200) -> dict:
    rid = guards.positive_id(run_id, "run_id")
    needle = guards.check_text(contains, "contains", required=False)
    n = max(1, min(int(limit), LOG_MAX))
    c = get_client()
    if scope.allowed_labels() is not None:
        _scoped_run(c, rid)
    body = c.get(f"playbook_run/{rid}/log", page_size=LOG_MAX, page=0)
    entries = body.get("data", []) if isinstance(body, dict) else (body or [])
    if needle:
        low = needle.lower()
        entries = [e for e in entries if low in str(e.get("message", "")).lower()]
    total = len(entries)
    return wrap_untrusted([_trim(e) for e in entries[:n]], run_id=rid, total=total,
                          returned=min(total, n), filter=needle)


def register_tools(server, mode: Mode) -> list[str]:
    return register(server, mode,
                    (list_playbooks, Mode.READONLY, READ),
                    (get_playbook_runs, Mode.READONLY, READ),
                    (get_playbook_run, Mode.READONLY, READ),
                    (get_playbook_run_log, Mode.READONLY, READ))
