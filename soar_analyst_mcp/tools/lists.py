"""Custom list tools (SOAR 'decided_list').

read:     list_custom_lists, get_custom_list
standard: append_to_custom_list, update_custom_list_row
"""
from __future__ import annotations

from ..core import guards
from ..core.audit import audited
from ..core.client import SoarClient, SoarError
from ..core.config import get_client
from ..core.modes import Mode
from ..core.shaping import _trim, wrap_untrusted
from ._common import READ, UPDATE, WRITE, register

MAX_CELLS = 20
MAX_CELL_LEN = 1024


def _find_list(c: SoarClient, name: str) -> dict:
    list_name = guards.check_text(name, "name")
    found = c.get_list("decided_list", limit=1, _filter_name=guards.soar_str(list_name))
    if not found:
        raise SoarError(f"custom list not found: {list_name}")
    return found[0]


def _check_row(row: list) -> list[str]:
    if not isinstance(row, list) or not row:
        raise SoarError("row must be a non-empty list of values, e.g. [\"203.0.113.5\", \"scanner\"]")
    if len(row) > MAX_CELLS:
        raise SoarError(f"row has too many cells (max {MAX_CELLS})")
    out = []
    for cell in row:
        if not isinstance(cell, (str, int, float, bool)) and cell is not None:
            raise SoarError("row cells must be scalar values")
        s = "" if cell is None else str(cell)
        if len(s) > MAX_CELL_LEN:
            raise SoarError(f"cell too long (max {MAX_CELL_LEN} chars)")
        out.append(s)
    return out


# ---------------------------------------------------------------- read

@audited()
def list_custom_lists(name_contains: str | None = None, limit: int = 50) -> dict:
    q = guards.check_text(name_contains, "name_contains", required=False)
    params = {"sort": "name", "order": "asc"}
    if q:
        params["_filter_name__icontains"] = guards.soar_str(q)
    data = get_client().get_list("decided_list", limit=guards.clamp_limit(limit, 50), **params)
    items = [{"id": d.get("id"), "name": d.get("name"), "rows": len(d.get("content") or []),
              "update_time": d.get("update_time")} for d in data]
    return {"count": len(items), "items": items}


@audited()
def get_custom_list(name: str, contains: str | None = None, max_rows: int = 100) -> dict:
    needle = guards.check_text(contains, "contains", required=False)
    found = _find_list(get_client(), name)
    rows = [(i, r) for i, r in enumerate(found.get("content") or [])]
    if needle:
        low = needle.lower()
        rows = [(i, r) for i, r in rows if any(low in str(cell).lower() for cell in (r or []))]
    n = guards.clamp_limit(max_rows, 100)
    items = [{"row_index": i, "values": _trim(r)} for i, r in rows[:n]]
    return wrap_untrusted(items, name=found.get("name"), id=found.get("id"),
                          total_rows=len(rows), returned=len(items), filter=needle)


# ---------------------------------------------------------------- write (standard)

@audited("write")
def append_to_custom_list(name: str, row: list) -> dict:
    values = _check_row(row)
    c = get_client()
    found = _find_list(c, name)
    c.post(f"decided_list/{found['id']}", {"append_rows": [values]})
    return {"appended": True, "name": found.get("name"), "row": values,
            "rows_before": len(found.get("content") or [])}


@audited("write")
def update_custom_list_row(name: str, row_index: int, row: list) -> dict:
    values = _check_row(row)
    c = get_client()
    found = _find_list(c, name)
    content = found.get("content") or []
    try:
        idx = int(row_index)
    except (TypeError, ValueError) as e:
        raise SoarError("row_index must be an integer") from e
    if not 0 <= idx < len(content):
        raise SoarError(f"row_index out of range (list has {len(content)} rows, 0-based)")
    c.post(f"decided_list/{found['id']}", {"update_rows": {str(idx): values}})
    return {"updated": True, "name": found.get("name"), "row_index": idx,
            "from": content[idx], "to": values}


def register_tools(server, mode: Mode) -> list[str]:
    return register(server, mode,
                    (list_custom_lists, Mode.READONLY, READ),
                    (get_custom_list, Mode.READONLY, READ),
                    (append_to_custom_list, Mode.STANDARD, WRITE),
                    (update_custom_list_row, Mode.STANDARD, UPDATE))
