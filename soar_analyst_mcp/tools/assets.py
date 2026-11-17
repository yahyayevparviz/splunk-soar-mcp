"""Asset tools (read): list_assets, get_asset.

Asset configuration contains credentials. list_assets never returns it; get_asset returns it
only after central redaction (core/redaction.py), so secrets become «redacted».
"""
from __future__ import annotations

from ..core import guards
from ..core.audit import audited
from ..core.client import SoarError
from ..core.config import get_client
from ..core.modes import Mode
from ..core.redaction import redact
from ..core.shaping import shape_asset
from ._common import READ, register


@audited()
def list_assets(name_contains: str | None = None, limit: int = 50) -> dict:
    q = guards.check_text(name_contains, "name_contains", required=False)
    params = {"sort": "name", "order": "asc"}
    if q:
        params["_filter_name__icontains"] = guards.soar_str(q)
    data = get_client().get_list("asset", limit=guards.clamp_limit(limit, 50), **params)
    return {"count": len(data), "items": [shape_asset(a) for a in data]}


@audited()
def get_asset(name: str) -> dict:
    asset_name = guards.check_text(name, "name", max_len=128)
    found = get_client().get_list("asset", limit=1, _filter_name=guards.soar_str(asset_name))
    if not found:
        raise SoarError(f"asset not found: {asset_name}")
    a = found[0]
    out = shape_asset(a)
    out["configuration"] = redact(a.get("configuration") or {})  # explicit, plus central pass
    return {"asset": out}


def register_tools(server, mode: Mode) -> list[str]:
    return register(server, mode,
                    (list_assets, Mode.READONLY, READ),
                    (get_asset, Mode.READONLY, READ))
