"""Container label scoping (SOAR_ALLOWED_LABELS).

When set, the server only reads or writes containers whose label is in the list. Refusals use
the same message as 'not found' and never name the label, so callers cannot enumerate labels.
Playbooks, custom lists and assets are instance-wide objects and are NOT label-scoped.
"""
from __future__ import annotations

import os

from .client import SoarClient, SoarError


def allowed_labels() -> set[str] | None:
    raw = {x.strip() for x in os.environ.get("SOAR_ALLOWED_LABELS", "").split(",") if x.strip()}
    return raw or None


def is_allowed(container: dict) -> bool:
    labels = allowed_labels()
    return labels is None or container.get("label") in labels


def not_accessible(cid: int) -> SoarError:
    return SoarError(f"container {cid} not found or not accessible")


def require_container(c: SoarClient, cid: int) -> dict:
    """Fetch a container and enforce the label allowlist. Returns the raw container."""
    try:
        container = c.get(f"container/{cid}")
    except SoarError as e:
        if "not found" in str(e):
            raise not_accessible(cid) from e
        raise
    if not is_allowed(container):
        raise not_accessible(cid)
    return container


def check_container_id(c: SoarClient, cid: int) -> None:
    """Cheap path: only fetch the container when an allowlist is configured."""
    if allowed_labels() is not None:
        require_container(c, cid)


def filter_containers(items: list[dict]) -> list[dict]:
    labels = allowed_labels()
    if labels is None:
        return items
    return [x for x in items if x.get("label") in labels]
