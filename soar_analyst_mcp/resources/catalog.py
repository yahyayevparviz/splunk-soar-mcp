"""Resource: soar://playbooks/catalog — compact list of active playbooks for context."""
from __future__ import annotations

import json

from ..core import guards
from ..core.config import get_client
from ..core.shaping import shape_playbook

CATALOG_FIELDS = ("id", "name", "description", "labels", "tags", "category")


def playbook_catalog() -> str:
    data = get_client().get_list("playbook", limit=guards.MAX_LIMIT, sort="name", order="asc",
                                 _filter_active="true")
    items = [{k: v for k, v in shape_playbook(p).items() if k in CATALOG_FIELDS} for p in data]
    return json.dumps({"count": len(items), "playbooks": items}, ensure_ascii=False, indent=2)


def register(server) -> None:
    server.resource(
        "soar://playbooks/catalog",
        name="playbook_catalog",
        description="Active SOAR playbooks (id, name, description, labels, tags, category). "
                    "Attach as context when choosing or discussing playbooks.",
        mime_type="application/json",
    )(playbook_catalog)
