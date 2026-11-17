"""server_info: SOAR version + this server's mode and limits. Call it first."""
from __future__ import annotations

from .. import __version__
from ..core import scope
from ..core.audit import audited
from ..core.client import SoarError
from ..core.config import get_client
from ..core.modes import Mode, action_allowlist, current_mode, playbook_allowlist
from ._common import READ, register


@audited()
def server_info() -> dict:
    try:
        soar_version = get_client().get("version").get("version")
    except SoarError as e:
        soar_version = f"unavailable ({e})"
    labels = scope.allowed_labels()
    mode = current_mode()
    return {
        "server": "soar-analyst-mcp", "server_version": __version__,
        "soar_version": soar_version,
        "mode": mode.name.lower(),
        "can_write": mode >= Mode.STANDARD,
        "can_execute": mode >= Mode.FULL,
        "label_scoped": labels is not None,
        "allowed_label_count": len(labels) if labels else 0,   # count only: the list is sensitive
        "runnable_playbooks": len(playbook_allowlist()) if mode >= Mode.FULL else 0,
        "runnable_actions": len(action_allowlist()) if mode >= Mode.FULL else 0,
    }


def register_tools(server, mode: Mode) -> list[str]:
    return register(server, mode, (server_info, Mode.READONLY, READ))
