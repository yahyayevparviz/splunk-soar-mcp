"""Server modes. The mode decides which tools are REGISTERED, not just which ones refuse.

readonly  every read tool. Cannot change anything.              (default)
standard  + notes, comments, container status/severity/owner, artifacts, custom-list rows
full      + run playbooks and app actions (each limited by an allowlist)

The SOAR role of the automation user is the real security boundary; modes are defence in depth.
"""
from __future__ import annotations

import os
from enum import IntEnum

from .client import SoarError


class Mode(IntEnum):
    READONLY = 0
    STANDARD = 1
    FULL = 2


def current_mode() -> Mode:
    raw = os.environ.get("SOAR_MCP_MODE", "readonly").strip().lower()
    try:
        return Mode[raw.upper()]
    except KeyError as e:
        raise SoarError("SOAR_MCP_MODE must be one of: readonly, standard, full") from e


def _csv_env(name: str) -> set[str]:
    return {x.strip() for x in os.environ.get(name, "").split(",") if x.strip()}


def playbook_allowlist() -> set[str]:
    """Playbook names run_playbook may start. Empty = nothing may be run."""
    return _csv_env("SOAR_PLAYBOOK_ALLOWLIST")


def action_allowlist() -> set[str]:
    """App action names run_action may start (e.g. 'ip reputation'). Empty = nothing."""
    return {a.lower() for a in _csv_env("SOAR_ACTION_ALLOWLIST")}
