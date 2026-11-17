"""Tool registration by mode, with honest MCP annotations."""
from __future__ import annotations

from mcp.types import ToolAnnotations

from ..core.modes import Mode
from ..descriptions import describe

READ = ToolAnnotations(read_only_hint=True, destructive_hint=False,
                       idempotent_hint=True, open_world_hint=False)
WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False,
                        idempotent_hint=False, open_world_hint=False)
UPDATE = ToolAnnotations(read_only_hint=False, destructive_hint=True,
                         idempotent_hint=True, open_world_hint=False)
EXECUTE = ToolAnnotations(read_only_hint=False, destructive_hint=True,
                          idempotent_hint=False, open_world_hint=True)


def register(server, mode: Mode, *entries: tuple) -> list[str]:
    """entries: (fn, min_mode, annotations). Registers only tools allowed in `mode`."""
    registered = []
    for fn, min_mode, ann in entries:
        if mode >= min_mode:
            server.add_tool(fn, name=fn.__name__, description=describe(fn.__name__),
                            annotations=ann)
            registered.append(fn.__name__)
    return registered
