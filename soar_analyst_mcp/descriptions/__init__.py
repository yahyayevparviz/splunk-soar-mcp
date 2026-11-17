"""Load tool descriptions from tools.yaml."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_PATH = Path(__file__).with_name("tools.yaml")


@lru_cache(maxsize=1)
def _all() -> dict[str, str]:
    return yaml.safe_load(_PATH.read_text(encoding="utf-8")) or {}


def describe(tool_name: str) -> str:
    desc = _all().get(tool_name)
    if not desc:
        raise KeyError(f"no description for tool '{tool_name}' in {_PATH.name}")
    return desc.strip()
