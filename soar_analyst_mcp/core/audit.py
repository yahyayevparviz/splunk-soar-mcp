"""Append-only JSONL audit of every tool call, central redaction, and clean error handling."""
from __future__ import annotations

import functools
import inspect
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from mcp.server.mcpserver.exceptions import ToolError

from .client import SoarError
from .redaction import redact

log = logging.getLogger(__name__)
DEFAULT_LOG = Path.home() / ".soar-analyst-mcp" / "audit.jsonl"
MAX_ARG_LEN = 500


def audit_path() -> Path:
    return Path(os.environ.get("SOAR_AUDIT_LOG", str(DEFAULT_LOG))).expanduser()


def _safe_args(args: dict) -> dict:
    out = {}
    for k, v in redact(args).items():
        s = json.dumps(v, default=str, ensure_ascii=False)
        out[k] = v if len(s) <= MAX_ARG_LEN else s[:MAX_ARG_LEN] + "...[truncated]"
    return out


def write_record(record: dict) -> None:
    path = audit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError as e:  # audit must never break the tool
        log.error("audit write failed: %s", e)


def audited(kind: str = "read") -> Callable:
    """Decorator. kind: 'read' | 'write' | 'execute' (recorded in the audit log).

    - every response is passed through redact() before it reaches the model
    - SoarError becomes a ToolError (the model sees is_error=True with a clean message)
    """
    def deco(fn: Callable) -> Callable:
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            record = {"ts": datetime.now(timezone.utc).isoformat(), "tool": fn.__name__,
                      "kind": kind,
                      "args": _safe_args(dict(sig.bind_partial(*args, **kwargs).arguments))}
            start = time.monotonic()
            try:
                result = redact(fn(*args, **kwargs))
                record["status"] = "ok"
                return result
            except SoarError as e:
                record["status"] = "error"
                record["error"] = str(e)
                raise ToolError(str(e)) from e
            except Exception as e:
                record["status"] = "error"
                record["error"] = f"{e.__class__.__name__}: {e}"
                log.exception("unexpected error in %s", fn.__name__)
                raise ToolError(f"internal error in {fn.__name__}: {e.__class__.__name__}") from e
            finally:
                record["duration_ms"] = int((time.monotonic() - start) * 1000)
                write_record(record)

        wrapper.audit_kind = kind  # type: ignore[attr-defined]
        return wrapper

    return deco
