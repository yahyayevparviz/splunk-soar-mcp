"""Input validation and safety rules applied before any SOAR call."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from .client import SoarError

MAX_LIMIT = 200

VALID_STATUS = {"new", "open", "closed"}
VALID_SEVERITY = {"low", "medium", "high"}

# CEF keys allowed for IOC search (they become part of a URL parameter name)
ALLOWED_CEF_FIELDS = {
    "sourceAddress", "destinationAddress", "sourceHostName", "destinationHostName",
    "sourceUserName", "destinationUserName", "fileHash", "fileHashMd5", "fileHashSha1",
    "fileHashSha256", "fileName", "requestURL", "destinationDnsDomain", "fromEmail", "toEmail",
}

_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_\-\.]{1,64}$")
_SAFE_CEF_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def clamp_limit(limit: int, default: int = 20) -> int:
    try:
        n = int(limit)
    except (TypeError, ValueError):
        return default
    return max(1, min(n, MAX_LIMIT))


def positive_id(value: int, name: str = "id") -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as e:
        raise SoarError(f"{name} must be an integer") from e
    if n <= 0:
        raise SoarError(f"{name} must be > 0")
    return n


def check_status(status: str | None) -> str | None:
    if not status:
        return None
    s = status.lower().strip()
    if s not in VALID_STATUS:
        raise SoarError(f"status must be one of {sorted(VALID_STATUS)}")
    return s


def check_severity(severity: str | None) -> str | None:
    if not severity:
        return None
    s = severity.lower().strip()
    if s not in VALID_SEVERITY:
        raise SoarError(f"severity must be one of {sorted(VALID_SEVERITY)}")
    return s


def check_label(label: str | None) -> str | None:
    if not label:
        return None
    if not _SAFE_LABEL.match(label):
        raise SoarError("label contains invalid characters")
    return label


def check_cef_field(field: str) -> str:
    if not _SAFE_CEF_KEY.match(field or ""):
        raise SoarError("invalid cef field name")
    if field not in ALLOWED_CEF_FIELDS:
        raise SoarError(f"cef field not allowed. Use one of: {', '.join(sorted(ALLOWED_CEF_FIELDS))}")
    return field


def check_text(q: str | None, name: str = "query", max_len: int = 256,
               required: bool = True) -> str | None:
    q = (q or "").strip()
    if not q:
        if required:
            raise SoarError(f"{name} must not be empty")
        return None
    if len(q) > max_len:
        raise SoarError(f"{name} too long (max {max_len})")
    return q


def soar_str(value: str) -> str:
    """Quote a string for SOAR REST _filter_ params (they expect JSON-quoted strings)."""
    return json.dumps(value)


def since_iso(hours: int | None) -> str | None:
    if not hours:
        return None
    h = max(1, min(int(hours), 24 * 90))  # cap at 90 days
    t = datetime.now(timezone.utc) - timedelta(hours=h)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000000Z")
