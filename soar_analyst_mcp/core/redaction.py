"""Credential redaction applied to EVERY tool response before it leaves the process.

SOAR returns asset configuration verbatim, credentials included. Redaction is keyed on the
field NAME (not the value), so hashes and other legit data are untouched.
"""
from __future__ import annotations

import re
from typing import Any

REDACTED = "«redacted»"
_SENSITIVE = ("password", "passwd", "secret", "token", "apikey", "privatekey",
              "credential", "authorization", "passphrase", "certificatekey")
_NORMALIZE = re.compile(r"[^a-z0-9]")


def is_sensitive_key(key: str) -> bool:
    k = _NORMALIZE.sub("", str(key).lower())
    return any(s in k for s in _SENSITIVE)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (REDACTED if is_sensitive_key(k) and v not in (None, "") else redact(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
