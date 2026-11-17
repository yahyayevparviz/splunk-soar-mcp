"""Configuration from environment variables only. One SOAR instance per server process."""
from __future__ import annotations

import os
from functools import lru_cache

from .client import SoarClient, SoarError


def _verify_from_env() -> bool | str:
    raw = os.environ.get("SOAR_VERIFY_SSL", "true").strip()
    if raw.lower() in ("true", "1", "yes"):
        return True
    if raw.lower() in ("false", "0", "no"):
        return False
    return raw  # path to a CA bundle


@lru_cache(maxsize=1)
def get_client() -> SoarClient:
    url = os.environ.get("SOAR_URL", "").strip()
    token = os.environ.get("SOAR_TOKEN", "").strip()
    if not url:
        raise SoarError("SOAR_URL is not set (e.g. https://soar.example.com)")
    if not token:
        raise SoarError("SOAR_TOKEN is not set (automation user ph-auth-token)")
    try:
        timeout = int(os.environ.get("SOAR_TIMEOUT", "30"))
    except ValueError as e:
        raise SoarError("SOAR_TIMEOUT must be an integer (seconds)") from e
    return SoarClient(url=url, token=token, verify=_verify_from_env(), timeout=timeout)


def reset_cache() -> None:
    get_client.cache_clear()
