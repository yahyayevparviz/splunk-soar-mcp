"""Thin Splunk SOAR REST client. The ONLY place that talks HTTP to SOAR.

GET is retried on transient errors. POST is never retried (a retry could run an action twice).
Write tools only reach `post()` when the server mode allows it (see core/modes.py).
"""
from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class SoarError(Exception):
    """Any SOAR API or input failure. The message is safe to show (never contains the token)."""


class SoarClient:
    def __init__(self, url: str, token: str, verify: bool | str = True, timeout: int = 30):
        self.base = url.rstrip("/").removesuffix("/rest") + "/rest"
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"ph-auth-token": token, "Accept": "application/json"})
        self.session.verify = verify
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 502, 503, 504],
                      allowed_methods=["GET"])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    # ---------- transport ----------

    def _request(self, method: str, path: str, params: dict | None = None,
                 body: dict | None = None) -> Any:
        url = f"{self.base}/{path.lstrip('/')}"
        try:
            if method == "GET":
                resp = self.session.get(url, params=params, timeout=self.timeout)
            else:
                resp = self.session.post(url, json=body, timeout=self.timeout)
        except requests.exceptions.SSLError as e:
            raise SoarError("TLS error talking to SOAR (check SOAR_VERIFY_SSL / CA bundle)") from e
        except requests.exceptions.ConnectionError as e:
            raise SoarError(f"cannot connect to SOAR at {self.base}") from e
        except requests.exceptions.Timeout as e:
            raise SoarError(f"SOAR request timed out after {self.timeout}s") from e

        if resp.status_code == 401:
            raise SoarError("SOAR rejected the token (401). Check SOAR_TOKEN.")
        if resp.status_code == 403:
            raise SoarError(f"automation user lacks permission for {method} '{path}' (403)")
        if resp.status_code == 404:
            raise SoarError(f"not found: {path}")
        if resp.status_code >= 400:
            raise SoarError(f"SOAR error {resp.status_code} on {method} {path}: {resp.text[:300]}")
        try:
            return resp.json()
        except ValueError as e:
            raise SoarError(f"SOAR returned non-JSON on {method} {path}") from e

    # ---------- public ----------

    def get(self, path: str, **params: Any) -> Any:
        return self._request("GET", path, params={k: v for k, v in params.items() if v is not None})

    def get_list(self, path: str, limit: int, **params: Any) -> list[dict]:
        """GET a list endpoint, single page (page_size=limit). Returns the 'data' array."""
        body = self.get(path, page_size=limit, page=0, **params)
        if isinstance(body, dict):
            return body.get("data", []) or []
        return body or []

    def post(self, path: str, body: dict) -> Any:
        result = self._request("POST", path, body=body)
        if isinstance(result, dict) and result.get("failed"):
            raise SoarError(f"SOAR refused {path}: {str(result.get('message', ''))[:300]}")
        return result
