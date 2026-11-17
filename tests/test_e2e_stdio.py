"""End-to-end: real MCP client <-> real server over stdio <-> fake SOAR over real HTTP.

Covers the whole lifecycle in readonly mode, and the write/execute path in full mode.
No real SOAR needed.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .fake_soar import route, route_post

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "e2e-token"


class Handler(BaseHTTPRequestHandler):
    posts: list = []

    def _auth_ok(self):
        if self.headers.get("ph-auth-token") != TOKEN:
            self._send(401, {"message": "bad token"})
            return False
        return True

    def do_GET(self):  # noqa: N802
        if self._auth_ok():
            u = urlparse(self.path)
            self._send(*route(u.path.removeprefix("/rest/"), dict(parse_qsl(u.query))))

    def do_POST(self):  # noqa: N802
        if self._auth_ok():
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
            path = urlparse(self.path).path.removeprefix("/rest/")
            Handler.posts.append((path, body))
            self._send(*route_post(path, body))

    def _send(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_soar_url():
    Handler.posts = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


def params_for(url: str, audit: Path, **extra) -> StdioServerParameters:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SOAR_")}
    env.update(SOAR_URL=url, SOAR_TOKEN=TOKEN, SOAR_AUDIT_LOG=str(audit),
               SOAR_LOG_LEVEL="WARNING", **extra)
    return StdioServerParameters(command=sys.executable, args=["-m", "soar_analyst_mcp.server"],
                                 cwd=str(ROOT), env=env)


def test_readonly_lifecycle(fake_soar_url, tmp_path):
    audit = tmp_path / "audit.jsonl"

    async def scenario():
        async with stdio_client(params_for(fake_soar_url, audit)) as (read, write):
            async with ClientSession(read, write) as s:
                init = await s.initialize()                                     # 1. handshake
                assert init.server_info.name == "soar-analyst"
                assert "READ-ONLY" in (init.instructions or "")

                names = {t.name for t in (await s.list_tools()).tools}          # 2. menu
                assert len(names) == 16 and "add_note" not in names

                r = await s.call_tool("get_container", {"container_id": 1001})   # 3. call
                assert json.loads(r.content[0].text)["container"]["severity"] == "high"

                r = await s.call_tool("get_asset", {"name": "virustotal"})
                assert "FAKE" not in r.content[0].text and "«redacted»" in r.content[0].text

                cat = await s.read_resource("soar://playbooks/catalog")         # 4. resource
                assert "edr_ip_hash_enrichment" in cat.contents[0].text

                p = await s.get_prompt("triage_case", {"container_id": "1001"})  # 5. prompt
                assert "get_artifacts" in p.messages[0].content.text

                err = await s.call_tool("add_note", {"container_id": 1001,       # 6. not exposed
                                                     "title": "t", "content": "c"})
                assert err.is_error

                err = await s.call_tool("get_container", {"container_id": 5})    # 7. error path
                assert err.is_error and "not found" in err.content[0].text

    asyncio.run(scenario())
    assert Handler.posts == []                       # readonly never POSTed anything
    records = [json.loads(x) for x in audit.read_text().splitlines()]
    assert [r["status"] for r in records] == ["ok", "ok", "error"]
    assert TOKEN not in audit.read_text()


def test_full_mode_write_and_execute(fake_soar_url, tmp_path):
    audit = tmp_path / "audit.jsonl"
    p = params_for(fake_soar_url, audit, SOAR_MCP_MODE="full",
                   SOAR_PLAYBOOK_ALLOWLIST="edr_ip_hash_enrichment",
                   SOAR_ACTION_ALLOWLIST="ip reputation")

    async def scenario():
        async with stdio_client(p) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                assert len((await s.list_tools()).tools) == 24

                r = await s.call_tool("add_note", {"container_id": 1001, "title": "Triage",
                                                   "content": "Likely TP"})
                assert json.loads(r.content[0].text)["note_id"] == 701

                r = await s.call_tool("run_playbook", {"container_id": 1001,
                                                       "playbook_name": "edr_ip_hash_enrichment"})
                assert json.loads(r.content[0].text)["playbook_run_id"] == 88100

                r = await s.call_tool("run_action", {"container_id": 1001,
                                                     "action": "ip reputation",
                                                     "asset_name": "abuseipdb",
                                                     "parameters": [{"ip": "203.0.113.45"}]})
                assert json.loads(r.content[0].text)["action_run_id"] == 5100

                r = await s.call_tool("run_playbook", {"container_id": 1001,
                                                       "playbook_name": "phishing_triage"})
                assert r.is_error and "ALLOWLIST" in r.content[0].text

    asyncio.run(scenario())
    assert [path for path, _ in Handler.posts] == ["note", "playbook_run", "action_run"]
    kinds = [json.loads(x)["kind"] for x in audit.read_text().splitlines()]
    assert kinds == ["write", "execute", "execute", "execute"]
