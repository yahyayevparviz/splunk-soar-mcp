# soar-analyst-mcp

[![tests](https://github.com/yahyayevparviz/soar-analyst-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/yahyayevparviz/soar-analyst-mcp/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

An [MCP](https://modelcontextprotocol.io) server that gives an AI assistant (Claude Code, Claude
Desktop, any MCP client) the day-to-day toolkit of a **SOC analyst working in Splunk SOAR**:
triage a case, investigate it, debug a failed playbook run, and, only when you allow it,
record findings or launch an allowlisted response.

```
You:     triage case 1001
Claude:  get_container(1001)        -> "Suspicious PowerShell EncodedCommand", high, edr
         get_artifacts(1001)        -> host WS-0001, user jdoe, IP 203.0.113.45, sha256 ...
         get_action_runs(1001)      -> AbuseIPDB score 95, VirusTotal failed (quota)
         search_containers(ioc ...) -> same IP seen in case 990 (closed)
         => Verdict: likely True Positive (medium). Hash not enriched (VT quota).

You:     re-run the hash lookup and write the summary on the case
Claude:  run_action("file reputation", ...)   [full mode, allowlisted]
         add_note(1001, "AI triage", ...)     [standard mode]
```

---

## Safety model

> The **SOAR role of the automation user** is the only boundary that really holds. Anyone
> with the token can bypass this server with `curl`. Everything below is defence in depth.

### Modes: `SOAR_MCP_MODE`

The mode decides which tools are **registered**. A tool that is not registered does not exist
for the model, so the model cannot be talked into calling it.

| Mode | Tools | Adds |
|---|---:|---|
| `readonly` *(default)* | 16 | Every read tool. Cannot change anything. |
| `standard` | 22 | Notes, comments, case status/severity/sensitivity/owner, artifacts, custom-list rows |
| `full` | 24 | `run_playbook`, `run_action`, each limited by an allowlist |

### Allowlists for execution (full mode)

- `SOAR_PLAYBOOK_ALLOWLIST`: exact playbook names `run_playbook` may start.
- `SOAR_ACTION_ALLOWLIST`: app action names `run_action` may start (e.g. `ip reputation`).

**An empty allowlist means nothing can be run, even in full mode.** Keep containment playbooks
and actions (isolate host, block IP, disable user) **out** of the allowlists: those stay a human
decision in the SOAR UI.

### Label scoping: `SOAR_ALLOWED_LABELS`

When set, every container read **and** write is limited to those labels. Listings and
searches are filtered. Fetching a case, its artifacts, notes, action runs or playbook runs
outside the set is refused. A refusal reads exactly like "not found" and never names a label,
so the labels cannot be enumerated. `server_info` reports only how many labels are allowed.
Playbooks, custom lists and assets are instance-wide objects and are not label-scoped.

### Credential redaction

SOAR returns asset configuration with credentials in plaintext. **Every** tool response passes
through one redaction function before it leaves the process. Any field whose *name* looks like
a secret (`password`, `token`, `secret`, `api_key`/`apiKey`, `private_key`, `credential`,
`authorization`, ...) becomes `«redacted»`, at any depth. Matching uses key names, not values,
so hashes and other evidence are never touched. Redaction cannot be turned off.

### Other guards

- **Honest MCP annotations:** reads are `readOnlyHint`. `update_container`, `run_*` and row
  updates are `destructiveHint`, so clients such as Claude Code ask before calling them.
- **No retry on POST:** only GETs are retried, so a flaky network cannot run an action twice.
- **`add_artifact` always sends `run_automation=false`:** an AI-added artifact never triggers
  active playbooks.
- **Input validation:** status/severity/sensitivity/CEF-field allowlists, label regex,
  JSON-quoted filter values, size limits on notes, rows, CEF and action parameters.
  Invalid input is rejected **before** any request is sent.
- **Prompt injection:** artifact, note, list, log and app-result content is returned with an
  `UNTRUSTED DATA` notice. The server instructions and prompts tell the model never to act on
  instructions found inside a case. This reduces the risk but does not remove it. The mode,
  the allowlists and the SOAR role are what limit the damage.
- **Audit:** every call is appended to a JSONL file with time, tool, kind
  (`read`/`write`/`execute`), redacted arguments, status, duration and error.

## Tools

### Read (all modes)

| Tool | Purpose |
|---|---|
| `server_info` | SOAR version, this server's mode, write/execute ability, scoping |
| `list_containers` | Cases by status, severity, label, last N hours |
| `get_container` | One case |
| `search_containers` | Related cases by name, or by exact IOC value in a CEF field |
| `get_artifacts` | IOCs and evidence (CEF) |
| `get_notes` | Analyst notes |
| `get_action_runs` | Actions on a case and their results (enrichment, failures) |
| `get_action_run` | One action run with its results (poll `run_action`) |
| `list_playbooks` | Playbooks by name, label, active |
| `get_playbook_runs` | Playbook runs by case, playbook, status |
| `get_playbook_run` | One playbook run (poll `run_playbook`) |
| `get_playbook_run_log` | Debug log of one run, filterable (`error`, `Traceback`, block name) |
| `list_custom_lists` | Custom lists with row counts |
| `get_custom_list` | Rows of one list (with `row_index`), filterable |
| `list_assets` | Integrations: name, vendor, product (no configuration) |
| `get_asset` | One asset with configuration, credentials redacted |

### Write (`standard` and `full`)

| Tool | Purpose |
|---|---|
| `update_container` | Status, severity, sensitivity, owner. Returns old → new |
| `add_note` | Titled note, e.g. a triage summary |
| `add_comment` | Short activity comment |
| `add_artifact` | New artifact with CEF fields (`run_automation=false`) |
| `append_to_custom_list` | Append one row |
| `update_custom_list_row` | Replace one row by `row_index`. Returns old → new |

### Execute (`full` only, allowlisted)

| Tool | Purpose |
|---|---|
| `run_playbook` | Start an allowlisted playbook on a case. Returns `playbook_run_id` |
| `run_action` | Run an allowlisted app action against an asset. Returns `action_run_id` |

Both are asynchronous. "Started" is not "succeeded": poll `get_playbook_run` /
`get_action_run` and read `get_playbook_run_log`.

Not included on purpose: deleting cases or artifacts, creating cases, user/role
management, system settings, raw POST/DELETE.

### Resource and prompts

- `soar://playbooks/catalog`: compact list of active playbooks to attach as context.
- `triage_case(container_id)`: fixed triage report (summary, IOCs, evidence, history,
  verdict, next steps, ATT&CK).
- `debug_playbook_run(run_id)`: failing block, root cause, fix, prevention.

## Install

Python 3.10+.

```bash
git clone https://github.com/yahyayevparviz/soar-analyst-mcp
cd soar-analyst-mcp
pip install -e .          # or: uv sync
```

## Configure

All configuration is via environment variables (see `.env.example`).

| Variable | Default | Meaning |
|---|---|---|
| `SOAR_URL` | *required* | SOAR base URL, e.g. `https://soar.example.com` (`/rest` added automatically) |
| `SOAR_TOKEN` | *required* | Automation user `ph-auth-token` |
| `SOAR_VERIFY_SSL` | `true` | `true`, `false`, or a path to a CA bundle (preferred over `false`) |
| `SOAR_MCP_MODE` | `readonly` | `readonly`, `standard` or `full` |
| `SOAR_ALLOWED_LABELS` | *(all)* | Comma-separated container labels this server may touch |
| `SOAR_PLAYBOOK_ALLOWLIST` | *(none)* | Playbook names `run_playbook` may start |
| `SOAR_ACTION_ALLOWLIST` | *(none)* | Action names `run_action` may start |
| `SOAR_TIMEOUT` | `30` | Request timeout, seconds |
| `SOAR_AUDIT_LOG` | `~/.soar-analyst-mcp/audit.jsonl` | Audit log path |
| `SOAR_LOG_LEVEL` | `INFO` | Log level (logs go to stderr) |

Check what a configuration exposes without starting a server:

```bash
soar-analyst-mcp --list-tools                 # current SOAR_MCP_MODE
soar-analyst-mcp --list-tools --mode full
```

### Automation user role per mode

Create it under **Administration → User Management → Users → + User** (type **Automation**)
with a role that matches the mode. The SOAR role is what really enforces the limits.

| Mode | Suggested SOAR permissions |
|---|---|
| `readonly` | view: containers, playbooks, custom lists, assets, apps |
| `standard` | + edit: containers, custom lists |
| `full` | + execute: playbooks / actions (consider a separate token for this mode) |

Running several modes for different people? Run **one process per mode, each with its own
automation user**, rather than one powerful token behind application checks.

## Connect a client

**Claude Code**

```bash
claude mcp add soar-analyst \
  -e SOAR_URL=https://soar.example.com \
  -e SOAR_TOKEN=your-token \
  -e SOAR_MCP_MODE=readonly \
  -- soar-analyst-mcp
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "soar-analyst": {
      "command": "soar-analyst-mcp",
      "env": {
        "SOAR_URL": "https://soar.example.com",
        "SOAR_TOKEN": "your-token",
        "SOAR_MCP_MODE": "standard",
        "SOAR_ALLOWED_LABELS": "edr,phishing"
      }
    }
  }
}
```

If the command is not on PATH, use the full path to the virtualenv's `soar-analyst-mcp`.

**Without Claude** (MCP Inspector): `npx @modelcontextprotocol/inspector soar-analyst-mcp`

## Example prompts

- "Show open high-severity cases from the last 24 hours."
- "Triage case 1001." (or pick the `triage_case` prompt)
- "Has 203.0.113.45 appeared in any other case?"
- "Why did playbook run 88001 fail?" (or `debug_playbook_run`)
- "Is jdoe on the vip_users list?"
- *standard:* "Write the triage summary as a note on 1001 and set severity to medium."
- *full:* "Run edr_ip_hash_enrichment on case 1001 and tell me when it finishes."

## Verify against your SOAR version

Tests run against a fake SOAR. These REST details can vary between SOAR versions, so check
them once on your instance (Inspector or curl), ideally on a test label:

| Tool | Request | Check |
|---|---|---|
| `list_containers` | `_filter_create_time__gt="<ISO time>"` | time filter accepted |
| `search_containers` (ioc) | `GET /rest/artifact?_filter_cef__destinationAddress="x"` | CEF JSON lookup |
| `get_action_runs` | `GET /rest/app_run?_filter_container=<id>` | app_run filter by container |
| `get_playbook_run_log` | `GET /rest/playbook_run/<id>/log` | log entries returned |
| `update_container` | `POST /rest/container/<id>` | closing may require a resolution on your instance |
| `append_to_custom_list` | `POST /rest/decided_list/<id>` `{"append_rows": [...]}` | row appended |
| `run_playbook` | `POST /rest/playbook_run` `{"container_id", "playbook_id", "scope", "run": true}` | returns `playbook_run_id` |
| `run_action` | `POST /rest/action_run` with `targets[].assets/parameters/app_id` | returns `action_run_id` |

If one differs, the change is local to the matching file in `soar_analyst_mcp/tools/`.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

115 tests, no live SOAR needed:
- **unit:** config, modes, guards, shaping, redaction, client errors
- **tools:** every read, write and execute tool against an in-process fake SOAR, checking the
  exact payloads sent and that invalid input sends nothing
- **scoping:** reads and writes outside `SOAR_ALLOWED_LABELS` refused, "denied" looks like "missing"
- **server:** tool sets and annotations per mode
- **end-to-end:** a real MCP client drives the real server over stdio against a fake SOAR over
  HTTP, in readonly mode (nothing is POSTed) and in full mode (note, playbook, action)

Layout:

```
soar_analyst_mcp/
  server.py              builds the server for the mode, CLI (--list-tools, --mode)
  core/
    config.py            env -> SoarClient
    client.py            the only HTTP code: GET (retried) and POST (never retried)
    modes.py             readonly / standard / full, allowlists
    scope.py             SOAR_ALLOWED_LABELS enforcement
    redaction.py         credential redaction by key name
    guards.py            input validation and filter quoting
    shaping.py           field selection, truncation, untrusted marking
    audit.py             JSONL audit, central redaction, SoarError -> ToolError
  tools/                 system, cases, evidence, playbooks, lists, assets, run
  resources/catalog.py   soar://playbooks/catalog
  prompts/templates.py   triage_case, debug_playbook_run
  descriptions/tools.yaml  tool descriptions the model reads
```

Adding a tool: write it in the right `tools/` module with `@audited("read"|"write"|"execute")`,
add its description to `descriptions/tools.yaml`, and register it in that module's
`register_tools` under the lowest mode that should have it, with honest annotations. Raise
`SoarError` for anything the caller can act on: its message reaches the model.

## Roadmap

- Workbook / phase progress per case
- Elicitation-based confirmation for execute tools (on clients that support it)
- Streamable HTTP transport with authentication for shared deployments

## License

MIT. Not affiliated with or endorsed by Splunk Inc. "Splunk" and "Splunk SOAR" are trademarks
of Splunk Inc.
