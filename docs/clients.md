# Connect a client to lookfirst

lookfirst sits between your MCP client and the real server. The client talks to lookfirst; lookfirst talks to the upstream(s)
listed in `lookfirst.yaml`. Three ready-made configurations – copy, adjust the two paths, restart the client.

Common part, once (5 minutes):

```sh
pipx install git+https://github.com/Aethelgard-Systems/lookfirst   # or: pip install git+https://…
mkdir ~/lookfirst && cd ~/lookfirst
curl -O https://raw.githubusercontent.com/Aethelgard-Systems/lookfirst/main/examples/lookfirst.yaml   # edit upstreams + rules
lookfirst keygen --config lookfirst.yaml                    # Ed25519 signing key, 0600, once
lookfirst serve --config lookfirst.yaml --transport http --port 8470   # only for HTTP clients; stdio clients start it themselves
```

The approval page is at http://127.0.0.1:8477/ when `confirm.web` is set. Tip: `lookfirst demo` first – no client needed.

## 1. Claude Desktop (stdio)

Claude Desktop → menu **Settings… → Developer → Edit Config** opens `claude_desktop_config.json`
(macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json`;
source: modelcontextprotocol.io "Connect to local MCP servers", 2026-10-18). Add:

```json
{
  "mcpServers": {
    "lookfirst": {
      "command": "lookfirst",
      "args": ["serve", "--config", "/Users/you/lookfirst/lookfirst.yaml"]
    }
  }
}
```

Use absolute paths; if `lookfirst` is not on the PATH the app sees, put the full path to the `lookfirst` executable
(`pipx` installs to `~/.local/bin/lookfirst`, Windows `%USERPROFILE%\.local\bin\lookfirst.exe`) into `command`.
Restart Claude Desktop completely. One tester report ([#34](https://github.com/Aethelgard-Systems/lookfirst/issues/34), v0.2.0, Claude Desktop 6.28899.6 on macOS, stdio) saw the approval on the localhost web page and no in-chat lookfirst form; see the note below the observation table, including the fixed-port limit with several processes. This is a single observation, not a compatibility promise; other builds and Windows are untested. Do not rely on in-chat elicitation. Keep `confirm.web` configured so approvals land on the page (`confirm.elicitation: true` only adds the in-chat form if the client offers it).

## 2. Claude Code (stdio or HTTP)

Source: code.claude.com/docs/en/mcp (2026-10-18). stdio, user scope (available in all projects):

```sh
claude mcp add --transport stdio --scope user lookfirst -- lookfirst serve --config /Users/you/lookfirst/lookfirst.yaml
```

or HTTP against a running `lookfirst serve --transport http --port 8470`:

```sh
claude mcp add --transport http lookfirst http://127.0.0.1:8470/mcp
```

Project scope writes `.mcp.json` next to the repo (shared with the team):

```json
{
  "mcpServers": {
    "lookfirst": {
      "type": "http",
      "url": "http://127.0.0.1:8470/mcp"
    }
  }
}
```

`claude mcp list` shows the connection. Everything after `--` is passed to lookfirst unchanged.

## 3. Google Antigravity (HTTP; second client)

Source: antigravity.google/docs/cli/gcli-migration (2026-10-18): MCP servers live in `~/.gemini/config/mcp_config.json`
(global) or `.agents/mcp_config.json` (workspace); remote servers use the key `serverUrl`.

```json
{
  "mcpServers": {
    "lookfirst": {
      "serverUrl": "http://127.0.0.1:8470/mcp"
    }
  }
}
```

Start `lookfirst serve --config lookfirst.yaml --transport http --port 8470` before the agent. Whether Antigravity
answers MCP elicitation is UNKNOWN (not stated in its docs) – keep `confirm.web` configured so approvals land on the page.

## Observed on a test machine (2026-11-04, Linux, local wheel, demo bank)

| Client (version) | In-chat elicitation | Web page (8477) | Webhook |
|---|---|---|---|
| Claude Code CLI 2.1.316 | not offered in our test (capability handshake reported `false`) | works | works |
| Gemini CLI 0.66.0 | not offered in our test | works | works |
| Antigravity 44.5.1 (HTTP) | not seen in our test | works | works |
| Claude Desktop 6.28899.6, macOS 26.7.1, stdio – tester report #34, not run by us | not observed in that run | worked (localhost page) | not reported |

**Single report, one configuration (issue #34, tester-reported, not verified by us):** lookfirst v0.2.0 (`7eef470`), Claude Desktop 6.28899.6, macOS 26.7.1, Python 3.14.3, MCP SDK 2.3.0, stdio, demo bank with a 45-second decision timeout.
Claude Desktop first showed its own "Allow once" tool permission; afterwards lookfirst's approval appeared on the localhost page. No in-chat lookfirst form was observed (webhook not reported).

| Case (synthetic demo bank) | Reported result |
|---|---|
| Approve 10 EUR on localhost | transfer executed, read-back `ok` |
| Deny 20 EUR on localhost | `Not approved`, no transfer |
| 30 EUR left pending | `Not approved (timeout)` after 45 s, no transfer |

The tester reports 18 audit entries verified with zero problems. This is one tester's report for exactly this build and configuration, not a general compatibility or security claim.

**Known operating limit – several stdio instances:** `confirm.web.port` is a fixed value (default 8477). If a client starts more than one lookfirst process, the extra processes cannot bind that port and exit (reported: `[Errno 48] address already in use`; in code, uvicorn stops the process with a startup failure when the bind fails). The tester's rerun used a small launcher giving each process its own loopback port and its own audit file. Until this is documented as supported, run one lookfirst process per web port and per audit file. Whether several processes may safely share one audit file is **not established** (the file is guarded by an in-process lock only, `lookfirst/audit.py`).

Single observations by one tester, not a compatibility promise: client versions change, and Claude Code releases in particular may add elicitation. Treat the **web page as the channel that works everywhere** and re-check your client version before relying on the in-chat form.

## Who approved?

Every decision is logged as `channel:actor`:

| Channel | `by` in the log | Where the actor comes from | Trust |
|---|---|---|---|
| Elicitation | `elicitation:<client name>` | the MCP client's `clientInfo.name` (e.g. `claude-ai`) | identifies the **client**, not the person |
| Web page | `web:<name>` | `confirm.web.identity_header` (e.g. `X-Forwarded-User`) when the page runs behind an authenticating reverse proxy – **verified**; otherwise the name typed on the page – **self-declared** (`note: self-declared`) | verified / self-declared |
| Webhook | `webhook:<actor>` | `actor` in the decision body | as trustworthy as the webhook system |

For audits (EU AI Act Art. 12(3)(d), MaRisk AT 4.3.1 – see `docs/compliance-mapping.md`) use the reverse-proxy header: it is the only
variant where lookfirst itself did not have to trust the browser.

```yaml
confirm:
  web: {host: 127.0.0.1, port: 8477, identity_header: X-Forwarded-User}
```
