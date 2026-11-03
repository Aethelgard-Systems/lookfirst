# Connect a client to Torwächter (v1.1)

Torwächter sits between your MCP client and the real server. The client talks to Torwächter; Torwächter talks to the upstream(s)
listed in `torwaechter.yaml`. Three ready-made configurations – copy, adjust the two paths, restart the client.

Common part, once (5 minutes):

```sh
pipx install git+https://github.com/<org>/<repo>.git#subdirectory=products/torwaechter   # or: pip install <path-to>/products/torwaechter
mkdir ~/torwaechter && cd ~/torwaechter
cp <repo>/products/torwaechter/examples/torwaechter.yaml .      # edit upstreams + rules
torwaechter keygen --config torwaechter.yaml                    # Ed25519 signing key, 0600, once
torwaechter serve --config torwaechter.yaml --transport http --port 8470   # only for HTTP clients; stdio clients start it themselves
```

The approval page is at http://127.0.0.1:8477/ when `confirm.web` is set. Tip: `torwaechter demo` first – no client needed.

## 1. Claude Desktop (stdio)

Claude Desktop → menu **Settings… → Developer → Edit Config** opens `claude_desktop_config.json`
(macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json`;
source: modelcontextprotocol.io "Connect to local MCP servers", 2026-10-18). Add:

```json
{
  "mcpServers": {
    "torwaechter": {
      "command": "torwaechter",
      "args": ["serve", "--config", "/Users/you/torwaechter/torwaechter.yaml"]
    }
  }
}
```

Use absolute paths; if `torwaechter` is not on the PATH the app sees, put the full path to the `torwaechter` executable
(`pipx` installs to `~/.local/bin/torwaechter`, Windows `%USERPROFILE%\.local\bin\torwaechter.exe`) into `command`.
Restart Claude Desktop completely. Claude Desktop supports MCP elicitation, so approvals appear **inside the chat**
(`confirm.elicitation: true`); the web page is the fallback.

## 2. Claude Code (stdio or HTTP)

Source: code.claude.com/docs/en/mcp (2026-10-18). stdio, user scope (available in all projects):

```sh
claude mcp add --transport stdio --scope user torwaechter -- torwaechter serve --config /Users/you/torwaechter/torwaechter.yaml
```

or HTTP against a running `torwaechter serve --transport http --port 8470`:

```sh
claude mcp add --transport http torwaechter http://127.0.0.1:8470/mcp
```

Project scope writes `.mcp.json` next to the repo (shared with the team):

```json
{
  "mcpServers": {
    "torwaechter": {
      "type": "http",
      "url": "http://127.0.0.1:8470/mcp"
    }
  }
}
```

`claude mcp list` shows the connection. Everything after `--` is passed to Torwächter unchanged.

## 3. Google Antigravity (HTTP; second client)

Source: antigravity.google/docs/cli/gcli-migration (2026-10-18): MCP servers live in `~/.gemini/config/mcp_config.json`
(global) or `.agents/mcp_config.json` (workspace); remote servers use the key `serverUrl`.

```json
{
  "mcpServers": {
    "torwaechter": {
      "serverUrl": "http://127.0.0.1:8470/mcp"
    }
  }
}
```

Start `torwaechter serve --config torwaechter.yaml --transport http --port 8470` before the agent. Whether Antigravity
answers MCP elicitation is UNKNOWN (not stated in its docs) – keep `confirm.web` configured so approvals land on the page.

## Who approved? (v1.1)

Every decision is logged as `channel:actor`:

| Channel | `by` in the log | Where the actor comes from | Trust |
|---|---|---|---|
| Elicitation | `elicitation:<client name>` | the MCP client's `clientInfo.name` (e.g. `claude-ai`) | identifies the **client**, not the person |
| Web page | `web:<name>` | `confirm.web.identity_header` (e.g. `X-Forwarded-User`) when the page runs behind an authenticating reverse proxy – **verified**; otherwise the name typed on the page – **self-declared** (`note: self-declared`) | verified / self-declared |
| Webhook | `webhook:<actor>` | `actor` in the decision body | as trustworthy as the webhook system |

For audits (EU AI Act Art. 12(3)(d), MaRisk AT 4.3.1 – see `docs/compliance-mapping.md`) use the reverse-proxy header: it is the only
variant where Torwächter itself did not have to trust the browser.

```yaml
confirm:
  web: {host: 127.0.0.1, port: 8477, identity_header: X-Forwarded-User}
```
