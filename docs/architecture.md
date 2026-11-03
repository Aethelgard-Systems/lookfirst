# lookfirst – architecture (V1)

```
                 ┌──────────────────────────────────────────────────────────────────┐
  MCP client     │ lookfirst (lookfirst/)                                        │     upstream MCP servers
  (Claude, …)    │                                                                  │
   tools/list ───┼─▶ upstream.py  merge tool lists (prefix "<up>__" if >1) ─────────┼──▶ stdio subprocess
   tools/call ───┼─▶ proxy.Gate.on_call_tool                                        │    or Streamable HTTP
                 │     1. rules.decide()  ← config.yaml + tool annotations          │
                 │     2. allow  → forward, log allow/result                        │
                 │        deny   → log, error result (never executed)               │
                 │        confirm:                                                  │
                 │          preview.build()  → redact hook → confirm.Confirmer.ask()│
                 │             ├ elicitation (client capability)                    │
                 │             ├ web.py  (local page, /approve /deny)      ◀──────── human
                 │             └ webhook (POST preview) … /decision/<id>  ◀──────── external system
                 │          approved → forward → readback.check() via a read tool ──┼──▶
                 │          every step → audit.AuditLog.append()                    │
                 └──────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                 audit.jsonl  (seq, ts, event, call_id, tool, args_sha256, summary, decision, by,
                               result_sha256, readback, note, prev, hash, sig) + audit.jsonl.head
                 verify-log: recompute hash, check Ed25519 sig, chain, sequence, head
```

## Modules
| Module | Responsibility |
|---|---|
| `config.py` | YAML → `Config` (upstreams, default actions, per-tool rules incl. summary template and read-back, confirmation channels, paths). Validates strictly. |
| `rules.py` | `decide()` → allow/confirm/deny with reason; defaults from `readOnlyHint`/`destructiveHint`. |
| `preview.py` | Canonical JSON, argument hash, human summary (template or generic). |
| `confirm.py` | `PendingRegistry` (open questions) + `Confirmer` (elicitation → web → webhook, one timeout, timeout = deny). |
| `web.py` | Starlette page: list, approve/deny (CSRF token per process), `/open`, `/decision/<id>` (webhook token). |
| `readback.py` | Resolve placeholders, call read tool, compare → ok / unklar / fehlgeschlagen. |
| `audit.py` | Key generation (Ed25519), append with chain + signature + head file, `verify()` with line-numbered problems. |
| `redact.py` | Hook loader; identity by default. |
| `upstream.py` | Connect stdio/HTTP upstreams, cache tools, name mapping, `from_sessions()` for embedding/tests. |
| `proxy.py` | `Gate` = the MCP server (lowlevel `Server` from the official SDK, `mcp>=2.2`). |
| `cli.py` | `serve`, `keygen`, `verify-log`, `demo`. |

## Design choices
- **Official SDK, lowlevel API**: no FastMCP magic, so the proxy forwards tool schemas verbatim and can speak to the client session (elicitation).
- **Stateless decisions, stateful log**: nothing is kept in memory beyond open confirmations; the log is the memory.
- **Timeout = deny, unknown = confirm, read-back mandatory for a "done"**: the three defaults that make the gate safe when misconfigured.
- **No business logic**: lookfirst knows nothing about banks, mails or tickets. Everything domain-specific lives in `lookfirst.yaml`.
- **Standalone**: no imports from other projects; copy `products/lookfirst/` into its own repo without changes.

## Known limits (V1)
- The web page and webhook endpoint share one process with the proxy; for HTTP transport they are a second port, not behind auth other than the CSRF/webhook token. Put it behind your own reverse proxy/auth.
- The log cannot prove entries that were never written (e.g. a bypassed gate). Deploy so the client can only reach the upstreams through lookfirst.
- Summaries are logged in clear text; use the redaction hook (stub in V1) if arguments carry private data.
- `tools/list_changed` from upstreams is not propagated; restart to pick up new tools.
- Resources/prompts are not proxied (tools only).

## Fit for AETHELGARD (first customer)
- Kanal (#286) `privat_vorschlagen`, STEVE "kündigen"-type actions: wrap the Kanal's MCP endpoint as an upstream, `confirm` for writes.
- Webhook → "Braucht dich" (S10): preview as one approval card, decision back to `/decision/<id>`.
- Audit log alongside the Kanal audit; same evidence classes.
