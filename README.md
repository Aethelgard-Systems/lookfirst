# 🛡️ lookfirst (formerly "Torwächter")

**A gatekeeper between AI agents and the tools they use.** Every *writing* action (transfer money, delete a record, send a
mail, close a ticket) goes through: **preview → a human confirms → execution → read-back → tamper-evident audit log.**
Reading actions pass through untouched.

lookfirst is an [MCP](https://modelcontextprotocol.io) proxy: put it between any MCP client (Claude, ChatGPT, Cursor, your own
agent) and any MCP servers. Nothing changes on either side.

```
AI client ──MCP──▶ lookfirst ──MCP──▶ upstream servers (bank, CRM, mail, files, …)
                      │
                      ├─ rules.yaml: allow | confirm | deny per tool (defaults from tool annotations)
                      ├─ confirmation: in-client (MCP elicitation) · local web page · webhook
                      ├─ read-back: re-read after writing → ok | unklar | fehlgeschlagen
                      └─ audit log: JSONL, hash chain, Ed25519-signed  →  `lookfirst verify-log`
```

*Deutsche Fassung: [README.de.md](README.de.md). Architecture: [docs/architecture.md](docs/architecture.md).*

## Status
0.2.0 (pre-1.0). Works end-to-end offline (demo below); tested with Claude Code, Gemini CLI and Antigravity (see `docs/clients.md`). **Not a production release:** real production use needs your own targeted tests and sign-off. There is no long-term field experience yet. **License:** Apache-2.0 (see `LICENSE`). The license grants rights to use the code; it makes no promise of fitness or security. Known limits are listed below.

Gate readiness can be measured at any time: `lookfirst pilot-status --config lookfirst.yaml`.

## Quick start (60 seconds, offline)

```bash
pip install -e .            # or: uvx --from . lookfirst demo
lookfirst demo
```

The demo starts a fake bank MCP server, puts lookfirst in front of it and plays an agent: a balance check passes through,
a transfer stops for your `y/N`, the result is read back and verified, then one log line is edited and `verify-log`
catches it. See [demo/VIDEO.md](demo/VIDEO.md) for the screen-recording script.

## Use it with a real client (5 minutes)

1. Install once: `pipx install <path-or-git-url>` (or `pip install`). Gives you the `lookfirst` command. Windows: pure Python, `py -m pip install <path-or-git-url>` should work, but we have **not tested it on Windows yet**.
2. Copy [examples/lookfirst.yaml](examples/lookfirst.yaml) next to where the log should live; set upstreams, rules, confirmation channels.
3. `lookfirst keygen --config lookfirst.yaml` – creates the Ed25519 signing key (0600) once.
4. Connect a client – ready-made snippets for **Claude Desktop**, **Claude Code** and **Antigravity** in [docs/clients.md](docs/clients.md)
   (stdio: the client starts `lookfirst serve --config …`; HTTP: run `lookfirst serve --transport http --port 8470` yourself).
5. Any time: `lookfirst verify-log --config lookfirst.yaml`.

**Who approved (v1.1):** every decision is logged as `channel:actor` – `web:<user>` from an authenticating reverse-proxy header
(`confirm.web.identity_header`) or a self-declared name on the page, `webhook:<actor>` from the decision body, `elicitation:<client>`
from the MCP client's name. Details and trust levels: [docs/clients.md](docs/clients.md#who-approved-v11).

## How a call is decided

| Situation | Default | Why |
|---|---|---|
| tool declares `readOnlyHint: true` | **allow** | reading is harmless |
| tool declares `destructiveHint: true` | **confirm** | a human decides |
| tool declares `destructiveHint: false` (a write, but reversible) | **confirm** | still a write |
| no annotations | **confirm** | unknown = ask |
| explicit rule `rules.tools.<name>.action` | that | rules beat annotations; `deny` never executes |

Confirmation channels, tried in order: **(1)** MCP elicitation inside the client, if the client supports it and the arguments
fit in full (argument JSON ≤ 800 characters – longer previews are never cut; they go to the web page or webhook, without one the
call is denied); **(2)** the local
web page (`confirm.web`); **(3)** a webhook (`confirm.webhook`) that receives the preview and answers on
`POST /decision/<id>` with a **per-call token** (HMAC of the call id – a leaked token opens nothing else; webhook URLs must be
`https://`) and the `args_sha256` from the preview – missing or different → 403, so a decision applies only to the exact
arguments shown; the web page binds its buttons the same way). **A webhook receiver must show `tool_display`, `summary` and `arguments_display` to the human – never the raw `tool` or `arguments`:** the display fields are escaped (invisible, bidi and look-alike-space characters appear as `\uXXXX`), the raw fields are not, and a receiver that shows them can be fooled – this is where a system like AETHELGARD's "Braucht dich" plugs in. Every channel shares one timeout; **a timeout
is a denial**.

Limits to know: **(a)** elicitation is answered by the *client*. An autonomous client that auto-answers elicitation would approve
its own calls – for such clients set `confirm.elicitation: false` so the decision must come from the web page or the webhook.
**(b)** The web page trusts only requests whose `Host` is this server and that are not cross-site (`Origin`/`Sec-Fetch-Site`),
plus a per-process CSRF token; it has no login and is meant for 127.0.0.1 only. **(c)** With `--transport http` the gate does
not know *who* calls. Without `http.token_file` it only starts on loopback (and warns: every local process can call tools); with
it, each request needs `Authorization: Bearer <token>`, else 401. Off loopback the token is required. The bearer token is
authentication, **not transport encryption**: beyond the local trusted host, put TLS or another protected transport (reverse
proxy with TLS, SSH tunnel, VPN) in front of the gate. What the gate does **not**
protect against (other routes to the same system, same-user access to keys and rules): [docs/threat-model.md](docs/threat-model.md).

Read-back (`rules.tools.<name>.readback`): after a confirmed write, lookfirst calls a *reading* tool and compares expected
fields (`$args.x`, `$result.y` placeholders). The result is `ok`, `unklar` (could not verify) or `fehlgeschlagen` (mismatch) and
is returned to the client in `structuredContent.lookfirst` – a write is never reported as "done" without it.


## Known limits (independent counter-check, 2026-11-03)

These are documented limits, not bugs we hide. The ids come from the counter-check and differ from the B-numbers in `docs/threat-model.md`. Each has a test that pins the current behaviour or marks the wanted one as an expected failure.

| Id | Limit | What to do |
|---|---|---|
| B4.1 | If the audit log is truncated at the end **and** the `.head` sidecar file is deleted, the remaining hash chain still looks intact. `lookfirst verify-log` then ends with exit 0 and a warning (`head sidecar missing`). | Use `lookfirst verify-log --config lookfirst.yaml --trusted-head /protected/audit.head` to check an external signed checkpoint. A missing, forged, or absent checkpoint in the log fails with exit 2. A valid older checkpoint permits new entries, but cannot detect truncation after that checkpoint. Refresh your external copy regularly. Keep it **outside the write access of whoever can truncate the log** — a `.head` beside the log can be deleted together with it. |
| B5.1 | The privacy filter (`schleuse`) is a deterministic pattern filter. An IBAN split by a line break, text with zero-width characters, or a secret that is only Base64-encoded in free text is **not** recognised. It reduces leakage, it does not anonymise. | Do not rely on it for secrets; keep secrets out of tool arguments. Also not recognised today: keys such as `db_password` or `access_token` (B5.2, pinned as an expected failure). |
| B7.1 | With `confirm.elicitation: true`, `lookfirst serve` warns at start that autonomous clients can answer elicitation themselves (self-approval), even if a fallback channel is configured. The warning cannot establish that a human approved. | For autonomous clients set `confirm.elicitation: false`, so only the web page or the webhook can approve — **and** keep the agent away from that page on the network level (other machine, container or network namespace, or a firewall rule per user). A separate OS user is not enough: every local user reaches loopback. Use `identity_header` only if the backend is reachable solely by the auth proxy; it takes the header unchecked, so an agent that reaches the backend directly can set it and approve itself. |

## Privacy lock („Schleuse“, v0.3 preview)

Private data leaves only as placeholders. Configure `schleuse:` (see `lookfirst/config.py`):

| Direction | What happens |
|---|---|
| tool **result** → AI client | IBANs (checksum-validated; invalid-looking ones are masked too), card numbers (Luhn), e-mails, phone numbers, credentials with a known shape (GitHub/OpenAI/Anthropic/AWS/Slack/Stripe/Hugging Face/Google keys, JWTs, private keys; for `password=…`, `api_key: …`, `Authorization: Bearer …` and `user:pass@` URLs only the value; in structured results also values under keys such as `password`/`token`/`api_key`). Not detected: free-form secrets without a known shape or key name, your own name list and custom patterns become `[[IBAN_3f9a1c]]` – in text, structured content, previews, denial texts and the audit log |
| AI client → **local** tool | a placeholder in arguments is resolved inside the gate – **only** placeholders this gate issued; an unknown or expired one is refused, nothing executes |

Deterministic (no AI), random 128-bit placeholders (not hashes of the value), mapping only in memory with expiry and
**bound to the client connection** – another client cannot resolve them; after 3 unknown placeholders resolution is locked
for that connection. All tool metadata from upstreams except the tool name (title, description, schemas, annotations,
`_meta`, icons) and all free-text audit fields are masked too; non-text content is withheld. Session isolation is tested
over real Streamable HTTP on loopback with two clients (`tests/test_mehrclient_http.py`): client B is refused A's placeholder,
nothing reaches the upstream, A's approval dialog never goes to B, a reconnect starts with an empty mapping. The binding is
per MCP session (`Mcp-Session-Id`), not per user: whoever holds the HTTP token *and* that session ID shares the session. Not yet shown in pilot operation. With stateless HTTP a placeholder may not resolve in a later request (fails closed). **Limits:** it reduces leakage, it does not anonymise – amounts, dates and merchants in context can
still identify a person. A human approving a write sees placeholders too. Arguments sent to *external* tools are not
masked yet (planned).

## Audit log

Append-only JSONL. Each entry carries the hash of its predecessor and an Ed25519 signature; `ts` is integer milliseconds. A
`.head` sidecar holds the latest hash and seq, **signed** with the same key. `verify-log` reports edited, removed, reordered,
inserted or forged entries by line number, and truncation at the end as long as the sidecar is present – a deleted sidecar
yields a warning, never a clean verdict. Arguments are logged as a
SHA-256, not in clear text; the human-readable summary is logged (keep secrets out of summaries – see redaction hook).

## Redaction hook (own code, optional)

`redact.hook: "mypkg.mod:function"` receives the preview before it is shown or sent anywhere and returns a redacted copy.
Default: unchanged. Built-in placeholders for IBANs, cards, e-mails, phone numbers, credentials and your name list come from
the Schleuse (see "Privacy lock" above); the hook is only for your own extra rules on top. It gets a copy and may mask anything
shown, but never the binding: call id and `args_sha256` always come from the gate and the pending registry, also on the approval
page and `/open` (#668 P3).

## Compliance

`docs/compliance-mapping.md` (German) maps what the gate *technically contributes* to EU AI Act Art. 12/14, DORA and MaRisk –
requirement → feature → evidence in the log → gap. It is not legal advice and claims no certification; the wording we allow
ourselves is "supports technically with …".

## Relation to agent-postbox

[agent-postbox](https://github.com/Aethelgard-Systems/agent-postbox) secures **hand-offs between agents** (who sent what to whom,
countersigned). lookfirst secures **actions at tools** (what an agent is allowed to do to the world, confirmed by a human).
Same family of trust tools, same evidence mindset; different seam. They compose: a hand-off can arrive via agent-postbox and the
resulting action still passes the gate.

## Execution interlock (#668 P4)

`execution: {timeout_seconds: 60}` bounds each upstream execution and read-back
request (finite positive seconds; separate from the human confirmation timeout).
Transport exceptions, timeouts and upstream `isError` responses return
`executed` / `readback: unklar` / `blocked: true`: the request was dispatched,
but its effect is not established. No automatic retry occurs. Even an upstream
error that appears to reject before an effect is conservatively treated as
uncertain, because generic MCP errors do not prove absence of side effects.
An inconclusive or mismatching configured read-back also blocks the original
tool. Other tools remain available under their current policies; read-back
requires the read tool's current `allow` policy. The per-tool lock also covers
human confirmation (up to `confirm.timeout_seconds`); parallel calls of that
same tool wait until the confirmation and execution finish.

Before dispatch, the gate writes a signed `execution_started` event. An unresolved
start or `execution_blocked` event is recovered on gate recreation using the same
audit log/key. `execution_resolved` clears successful execution. Recovery refuses
a damaged log or missing signed head. Keep the complete log, head and key across
restarts; changing paths or deleting history loses this protection. This uses the
existing single-worker audit writer, **not** a distributed lock: run one gate
process per log and route a tool consistently to it. It does not prove protection
against disk loss, rollback of both log and head, or a user holding the signing key.

After inspecting the previous effect, request the blocked tool again: this opens
a separate **UNLOCK** preview through the existing configured human confirmation
channels. Approving it writes `execution_unblocked` and returns `unblocked` with
`blocked: false`; **that request never executes the original action**. Submit a
fresh call afterward, subject to current policy and its own required approval.
Denial, timeout or a missing channel keeps the lock. Policy `deny` takes precedence
and cannot unlock. The existing channels retain their trust limits: elicitation
does not prove an actual human answered; disable it for clients that auto-answer
(`elicitation: false`; see [Threat model](docs/threat-model.md)).
A timed-out upstream can still complete remotely; inspect that possibility before
unlocking. No read-back of an uncertain write is automatically retried.

A local pilot adapter already has adapter-local title deduplication (ten minutes) and an
in-memory write latch for its one creation endpoint. P4 does not copy that
business rule or clear its latch. It adds the missing generic timeout and signed,
recoverable per-tool interlock at the gate. Unlocking the gate alone does **not**
unlock a blocked adapter; its operator procedure remains necessary.

## Update, rollback, errors

**Check before every start or after every change:** `lookfirst check --config lookfirst.yaml [--timeout 10]` loads the
configuration, checks rules, audit key, `http.token_file` (never printed), confirmation channels, Schleuse and redaction hook,
and connects to every upstream once to list its tools. One line per check: `OK`, `WARN` (works, but look at it) or `ERROR`
(will not work). Exit 0 without ERROR, 2 with ERROR. It does not start the gate and calls no tool.

**Update.** Your configuration, audit log (`*.jsonl` + `.head`) and key (`*.key` + `.pub`) live next to your config, not in the
package – an update or rollback does not touch them. Copy those four files somewhere safe first.

```bash
pip show lookfirst                                   # note the current version / commit
pipx install --force <path-or-git-url>   # or: pip install -U <path>
lookfirst check --config lookfirst.yaml
lookfirst verify-log --config lookfirst.yaml
```

Then restart the client (stdio: the client starts the gate) or the `serve --transport http` process.

**Rollback.** Install the previous version the same way, pinned to the commit you noted:
`pipx install --force "git+<git-url>@<previous-commit>"`, then `check` and `verify-log`
again. Never create a new key to "fix" a problem: old entries can only be verified with the old `.pub`.

**What a tool call result means** (`structuredContent.lookfirst`):

| Result | What happened | What to do |
|---|---|---|
| `denied` (policy, `not approved`, timeout, no channel) | **nothing** was executed | approve in time, or change the rule; retrying is safe |
| `executed`, `readback: ok` | done and verified | nothing |
| `executed`, `readback: none` | executed, no read-back rule | check in the target system if it matters; add a `readback` rule |
| `executed`, `readback: unklar` / "outcome unclear" | **may have happened**, could not be verified | look in the target system *before* any retry – a blind retry can do it twice |
| `executed`, `readback: fehlgeschlagen` | happened, but the target shows something else | check the target system, fix by hand; do not repeat |
| `Denied: schleuse: unknown or expired placeholder …` | nothing executed | ask the agent to fetch the data again in this session |

**Start and check errors:**

| Message | Meaning | What to do |
|---|---|---|
| `audit key missing … run lookfirst keygen` | no signing key yet | `lookfirst keygen --config …` once (not when restoring – restore the backup instead) |
| `… action must be one of ('allow', 'confirm', 'deny')` | typo in a rule | fix the named rule |
| `rule '…' matches no tool` (WARN) | the rule does nothing; a `deny` falls back to the default | use the exact tool name; with several upstreams `<upstream>__<tool>` |
| `upstream … not reachable` | server not started, wrong command/URL, or no answer in time | start the server, fix `command`/`url`, raise `--timeout` |
| `http.token_file not readable` / `needs at least 32 characters` | token file missing or too short | write a random token of 32+ characters into that file |
| `HTTP on '…' needs http.token_file` | non-loopback address without token | set `http.token_file` or bind to 127.0.0.1 |
| `no approval channel` (WARN) | every `confirm` call will be denied | enable `confirm.web` or `confirm.webhook` |
| `verify-log`: `TAMPERED` | the log was changed, cut or forged | keep the file as evidence, compare with your backup; do not delete |

## Tests

`python -m unittest discover -s tests` – 95 tests, synthetic data, in-memory MCP plus one real stdio subprocess: rules,
parameter binding (`args_sha256`), approve/deny/timeout, web + webhook channel, read-back ok/unklar/fehlgeschlagen, log tampering
(modified, removed, reordered, inserted lines, forged signature, truncated, foreign key), read calls pass through unchanged, multiple upstreams,
HTTP bearer token, Schleuse (masking, placeholders, session binding, credentials), `lookfirst check`, `lookfirst pilot-status`,
and launch gate evaluation.
