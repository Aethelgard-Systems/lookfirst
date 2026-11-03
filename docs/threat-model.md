# Threat model and known bypasses (#668 P2)

lookfirst protects **one route**: tool calls that a client sends *through* the gate. It is not a sandbox and does not
control anything that reaches the same system another way. This page lists what is and is not covered, so a release
claims only what is proven.

## Covered (with tests)

| Boundary | How | Test |
|---|---|---|
| Write without human decision | rules + annotations → `confirm`; timeout/deny = no | `tests/test_lookfirst.py` |
| Approval reused for other arguments | decision bound to `call_id` and `args_sha256`; web form and webhook must echo the hash of the preview, else 403 (#668 P3) | `tests/test_lookfirst.py` `FreigabeBindungTest` |
| Approval for content the human did not see | elicitation only when the argument JSON fits in full (≤ 800 characters); longer → web page/webhook only, otherwise denied („Vorschau zu lang für Elicitation“) | `tests/test_lookfirst.py` `FreigabeBindungTest` |
| Webhook decision for another call | per-call HMAC token | `tests/test_lookfirst.py` |
| Unauthenticated HTTP entry | loopback-only without token; bearer token otherwise (401) | `tests/test_httpauth.py` |
| Placeholder from another session | Schleuse binds placeholders to the session | `tests/test_schleuse.py` |

## Not covered – known bypasses

| # | Route | Effect | Status / mitigation |
|---|---|---|---|
| B1 | Another integration writes to the same system directly (e.g. an existing chat tool with its own API token) | Writes without gate, preview or audit entry | **Open.** Operator must remove or route such paths through the gate before claiming coverage for that system. |
| B2 | Upstream credentials in the gate's process environment / config, readable by the same OS user | An agent with shell access as that user can call the upstream API directly | **Open.** Run the gate as a separate user or container; give the agent no shell as that user. |
| B3 | Audit signing key, rules and config in a directory writable by the same user | Rules can be loosened, log re-signed | **Open.** Same separation as B2; `verify-log` detects changes only with a public key kept elsewhere. |
| B4 | Client answers elicitation itself (autonomous agent) | Self-approval | Mitigated: `confirm.elicitation: false` → only web page or webhook decide. |
| B5 | Any local process on loopback HTTP without token | Calls tools like the client | Mitigated: set `http.token_file`; the gate warns at start when it is missing. |
| B6 | Arguments sent to external tools | Not masked (Schleuse route C missing) | **Open**, documented in README; not an anonymisation guarantee. |
| B7 | Bearer token, previews and decisions over plain HTTP across a network | Anyone on the path reads the token and calls tools; previews leak; decisions can be altered | **Operator duty.** The bearer token is authentication, **not transport encryption**. Off the local trusted host, require TLS or another protected transport (reverse proxy with TLS, SSH tunnel, VPN). Webhook URLs are already `https://`-only. |

## Release rule

Public material names the systems for which B1 was checked and the deployment that addresses B2/B3. Two tested clients
do not prove arbitrary client compatibility.
