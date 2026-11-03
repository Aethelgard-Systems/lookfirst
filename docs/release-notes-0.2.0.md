# lookfirst 0.2.0 — release notes (draft)

**Status:** pre-1.0, not a production release. Apache-2.0. Python package `lookfirst`.

## What it is
A gate between AI agents and their tools (MCP proxy). Before a risky tool call runs: preview of what will happen → a human confirms (in the client, on a local web page, or via webhook) → read-back of the result → signed audit log.

## What is in 0.2.0
- Preview, confirmation (three channels), read-back, signed audit log (`verify-log`).
- Preview-forgery protection: control, bidi, zero-width, blank-looking and other invisible characters are shown as `\uXXXX` in every channel; checked against all Default_Ignorable code points.
- Webhook bodies carry escaped `tool_display` / `arguments_display`; receivers must show those, not the raw fields.
- Tests: 148 (5 documented expected failures that pin the known limits).

## Known limits (see README)
B4.1 log truncation with deleted `.head`; B5.1/B5.2 secret redaction is not complete (e.g. `db_password`, `access_token`); B7.1 self-approval by autonomous clients that can reach the approval page. Homoglyphs are not detected.

## Evidence
Unit tests and an independent counter-check by a second model (local runs). A recorded operator run with a real client is pending and is **not** claimed here.

## Install
`pip install lookfirst` (once published) or from the wheel/sdist attached to the release.
