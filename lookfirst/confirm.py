"""Human confirmation. Three channels, tried in this order per call:

1. **MCP elicitation** – if the connected client declares the ``elicitation`` capability, the question is asked inside the
   client (form with a boolean). No extra UI. The arguments are shown in full; if their JSON is longer than
   ``MAX_ELICIT_ARGS`` characters, elicitation is skipped (#668 P3: no approval for content the human could not see) and only
   the web page or the webhook may decide – without either, the call is denied ("Vorschau zu lang für Elicitation").
2. **Local web page** – ``confirm.web`` configured: the call waits until someone opens the page and clicks approve/deny.
3. **Webhook** – ``confirm.webhook`` configured: the preview is POSTed to an external system (later AETHELGARD "Braucht dich");
   the decision comes back on the local HTTP endpoint ``POST /decision/<id>`` with a **per-call token**
   (``HMAC-SHA256(secret, call_id)``): a token seen in one webhook body or log cannot approve any other call (review #304 P2).
   The decision must also echo ``args_sha256`` from the preview; a missing or different hash is refused (#668 P3), so a
   decision only ever applies to the exact arguments that were shown.
   Webhook URLs must be ``https://`` unless they point to 127.0.0.1/localhost.

Every channel has the same timeout; a timeout is a denial (``deny_timeout``). The decision is a value object with who/how.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import anyio


@dataclass
class Decision:
    approved: bool
    by: str          # "elicitation" | "web" | "webhook" | "timeout" | "policy"
    note: str = ""
    actor: str = ""  # v1.1: wer entschieden hat – Kennung aus SSO-Header, Formularfeld, Webhook-Body oder MCP-Client-Name

    @property
    def label(self) -> str:
        """Für Protokoll und Antwort: ``kanal:akteur`` (``web:marco``), nur ``kanal`` wenn keine Kennung vorliegt."""
        return f"{self.by}:{self.actor}" if self.actor else self.by


ACTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@+/:-]{0,62}$")


def clean_actor(value) -> str:
    v = " ".join(str(value or "").split())
    return v if ACTOR_RE.fullmatch(v) else ""


@dataclass
class Pending:
    id: str
    preview: dict
    created: float
    event: anyio.Event = field(default_factory=anyio.Event)
    decision: Decision | None = None
    args_sha256: str = ""  # binding, kept outside the preview dict: a redaction hook mutating the preview cannot change it


MAX_ELICIT_ARGS = 800  # characters of argument JSON an elicitation form shows; longer → web page / webhook only


def args_text(preview: dict) -> str:
    return json.dumps(preview.get("arguments") or {}, ensure_ascii=False)


class PendingRegistry:
    """Open confirmations, shared between the proxy, the web page and the webhook endpoint."""

    def __init__(self, now=time.time):
        self.now = now
        self.items: dict[str, Pending] = {}

    def open(self, preview: dict) -> Pending:
        p = Pending(id=preview["id"], preview=preview, created=self.now(), args_sha256=str(preview.get("args_sha256") or ""))
        self.items[p.id] = p
        return p

    def decide(self, call_id: str, approved: bool, by: str, note: str = "", actor: str = "") -> bool:
        p = self.items.get(call_id)
        if p is None or p.decision is not None:
            return False
        p.decision = Decision(approved, by, note, clean_actor(actor))
        p.event.set()
        return True

    def args_match(self, call_id: str, given) -> bool | None:
        """``None``: no open call with this id. Otherwise whether ``given`` is the ``args_sha256`` of its preview."""
        p = self.items.get(call_id)
        if p is None or p.decision is not None:
            return None
        return bool(p.args_sha256) and isinstance(given, str) and secrets.compare_digest(given, p.args_sha256)

    def close(self, call_id: str):
        self.items.pop(call_id, None)

    def list_open(self) -> list[dict]:
        return [p.preview for p in self.items.values() if p.decision is None]

    def open_items(self) -> list[Pending]:
        return [p for p in self.items.values() if p.decision is None]


class Confirmer:
    def __init__(self, registry: PendingRegistry, timeout: float, use_elicitation: bool, web_enabled: bool, webhook: dict | None, opener=None):
        self.registry, self.timeout, self.use_elicitation, self.web_enabled, self.webhook = registry, timeout, use_elicitation, web_enabled, webhook
        self.open = opener or urllib.request.urlopen
        self.webhook_secret = None
        if webhook:
            from pathlib import Path
            u = urllib.parse.urlparse(str(webhook.get("url", "")))
            if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1")):
                raise ValueError("confirm.webhook.url must be https:// (http:// only for 127.0.0.1/localhost)")
            self.webhook_secret = Path(webhook["token_file"]).read_text(encoding="utf-8").strip() if webhook.get("token_file") else secrets.token_urlsafe(24)

    def call_token(self, call_id: str) -> str:
        """Per-call decision token: HMAC-SHA256 of the call id under the webhook secret (never the secret itself)."""
        return hmac.new(self.webhook_secret.encode("utf-8"), call_id.encode("utf-8"), hashlib.sha256).hexdigest()

    def call_token_ok(self, call_id: str, given: str) -> bool:
        return bool(self.webhook_secret) and secrets.compare_digest(given, self.call_token(call_id))

    async def ask(self, preview: dict, session=None) -> Decision:
        """``session`` is the MCP ServerSession of the calling client (for elicitation)."""
        too_long = len(args_text(preview)) > MAX_ELICIT_ARGS
        if self.use_elicitation and session is not None and _supports_elicitation(session):
            if not too_long:
                return await self._elicit(preview, session)
            if not self.web_enabled and not self.webhook:
                return Decision(False, "policy", f"Vorschau zu lang für Elicitation ({len(args_text(preview))} > {MAX_ELICIT_ARGS} Zeichen); "
                                                 "Freigabe nur über confirm.web oder confirm.webhook – keiner konfiguriert")
        if not self.web_enabled and not self.webhook:
            return Decision(False, "policy", "no confirmation channel configured")
        pending = self.registry.open(preview)
        try:
            if self.webhook:
                try:
                    await anyio.to_thread.run_sync(self._post_webhook, preview)
                except Exception as e:  # noqa: BLE001
                    if not self.web_enabled:
                        return Decision(False, "policy", f"webhook unreachable: {type(e).__name__}")
            with anyio.move_on_after(self.timeout):
                await pending.event.wait()
            return pending.decision or Decision(False, "timeout", f"no decision within {int(self.timeout)}s")
        finally:
            self.registry.close(preview["id"])

    async def _elicit(self, preview: dict, session) -> Decision:
        import mcp.types as t
        shown = args_text(preview)
        if len(shown) > MAX_ELICIT_ARGS:  # never approve what was not shown in full (ask() already routes these elsewhere)
            return Decision(False, "policy", "Vorschau zu lang für Elicitation")
        schema = {"type": "object", "properties": {"approve": {"type": "boolean", "title": "Approve this action?", "description": preview["summary"]}}, "required": ["approve"]}
        try:
            with anyio.fail_after(self.timeout):
                res: t.ElicitResult = await session.elicit_form(f"lookfirst: {preview['summary']}\nTool: {preview['tool']}\nArguments: {shown}", schema)
        except TimeoutError:
            return Decision(False, "timeout", f"no answer within {int(self.timeout)}s")
        except Exception as e:  # noqa: BLE001
            return Decision(False, "elicitation", f"elicitation failed: {type(e).__name__}")
        actor = _client_name(session)
        if res.action != "accept" or not isinstance(res.content, dict) or res.content.get("approve") is not True:
            reason = f"action={res.action}" if res.action != "accept" else "user rejected"
            return Decision(False, "elicitation", reason, actor)
        return Decision(True, "elicitation", "", actor)

    def _post_webhook(self, preview: dict):
        body = json.dumps({"id": preview["id"], "summary": preview["summary"], "tool": preview["tool"], "arguments": preview["arguments"],
                           "args_sha256": preview["args_sha256"], "decision_endpoint": f"/decision/{preview['id']}", "token": self.call_token(preview["id"])}).encode()
        req = urllib.request.Request(self.webhook["url"], data=body, method="POST", headers={"Content-Type": "application/json"})
        with self.open(req, timeout=10) as r:
            r.read()


def _client_name(session) -> str:
    """Name des MCP-Clients (clientInfo.name) – kennzeichnet den Kanal, nicht die Person; bleibt im Protokoll als ``elicitation:<client>``."""
    try:
        params = getattr(session, "client_params", None)
        info = getattr(params, "client_info", None) or getattr(params, "clientInfo", None)
        return clean_actor(getattr(info, "name", ""))
    except Exception:  # noqa: BLE001
        return ""


def _supports_elicitation(session) -> bool:
    try:
        import mcp.types as t
        return bool(session.check_client_capability(t.ClientCapabilities(elicitation=t.ElicitationCapability())))
    except Exception:  # noqa: BLE001
        return False
