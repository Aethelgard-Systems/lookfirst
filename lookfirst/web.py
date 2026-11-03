"""Small local approval page (Starlette). Lists open confirmations, one click approves or denies.
Also hosts ``POST /decision/<id>`` for the webhook channel (per-call token required).

Content binding (#668 P3): every decision – page form or webhook – must carry the ``args_sha256`` of the preview it was made
for; missing or different → 403, no decision. A decision therefore never applies to arguments other than the ones shown.
The page and ``/open`` re-apply the redaction hook (defence in depth) to a copy only; id and hash always come from the
registry entry, never from the hook's output, so a hook cannot break or redirect the binding.

Browser hardening (review #304 P1): the page is bound to 127.0.0.1, but a web page in the user's browser could still reach it
via DNS rebinding. Therefore every request must carry a ``Host`` header naming this server (loopback or the configured host),
browser requests with a foreign ``Origin``/``Sec-Fetch-Site: cross-site`` are refused, and state changes need the per-process
CSRF token that only the page itself delivers."""
from __future__ import annotations

import copy
import html
import json
import secrets

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from .confirm import Confirmer, PendingRegistry, clean_actor

PAGE = """<!doctype html><meta charset="utf-8"><title>lookfirst – Freigaben</title>
<style>body{{font-family:system-ui;max-width:44rem;margin:2rem auto;padding:0 1rem}} .c{{border:1px solid #ccc;border-radius:8px;padding:1rem;margin:1rem 0}}
pre{{white-space:pre-wrap;background:#f6f6f6;padding:.5rem;border-radius:6px}} button{{padding:.6rem 1.2rem;font-size:1rem;margin-right:.5rem}}</style>
<h1>lookfirst – waiting for you</h1><p>{count}</p>{cards}
<p><small>This page refreshes every 5 s. Nothing happens without your click.</small></p><script>setTimeout(()=>location.reload(),5000)</script>"""
CARD = """<div class="c"><h2>{summary}</h2><p>Tool: <code>{tool}</code></p><pre>{args}</pre>
{who}
<form method="post" action="/approve/{id}" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="args_sha256" value="{sha}"><input type="hidden" name="actor" class="actor-copy"><button>✅ Approve</button></form>
<form method="post" action="/deny/{id}" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="args_sha256" value="{sha}"><input type="hidden" name="actor" class="actor-copy"><button>⛔ Deny</button></form></div>"""
WHO_FIELD = """<p><label>Your name (goes into the audit log, self-declared): <input id="actor" maxlength="63" autocomplete="username" placeholder="e.g. marco"></label></p>"""
WHO_HEADER = """<p>Signed in as <b>{actor}</b> (from reverse proxy).</p>"""
ACTOR_SCRIPT = """<script>
try{{const a=document.getElementById('actor');if(a){{a.value=localStorage.getItem('tw-actor')||'';
const sync=()=>{{document.querySelectorAll('.actor-copy').forEach(i=>i.value=a.value);try{{localStorage.setItem('tw-actor',a.value)}}catch(e){{}}}};a.addEventListener('input',sync);sync();}}}}catch(e){{}}
</script>"""


MAX_DECISION_BODY = 64 * 1024
LOOPBACK = ("127.0.0.1", "localhost", "[::1]")


class HostGuard(BaseHTTPMiddleware):
    """403 unless ``Host`` names this server; browser cross-site requests (Origin elsewhere / Sec-Fetch-Site cross-site) are refused."""

    def __init__(self, app, host: str, port: int):
        super().__init__(app)
        extra = f"[{host}]" if ":" in host else host
        self.names = {n for base in (*LOOPBACK, extra) for n in (base, f"{base}:{port}")}

    async def dispatch(self, request: Request, call_next):
        host = request.headers.get("host", "").lower()
        if host not in self.names:
            return JSONResponse({"error": "forbidden: Host header does not name this server"}, status_code=403)
        origin = request.headers.get("origin")
        if origin is not None and origin.lower().rstrip("/") not in {f"http://{n}" for n in self.names}:
            return JSONResponse({"error": "forbidden: foreign origin"}, status_code=403)
        if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
            return JSONResponse({"error": "forbidden: cross-site request"}, status_code=403)
        return await call_next(request)


def create_app(registry: PendingRegistry, confirmer: Confirmer, redact, host: str = "127.0.0.1", port: int = 8477,
               identity_header: str | None = None) -> Starlette:
    """``identity_header`` (e.g. ``X-Forwarded-User``): when the page runs behind an authenticating reverse proxy, the user from this
    header is the actor (verified by the proxy). Without it the page asks for a self-declared name (marked as such in the log)."""
    csrf = secrets.token_urlsafe(16)
    hdr = identity_header.lower() if identity_header else None

    def actor_of(request: Request, form=None) -> str:
        if hdr:
            return clean_actor(request.headers.get(hdr, ""))
        return clean_actor(form.get("actor", "")) if form is not None else ""

    def view(p) -> dict:
        return {**redact(copy.deepcopy(p.preview)), "id": p.id, "args_sha256": p.args_sha256}

    async def index(request: Request):
        items = [view(p) for p in registry.open_items()]
        verified = actor_of(request)
        who = WHO_HEADER.format(actor=html.escape(verified)) if hdr else WHO_FIELD
        cards = "".join(CARD.format(summary=html.escape(p["summary"]), tool=html.escape(p["tool"]), args=html.escape(json.dumps(p["arguments"], ensure_ascii=False, indent=1)),
                                    id=html.escape(p["id"]), sha=html.escape(str(p.get("args_sha256", ""))), csrf=csrf, who=who) for p in items)
        count = f"{len(items)} open" if items else "Nothing open."
        r = HTMLResponse(PAGE.format(count=count, cards=cards) + ("" if hdr else ACTOR_SCRIPT))
        r.headers["Cache-Control"] = "no-store"
        r.headers["X-Frame-Options"] = "DENY"
        return r

    async def decide_form(request: Request):
        form = await request.form()
        if form.get("csrf") != csrf:
            return JSONResponse({"error": "csrf"}, status_code=403)
        call_id = request.path_params["call_id"]
        match = registry.args_match(call_id, form.get("args_sha256"))
        if match is None:
            return JSONResponse({"error": "unknown or already decided"}, status_code=404)
        if not match:
            return JSONResponse({"error": "forbidden: args_sha256 missing or does not match the preview"}, status_code=403)
        approved = request.url.path.startswith("/approve/")
        actor = actor_of(request, form)
        if not actor:
            return JSONResponse({"error": "name required (who approves goes into the audit log)"}, status_code=400)
        ok = registry.decide(call_id, approved, "web", "" if hdr else "self-declared", actor)
        return RedirectResponse("/", status_code=303) if ok else JSONResponse({"error": "unknown or already decided"}, status_code=404)

    async def decision_api(request: Request):
        try:
            raw = await request.body()
            body = json.loads(raw) if len(raw) <= MAX_DECISION_BODY else None
        except ValueError:
            body = None
        if body is None:
            return JSONResponse({"error": "JSON object expected (≤ 64 KiB)"}, status_code=400)
        call_id = request.path_params["call_id"]
        if not isinstance(body, dict) or not confirmer.call_token_ok(call_id, str(body.get("token", ""))):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if body.get("decision") not in ("approve", "deny"):
            return JSONResponse({"error": "decision: approve|deny"}, status_code=400)
        match = registry.args_match(call_id, body.get("args_sha256"))
        if match is None:
            return JSONResponse({"status": "unknown"}, status_code=404)
        if not match:
            return JSONResponse({"error": "forbidden: args_sha256 missing or does not match the preview"}, status_code=403)
        ok = registry.decide(call_id, body["decision"] == "approve", "webhook", str(body.get("note", ""))[:200], str(body.get("actor", "")))
        return JSONResponse({"status": "recorded" if ok else "unknown"}, status_code=200 if ok else 404)

    async def open_api(request: Request):
        return JSONResponse({"open": [view(p) for p in registry.open_items()]})

    return Starlette(routes=[Route("/", index), Route("/open", open_api), Route("/approve/{call_id}", decide_form, methods=["POST"]),
                             Route("/deny/{call_id}", decide_form, methods=["POST"]), Route("/decision/{call_id}", decision_api, methods=["POST"])],
                     middleware=[Middleware(HostGuard, host=host, port=port)])
