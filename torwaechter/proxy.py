"""The gate itself: an MCP server that forwards ``tools/list`` and ``tools/call`` to the upstreams and, for every call
that is not plain reading, runs preview → confirmation → execution → read-back → audit.

Outcomes a client sees (``structuredContent.torwaechter``):
  allowed            – read-only or allowed by rule, forwarded unchanged (logged)
  denied             – by rule, by a human, by timeout, or because no confirmation channel exists (logged, never executed)
  executed           – approved and executed; ``readback`` is ``ok`` | ``unklar`` | ``fehlgeschlagen`` | ``none`` (no rule)
The proxy never reports "done" for a write without saying what the read-back found.
"""
from __future__ import annotations

import contextvars
import copy
import secrets
import weakref
from pathlib import Path

import anyio
import mcp.types as t
from mcp.server.lowlevel import Server

from . import preview as pv, readback, rules
from .audit import AuditLog
from .config import Config
from .confirm import Confirmer
from .execution import ExecutionSafety
from .schleuse import Schleuse, SchleuseError
from .upstream import Upstreams


def new_call_id() -> str:
    return "tw-" + secrets.token_hex(8)


_CURRENT: contextvars.ContextVar = contextvars.ContextVar("torwaechter_schleuse", default=None)


class _MaskedAudit:
    """Every free-text audit field (summary, note, by) passes the current session's Schleuse before it is written."""
    def __init__(self, inner: AuditLog):
        self._inner = inner

    def append(self, event, call_id, tool, **kw):
        s = _CURRENT.get()
        if s is not None:
            for k in ("summary", "note", "by"):
                if isinstance(kw.get(k), str):
                    kw[k] = s.mask_text(kw[k])
        return self._inner.append(event, call_id, tool, **kw)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _mask_tool(schleuse, tool):
    data = tool.model_dump(by_alias=True, exclude_none=True)
    name = data.pop("name")
    return t.Tool.model_validate({"name": name, **schleuse.mask(data)})


class Gate:
    def __init__(self, config: Config, upstreams: Upstreams, audit: AuditLog, confirmer: Confirmer, redact, schleuse: Schleuse | None = None):
        self.config, self.up, self.audit, self.confirmer, self.redact = config, upstreams, audit, confirmer, redact
        base = config.base or Path(".")
        # Datenschutz-Schleuse: one instance PER CLIENT SESSION (placeholders are bound to the session that received them).
        if schleuse is not None:
            self._make_schleuse = lambda: schleuse
        elif config.schleuse is not None:
            self._make_schleuse = lambda: Schleuse.from_config(config.schleuse, base)
        else:
            self._make_schleuse = None
        self._sessions: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        self._no_session: Schleuse | None = None
        if self._make_schleuse is not None:
            self.audit = _MaskedAudit(audit)
            inner = redact
            # Preview for human, webhook and elicitation (travels through the client!) is masked as well.
            self.redact = lambda preview: inner(_CURRENT.get().mask(preview) if _CURRENT.get() is not None else preview)
        self.execution = ExecutionSafety(self.audit)

    def schleuse_for(self, ctx) -> Schleuse | None:
        if self._make_schleuse is None:
            return None
        session = getattr(ctx, "session", None)
        # mcp ≥2 wraps each request in a fresh ServerSession; the underlying connection is the stable per-client key.
        # Stateless HTTP may create a connection per request → placeholders then do not resolve (fail-closed).
        session = getattr(session, "_connection", None) or session
        if session is None:
            if self._no_session is None:
                self._no_session = self._make_schleuse()
            return self._no_session
        try:
            found = self._sessions.get(session)
            if found is None:
                found = self._sessions[session] = self._make_schleuse()
            return found
        except TypeError:  # session object not weak-referenceable → refuse to share state across clients
            raise SchleuseError("no session isolation available") from None

    def unmatched_rules(self) -> list[str]:
        """Rule names that match no upstream tool (typo, wrong prefix such as ``bank.x`` instead of ``bank__x``). Such a rule
        silently does nothing – a ``deny`` would fall back to the default ``confirm`` – so the CLI warns at start-up."""
        return sorted(n for n in self.config.tool_rules if self.up.resolve(n) is None)

    def server(self) -> Server:
        return Server(self.config.server_name, version="0.2.0", instructions="Writes go through a human gate. Read tools pass through.",
                      on_list_tools=self.on_list_tools, on_call_tool=self.on_call_tool)

    async def on_list_tools(self, ctx, params):
        tools = self.up.list_tools()
        if self._make_schleuse is None:
            return t.ListToolsResult(tools=tools)
        # Upstream metadata can carry private data anywhere (title, description, schemas, annotations, meta, icons):
        # every field except the tool name (needed for routing) is masked like any other text towards the client.
        s = self.schleuse_for(ctx)
        return t.ListToolsResult(tools=[_mask_tool(s, x) for x in tools])

    async def on_call_tool(self, ctx, params: t.CallToolRequestParams):
        """Datenschutz-Schleuse (#604) um jeden Aufruf: Platzhalter in Argumenten lokal auflösen (nur eigene dieser Sitzung),
        jede Antwort an den Client maskieren – auch Ablehnungs-, Vorschau-, Rücklese- und Protokolltexte."""
        if self._make_schleuse is None:
            return await self._call(ctx, params)
        try:
            schleuse = self.schleuse_for(ctx)
        except SchleuseError as e:
            return self._result({"status": "denied", "reason": f"schleuse: {e}"}, f"Denied: {e}", error=True)
        token = _CURRENT.set(schleuse)
        try:
            before = dict(schleuse.counts)
            try:
                resolved = schleuse.resolve(dict(params.arguments or {}))
            except SchleuseError as e:
                self.audit.append("decision", new_call_id(), params.name, decision="deny", by="schleuse", note=str(e))
                return self._result({"status": "denied", "reason": f"schleuse: {e}"}, f"Denied: {e}", error=True)
            res = await self._call(ctx, t.CallToolRequestParams(name=params.name, arguments=resolved))
            out = t.CallToolResult(content=[self._mask_content(schleuse, c) for c in res.content], structuredContent=schleuse.mask(_structured(res)),
                                   isError=bool(getattr(res, "is_error", False) or getattr(res, "isError", False)))
            delta = {k: schleuse.counts[k] - before[k] for k in ("ersetzt", "aufgeloest")}
            if any(delta.values()):
                self.audit.append("schleuse", new_call_id(), params.name, note=f"ersetzt={delta['ersetzt']} aufgeloest={delta['aufgeloest']}")
            return out
        finally:
            _CURRENT.reset(token)

    @staticmethod
    def _mask_content(schleuse, c):
        if getattr(c, "type", None) == "text":
            return t.TextContent(type="text", text=schleuse.mask_text(c.text))
        # Fail-closed: non-text content (images, resources) could carry private data we cannot inspect.
        return t.TextContent(type="text", text="[schleuse: nicht-textlicher Inhalt zurückgehalten]")

    async def _call(self, ctx, params: t.CallToolRequestParams):
        # Serialize confirmation + execution for the same tool, including callers
        # already waiting when a previous dispatch acquired an uncertain outcome.
        async with self.execution.lock(params.name):
            return await self._call_serialized(ctx, params)

    async def _call_serialized(self, ctx, params: t.CallToolRequestParams):
        name, args = params.name, dict(params.arguments or {})
        call_id = new_call_id()
        found = self.up.resolve(name)
        if found is None:
            return self._result({"status": "denied", "reason": "unknown tool"}, f"Unknown tool {name}", error=True)
        conn, local = found
        tool = conn.tools[local]
        action, reason = rules.decide(self.config, name, tool.annotations)
        rule = self.config.tool_rules.get(name)
        preview = pv.build(call_id, name, args, rule.summary if rule else None, tool.description, action, reason)
        # The redaction hook runs once, before anything leaves the call: the audit log, the human channels and the
        # client-visible text all see the redacted preview. The raw arguments only go to the upstream.
        # The hook may mask what is displayed, but never the binding: id and hash of the arguments that will be executed.
        # It gets a copy (in-place mutation cannot reach the preview) and the binding is restored from values held outside it.
        bound = preview["args_sha256"]
        shown = {**self.redact(copy.deepcopy(preview)), "id": call_id, "args_sha256": bound}
        summary = str(shown.get("summary", ""))[:pv.MAX_SUMMARY]
        if action != "deny" and name in self.execution.blocked:
            return await self._unlock(ctx, call_id, name)
        if action == "allow":
            self.audit.append("allow", call_id, name, args_sha256=preview["args_sha256"], summary=summary, decision="allow", by=reason)
            res, failed = await self._dispatch(conn, local, args, call_id, name, preview["args_sha256"])
            if failed:
                return res
            self.audit.append("result", call_id, name, result_sha256=pv.args_hash(_structured(res)), note="passthrough")
            self.execution.resolve(call_id, name)
            return _with_gate(res, {"status": "allowed", "id": call_id, "reason": reason})
        self.audit.append("preview", call_id, name, args_sha256=preview["args_sha256"], summary=summary, decision=action, by=reason)
        if action == "deny":
            self.audit.append("decision", call_id, name, decision="deny", by="policy", note=reason)
            return self._result({"status": "denied", "id": call_id, "reason": reason}, f"Denied by policy: {summary}", error=True)
        decision = await self.confirmer.ask(shown, getattr(ctx, "session", None))
        self.audit.append("decision", call_id, name, decision="approve" if decision.approved else "deny", by=decision.label, note=decision.note)
        if not decision.approved:
            return self._result({"status": "denied", "id": call_id, "reason": f"{decision.label}: {decision.note or 'not approved'}"},
                                f"Not approved ({decision.label}): {summary}", error=True)
        res, failed = await self._dispatch(conn, local, args, call_id, name, preview["args_sha256"])
        if failed:
            return res
        structured = _structured(res)
        self.audit.append("result", call_id, name, result_sha256=pv.args_hash(structured), note="error" if res.is_error else "ok")
        verdict, detail = "none", "no read-back rule"
        if rule and rule.readback:
            verdict, detail = await readback.check(rule.readback, args, structured, self._reader())
        if verdict in ("unklar", "fehlgeschlagen"):
            self.execution.block(call_id, name, "read-back could not confirm the effect")
        self.audit.append("readback", call_id, name, readback=verdict, note=detail)
        if verdict not in ("unklar", "fehlgeschlagen"):
            self.execution.resolve(call_id, name)
        gate = {"status": "executed", "id": call_id, "approved_by": decision.label, "readback": verdict, "readback_detail": detail,
                "blocked": name in self.execution.blocked}
        return _with_gate(res, gate)

    async def _dispatch(self, conn, local, args, call_id, name, args_sha256):
        self.execution.start(call_id, name, args_sha256)
        try:
            with anyio.fail_after(self.config.upstream_timeout_seconds):
                res = await conn.session.call_tool(local, args)
            if not res.is_error:
                return res, False
            error = "UpstreamToolError"
        except anyio.get_cancelled_exc_class():
            self.execution.block(call_id, name, "dispatch cancelled; outcome unclear")
            raise
        except Exception as e:  # noqa: BLE001
            error = type(e).__name__
        self.execution.block(call_id, name, f"upstream error {error}")
        self.audit.append("result", call_id, name, note=f"upstream error {error}", readback="unklar")
        return self._result({"status": "executed", "id": call_id, "upstream_error": error, "readback": "unklar", "blocked": True},
                            f"Upstream outcome unclear ({error}); tool blocked. Inspect the effect before requesting human unlock; no retry performed.", error=True), True

    async def _unlock(self, ctx, call_id, name):
        blocked_call = self.execution.blocked[name]
        preview = pv.build(call_id, name, {"operation": "unlock", "blocked_call_id": blocked_call},
                           "UNLOCK tool after inspecting the previous uncertain effect; this does not retry the action",
                           "", "confirm", "tool blocked after uncertain execution")
        shown = self.redact(preview)
        self.audit.append("preview", call_id, name, args_sha256=preview["args_sha256"], summary=shown["summary"], decision="confirm", by="execution interlock")
        decision = await self.confirmer.ask(shown, getattr(ctx, "session", None))
        self.audit.append("decision", call_id, name, decision="approve" if decision.approved else "deny", by=decision.label, note=decision.note)
        if decision.approved:
            self.execution.unblock(call_id, name, decision)
        return self._result({"status": "unblocked" if decision.approved else "denied", "id": call_id, "blocked": not decision.approved,
                             "reason": "tool unblocked; submit a fresh call for current policy/approval" if decision.approved else "tool blocked; human unlock required"},
                            "No upstream call made. " + ("Tool unblocked; submit a fresh call." if decision.approved else "Tool remains blocked; inspect previous effect before unlocking."), error=True)

    def _reader(self):
        async def call_read(public_tool: str, args: dict):
            found = self.up.resolve(public_tool)
            if found is None:
                raise LookupError(public_tool)
            conn, local = found
            action, _ = rules.decide(self.config, public_tool, conn.tools[local].annotations)
            if action != "allow":
                raise PermissionError("read-back tool requires current allow policy")
            if public_tool in self.execution.blocked:
                raise RuntimeError("read-back tool blocked")
            with anyio.fail_after(self.config.upstream_timeout_seconds):
                r = await conn.session.call_tool(local, args)
            return _structured(r), bool(r.is_error)
        return call_read

    @staticmethod
    def _result(gate: dict, text: str, error: bool = False) -> t.CallToolResult:
        return t.CallToolResult(content=[t.TextContent(type="text", text=text)], structuredContent={"torwaechter": gate}, isError=error)


def _structured(res) -> dict | None:
    s = getattr(res, "structured_content", None)
    if s is None:
        s = getattr(res, "structuredContent", None)
    return s if isinstance(s, dict) else None


def _with_gate(res, gate: dict) -> t.CallToolResult:
    structured = _structured(res)
    merged = {**(structured or {}), "torwaechter": gate}
    return t.CallToolResult(content=list(res.content), structuredContent=merged, isError=bool(res.is_error))
