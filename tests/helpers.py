"""Test helpers: in-memory upstream servers and a gate wired to an in-memory MCP client. Synthetic data only."""
from __future__ import annotations

import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import mcp.types as t
import yaml
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.shared.memory import create_client_server_memory_streams

from lookfirst import audit, config as cfg, redact
from lookfirst.confirm import Confirmer, PendingRegistry
from lookfirst.proxy import Gate
from lookfirst.upstream import Upstreams


def bank_server(state: dict, lie: bool = False) -> Server:
    """Fake bank. ``lie=True``: the transfer reports a balance that the read-back will not confirm."""
    async def list_tools(ctx, params):
        return t.ListToolsResult(tools=[
            t.Tool(name="kontostand", description="balance", inputSchema={"type": "object", "properties": {}}, annotations=t.ToolAnnotations(readOnlyHint=True)),
            t.Tool(name="ueberweisung", description="transfer", inputSchema={"type": "object", "properties": {"an": {"type": "string"}, "betrag": {"type": "number"}}, "required": ["an", "betrag"]},
                   annotations=t.ToolAnnotations(destructiveHint=True)),
            t.Tool(name="notiz", description="no annotations", inputSchema={"type": "object", "properties": {"text": {"type": "string"}}}),
            t.Tool(name="loeschen", description="delete all", inputSchema={"type": "object", "properties": {}}, annotations=t.ToolAnnotations(destructiveHint=True)),
        ])

    async def call_tool(ctx, params):
        a = params.arguments or {}
        if params.name == "kontostand":
            return t.CallToolResult(content=[t.TextContent(type="text", text=f"saldo {state['saldo']}")], structuredContent={"saldo": state["saldo"]})
        if params.name == "ueberweisung":
            state["saldo"] = round(state["saldo"] - float(a["betrag"]), 2)
            state["calls"].append(("ueberweisung", dict(a)))
            return t.CallToolResult(content=[t.TextContent(type="text", text="ok")], structuredContent={"saldo": state["saldo"] + (1 if lie else 0)})
        state["calls"].append((params.name, dict(a)))
        return t.CallToolResult(content=[t.TextContent(type="text", text="done")], structuredContent={"done": True})
    return Server("fake-bank", version="0", on_list_tools=list_tools, on_call_tool=call_tool)


DEFAULT_RULES = {
    "default": {"read_only": "allow", "destructive": "confirm", "unknown": "confirm"},
    "tools": {"ueberweisung": {"action": "confirm", "summary": "Transfer {betrag} EUR to {an}", "readback": {"tool": "kontostand", "args": {}, "expect": {"saldo": "$result.saldo"}}},
              "loeschen": {"action": "deny"}},
}


def write_config(d: Path, rules=None, upstreams=None, confirm=None) -> cfg.Config:
    data = {"upstreams": upstreams or {"bank": {"command": "true"}}, "rules": rules or DEFAULT_RULES,
            "confirm": confirm or {"timeout_seconds": 0.5, "elicitation": True}, "audit": {"log": "audit.jsonl", "key": "key.pem"}}
    (d / "lookfirst.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    return cfg.load(d / "lookfirst.yaml")


@asynccontextmanager
async def serve_in_memory(server: Server, elicitation_callback=None):
    async with create_client_server_memory_streams() as ((cr, cw), (sr, sw)):
        async with anyio.create_task_group() as tg:
            tg.start_soon(server.run, sr, sw, server.create_initialization_options())
            async with ClientSession(cr, cw, elicitation_callback=elicitation_callback) as cs:
                await cs.initialize()
                yield cs
            tg.cancel_scope.cancel()


class GateHarness:
    """Everything a test needs: tmp dir, config, audit log, registry, confirmer, gate server, upstream sessions."""

    def __init__(self, rules=None, upstreams=None, confirm=None, web_enabled=False, webhook=None, opener=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.conf = write_config(self.dir, rules, upstreams, confirm)
        audit.generate_key(self.conf.audit_key)
        self.log = audit.AuditLog(self.conf.audit_log, audit.load_private(self.conf.audit_key))
        self.registry = PendingRegistry()
        self.confirmer = Confirmer(self.registry, self.conf.timeout_seconds, self.conf.elicitation, web_enabled, webhook, opener=opener)
        self.state = {"saldo": 100.0, "calls": []}

    def close(self):
        self.tmp.cleanup()

    def verify(self):
        return audit.verify(self.conf.audit_log, audit.load_public(Path(str(self.conf.audit_key) + ".pub")))

    @asynccontextmanager
    async def client(self, elicitation_callback=None, servers: dict | None = None, hook=None):
        self.gate = None
        from contextlib import AsyncExitStack
        servers = servers or {"bank": bank_server(self.state)}
        async with AsyncExitStack() as stack:
            sessions = {name: await stack.enter_async_context(serve_in_memory(srv)) for name, srv in servers.items()}
            ups = await Upstreams.from_sessions(self.conf, sessions)
            gate = self.gate = Gate(self.conf, ups, self.log, self.confirmer, hook or redact.identity)
            server = gate.server()
            async with create_client_server_memory_streams() as ((cr, cw), (sr, sw)):
                async with anyio.create_task_group() as tg:
                    tg.start_soon(server.run, sr, sw, server.create_initialization_options())
                    async with ClientSession(cr, cw, elicitation_callback=elicitation_callback) as cs:
                        await cs.initialize()
                        yield cs, sessions
                    tg.cancel_scope.cancel()

    @asynccontextmanager
    async def two_clients(self, elicitation_a=None, elicitation_b=None, servers: dict | None = None, hook=None):
        """Two independent MCP client sessions connected to the same gate and upstream state."""
        from contextlib import AsyncExitStack
        servers = servers or {"bank": bank_server(self.state)}
        async with AsyncExitStack() as stack:
            sessions = {name: await stack.enter_async_context(serve_in_memory(srv)) for name, srv in servers.items()}
            ups = await Upstreams.from_sessions(self.conf, sessions)
            gate = self.gate = Gate(self.conf, ups, self.log, self.confirmer, hook or redact.identity)

            s1 = gate.server()
            stream1_pair = await stack.enter_async_context(create_client_server_memory_streams())
            (cr1, cw1), (sr1, sw1) = stream1_pair

            s2 = gate.server()
            stream2_pair = await stack.enter_async_context(create_client_server_memory_streams())
            (cr2, cw2), (sr2, sw2) = stream2_pair

            async with anyio.create_task_group() as tg:
                tg.start_soon(s1.run, sr1, sw1, s1.create_initialization_options())
                tg.start_soon(s2.run, sr2, sw2, s2.create_initialization_options())
                async with ClientSession(cr1, cw1, elicitation_callback=elicitation_a) as ca, \
                           ClientSession(cr2, cw2, elicitation_callback=elicitation_b) as cb:
                    await ca.initialize()
                    await cb.initialize()
                    yield ca, cb, gate
                tg.cancel_scope.cancel()
