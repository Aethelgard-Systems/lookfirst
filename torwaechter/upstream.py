"""Connections to upstream MCP servers (stdio subprocess or Streamable HTTP). Tool names are prefixed ``<upstream>__<tool>``
when more than one upstream is configured; with a single upstream the names pass through unchanged."""
from __future__ import annotations

import os
from contextlib import AsyncExitStack
from dataclasses import dataclass, field

import mcp.types as t
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from .config import Config, Upstream

SEP = "__"


@dataclass
class Connected:
    upstream: Upstream
    session: ClientSession
    tools: dict[str, t.Tool] = field(default_factory=dict)  # upstream-local name → Tool


class Upstreams:
    def __init__(self, config: Config):
        self.config, self.stack = config, AsyncExitStack()
        self.conns: dict[str, Connected] = {}

    async def __aenter__(self):
        await self.stack.__aenter__()
        for name, up in self.config.upstreams.items():
            if up.command:
                env = {**os.environ, **up.env}
                r, w = await self.stack.enter_async_context(stdio_client(StdioServerParameters(command=up.command, args=up.args, env=env, cwd=up.cwd)))
            else:
                from mcp.client.streamable_http import streamable_http_client
                streams = await self.stack.enter_async_context(streamable_http_client(up.url))
                r, w = streams[0], streams[1]
            session = await self.stack.enter_async_context(ClientSession(r, w))
            await session.initialize()
            conn = Connected(up, session)
            await self.refresh(conn)
            self.conns[name] = conn
        return self

    async def __aexit__(self, *exc):
        await self.stack.__aexit__(*exc)

    @classmethod
    async def from_sessions(cls, config: Config, sessions: dict[str, ClientSession]) -> "Upstreams":
        """Already-connected sessions (tests, embedding). No subprocesses are started."""
        self = cls(config)
        for name, session in sessions.items():
            conn = Connected(config.upstreams[name], session)
            await self.refresh(conn)
            self.conns[name] = conn
        return self

    async def refresh(self, conn: Connected):
        conn.tools = {tool.name: tool for tool in (await conn.session.list_tools()).tools}

    def public_name(self, upstream: str, tool: str) -> str:
        return f"{upstream}{SEP}{tool}" if self.config.prefixed else tool

    def resolve(self, public: str) -> tuple[Connected, str] | None:
        if self.config.prefixed:
            up, sep, tool = public.partition(SEP)
            conn = self.conns.get(up) if sep else None
            return (conn, tool) if conn and tool in conn.tools else None
        (conn,) = self.conns.values()
        return (conn, public) if public in conn.tools else None

    def list_tools(self) -> list[t.Tool]:
        out = []
        for name, conn in self.conns.items():
            for tool in conn.tools.values():
                out.append(tool.model_copy(update={"name": self.public_name(name, tool.name)}))
        return out
