"""``torwaechter check --config …`` (#668 P6): check a configuration without starting the gate.

One line per check: ``OK``, ``WARN`` or ``ERROR`` plus what to do. Exit 0 when there is no ERROR, 2 otherwise.
Never prints tokens, keys or upstream environment values; upstream URLs are shown without credentials or query.
"""
from __future__ import annotations

import os
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

import anyio

from . import audit, config as cfg, httpauth, redact

OK, WARN, ERROR = "OK", "WARN", "ERROR"
DEFAULT_TIMEOUT = 10.0

# probe(upstream, timeout) -> upstream-local tool names; raises on failure. Replaceable in tests.
Probe = Callable[[cfg.Upstream, float], Awaitable[list[str]]]


@dataclass
class Report:
    lines: list[tuple[str, str, str]] = field(default_factory=list)

    def add(self, status: str, topic: str, text: str):
        self.lines.append((status, topic, text))

    @property
    def errors(self) -> int:
        return sum(1 for s, _, _ in self.lines if s == ERROR)

    @property
    def warnings(self) -> int:
        return sum(1 for s, _, _ in self.lines if s == WARN)

    def render(self) -> str:
        out = [f"{s:<5}  {topic:<10} {text}" for s, topic, text in self.lines]
        out.append(f"result: {self.errors} error(s), {self.warnings} warning(s) – gate not started")
        return "\n".join(out)


def url_problem(url: str | None) -> str | None:
    """Why ``url`` cannot be an MCP upstream, or None. Never echoes the url or parser text (may hold credentials)."""
    try:
        u = urllib.parse.urlsplit(str(url or ""))
        u.port  # raises ValueError for a non-numeric or out-of-range port
    except ValueError:
        return "invalid url (bad port or broken [IPv6] host)"
    if u.scheme not in ("http", "https"):
        return "invalid url (scheme must be http or https)"
    if not u.hostname:
        return "invalid url (no host)"
    return None


def safe_url(url: str | None) -> str:
    """scheme://host[:port]/path – no user:password, no query, no fragment."""
    try:
        u = urllib.parse.urlsplit(str(url or ""))
        port = u.port
    except ValueError:
        return "(invalid url)"
    host = u.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if port:
        host = f"{host}:{port}"
    return f"{u.scheme}://{host}{u.path}" if u.scheme else "(invalid url)"


def _reason(e: BaseException, hide: str | None = None) -> str:
    while isinstance(e, BaseExceptionGroup) and e.exceptions:
        e = e.exceptions[0]
    text = str(e) or type(e).__name__
    if isinstance(e, TimeoutError):
        text = "no answer within the time limit"
    if hide:
        text = text.replace(hide, "<url>")
    text = " ".join(text.split())
    return text if len(text) <= 200 else text[:197] + "..."


async def probe_upstream(up: cfg.Upstream, timeout: float) -> list[str]:
    """Connect like ``serve`` does, initialize, list tools, disconnect."""
    from mcp.client.session import ClientSession
    with anyio.fail_after(timeout):
        if up.command:
            from mcp.client.stdio import StdioServerParameters, stdio_client
            params = StdioServerParameters(command=up.command, args=up.args, env={**os.environ, **up.env}, cwd=up.cwd)
            with open(os.devnull, "w") as quiet:
                async with stdio_client(params, errlog=quiet) as (r, w):
                    async with ClientSession(r, w) as s:
                        await s.initialize()
                        return [tool.name for tool in (await s.list_tools()).tools]
        from mcp.client.streamable_http import streamable_http_client
        async with streamable_http_client(up.url) as streams:
            async with ClientSession(streams[0], streams[1]) as s:
                await s.initialize()
                return [tool.name for tool in (await s.list_tools()).tools]


def _check_audit(conf: cfg.Config, path: str, rep: Report):
    key = conf.audit_key
    if not key.exists():
        rep.add(ERROR, "audit key", f"missing: {key} – run `torwaechter keygen --config {path}` once")
    else:
        try:
            audit.load_private(key)
            rep.add(OK, "audit key", f"{key}")
        except Exception as e:  # noqa: BLE001 – any parse error is a broken key file
            rep.add(ERROR, "audit key", f"unusable: {key} ({_reason(e)}) – restore it from backup; a new key cannot verify old entries")
        pub = Path(str(key) + ".pub")
        if not pub.exists():
            rep.add(WARN, "audit key", f"public key missing: {pub} – `verify-log` needs it; restore it from backup")
    folder = conf.audit_log.parent
    while not folder.exists() and folder != folder.parent:  # the log creates missing folders itself
        folder = folder.parent
    if not folder.is_dir() or not os.access(folder, os.W_OK) or (conf.audit_log.exists() and not os.access(conf.audit_log, os.W_OK)):
        rep.add(ERROR, "audit log", f"not writable: {conf.audit_log} – fix permissions or audit.log")
    else:
        rep.add(OK, "audit log", f"{conf.audit_log}" + ("" if conf.audit_log.exists() else " (created on first call)"))


def _check_http(conf: cfg.Config, rep: Report):
    if conf.http_token_file is None:
        rep.add(OK, "http", "no token_file – HTTP transport only on loopback (127.0.0.1); stdio unaffected")
        return
    try:
        httpauth.load_token(conf.http_token_file)  # value is never printed
        rep.add(OK, "http", f"token_file readable, length ok: {conf.http_token_file}")
    except httpauth.HttpAuthError as e:
        rep.add(ERROR, "http", f"{e} – write a random token of {httpauth.MIN_TOKEN}+ characters into that file")


def _check_confirm(conf: cfg.Config, rep: Report):
    from .confirm import Confirmer, PendingRegistry
    try:
        Confirmer(PendingRegistry(), conf.timeout_seconds, conf.elicitation, bool(conf.web), conf.webhook)
    except OSError as e:
        rep.add(ERROR, "confirm", f"confirm.webhook.token_file not readable ({e.strerror})")
        return
    except Exception as e:  # noqa: BLE001
        rep.add(ERROR, "confirm", _reason(e))
        return
    channels = [n for n, on in (("elicitation", conf.elicitation), ("web", bool(conf.web)), ("webhook", bool(conf.webhook))) if on]
    if not channels:
        rep.add(WARN, "confirm", "no approval channel – every `confirm` call will be denied; enable confirm.web or confirm.webhook")
    elif channels == ["elicitation"]:
        rep.add(WARN, "confirm", "only elicitation – clients without elicitation support get every `confirm` call denied; consider confirm.web")
    else:
        rep.add(OK, "confirm", f"channels: {', '.join(channels)}; timeout {conf.timeout_seconds:g}s (timeout = denial)")


def _check_privacy(conf: cfg.Config, rep: Report):
    from .schleuse import Schleuse
    try:
        s = Schleuse.from_config(conf.schleuse, conf.base or Path.cwd())
    except OSError as e:
        rep.add(ERROR, "schleuse", f"names_file not readable: {e.filename} ({e.strerror})")
    except Exception as e:  # noqa: BLE001 – unknown detector, bad label, bad regex
        rep.add(ERROR, "schleuse", f"{_reason(e)} – fix the schleuse: section")
    else:
        rep.add(OK, "schleuse", "off" if s is None else f"on: {', '.join(s.detect)}" + (f", {len(s.names)} name(s)" if s.names else "")
                + (f", {len(s.patterns)} pattern(s)" if s.patterns else ""))
    try:
        redact.load(conf.redact_hook)
        rep.add(OK, "redact", f"hook {conf.redact_hook}" if conf.redact_hook else "no hook")
    except Exception as e:  # noqa: BLE001
        rep.add(ERROR, "redact", f"hook {conf.redact_hook!r} not loadable ({_reason(e)})")


async def _check_upstreams(conf: cfg.Config, rep: Report, probe: Probe, timeout: float):
    public: set[str] = set()
    reached = True
    for name, up in conf.upstreams.items():
        where = f"command {up.command!r}" if up.command else safe_url(up.url)
        problem = None if up.command else url_problem(up.url)
        if problem:
            reached = False
            rep.add(ERROR, "upstream", f"{name} ({where}): {problem} – fix upstreams.{name}.url, e.g. http://127.0.0.1:9000/mcp")
            continue
        try:
            tools = await probe(up, timeout)
        except Exception as e:  # noqa: BLE001
            reached = False
            rep.add(ERROR, "upstream", f"{name} ({where}) not reachable: {_reason(e, up.url)} – check command/url and that the server runs")
            continue
        rep.add(OK, "upstream", f"{name} ({where}): {len(tools)} tool(s)")
        public.update(f"{name}__{tn}" if conf.prefixed else tn for tn in tools)
    if not reached:
        rep.add(WARN, "rules", "tool names not checked (an upstream is not reachable)")
        return
    unmatched = sorted(n for n in conf.tool_rules if n not in public)
    for n in unmatched:
        rep.add(WARN, "rules", f"rule {n!r} matches no tool – it does nothing (a `deny` falls back to the default)")
    for n, r in sorted(conf.tool_rules.items()):
        if r.readback and r.readback.tool not in public:
            rep.add(WARN, "rules", f"read-back of {n!r} uses unknown tool {r.readback.tool!r} – read-back will report `unklar`")
    if not unmatched:
        rep.add(OK, "rules", f"all {len(conf.tool_rules)} tool rule(s) match a tool")


def run(path: str, probe: Probe | None = None, timeout: float = DEFAULT_TIMEOUT) -> tuple[int, str]:
    rep = Report()
    try:
        conf = cfg.load(path)
    except FileNotFoundError:
        rep.add(ERROR, "config", f"file not found: {path}")
        return 2, rep.render()
    except cfg.ConfigError as e:
        rep.add(ERROR, "config", f"{e} – fix {path}")
        return 2, rep.render()
    except Exception as e:  # noqa: BLE001 – YAML syntax, wrong types
        rep.add(ERROR, "config", f"cannot read {path}: {_reason(e)}")
        return 2, rep.render()
    rep.add(OK, "config", f"{path}: {len(conf.upstreams)} upstream(s), {len(conf.tool_rules)} tool rule(s), actions valid")
    _check_audit(conf, path, rep)
    _check_http(conf, rep)
    _check_confirm(conf, rep)
    _check_privacy(conf, rep)
    anyio.run(_check_upstreams, conf, rep, probe or probe_upstream, timeout)
    return (2 if rep.errors else 0), rep.render()


def main(path: str, timeout: float = DEFAULT_TIMEOUT) -> int:
    code, text = run(path, timeout=timeout)
    print(text)
    sys.stdout.flush()
    return code
