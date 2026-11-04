"""``lookfirst serve --config lookfirst.yaml [--transport stdio|http] [--host] [--port]``
``lookfirst keygen --config …``      create the Ed25519 audit key (once)
``lookfirst verify-log --config …``  verify the audit log (hash chain + signatures + head)
``lookfirst check --config … [--timeout S]``  check configuration, key, token file, upstreams; gate not started (exit 2 on ERROR)
``lookfirst demo [--yes|--no] [--keep DIR]``  run the offline bank demo (see demo/VIDEO.md)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import anyio

from . import audit, config as cfg, httpauth, redact
from .confirm import Confirmer, PendingRegistry


def _gate(conf: cfg.Config):
    from .proxy import Gate
    from .upstream import Upstreams
    if not conf.audit_key.exists():
        raise SystemExit(f"audit key missing: {conf.audit_key} – run `lookfirst keygen --config …` first")
    log = audit.AuditLog(conf.audit_log, audit.load_private(conf.audit_key))
    registry = PendingRegistry()
    confirmer = Confirmer(registry, conf.timeout_seconds, conf.elicitation, bool(conf.web), conf.webhook)
    hook = redact.load(conf.redact_hook)
    return conf, Upstreams(conf), log, registry, confirmer, hook, Gate


async def serve(conf: cfg.Config, transport: str, host: str, port: int):
    import uvicorn
    if conf.elicitation:
        print("[lookfirst] WARNING: autonomous clients can self-approve elicitation; "
              "set confirm.elicitation: false and isolate the human approval channel", file=sys.stderr)
    token = None
    if transport == "http":  # #668 P2: check before any upstream starts
        try:
            token = httpauth.load_token(conf.http_token_file)
            httpauth.check_bind(host, token)
        except httpauth.HttpAuthError as e:
            raise SystemExit(f"[lookfirst] {e}") from None
    conf, ups, log, registry, confirmer, hook, Gate = _gate(conf)
    async with ups:
        gate = Gate(conf, ups, log, confirmer, hook)
        for name in gate.unmatched_rules():
            print(f"[lookfirst] WARNING: rule for {name!r} matches no upstream tool (known: {', '.join(t.name for t in ups.list_tools())})", file=sys.stderr)
        server = gate.server()
        web = None
        async with anyio.create_task_group() as tg:
            if conf.web:
                from .web import create_app
                wh, wp = conf.web.get("host", "127.0.0.1"), int(conf.web.get("port", 8477))
                web = uvicorn.Server(uvicorn.Config(create_app(registry, confirmer, hook, wh, wp, conf.web.get("identity_header")), host=wh, port=wp, log_level="warning"))
                tg.start_soon(web.serve)
                print(f"[lookfirst] approval page: http://{conf.web.get('host', '127.0.0.1')}:{conf.web.get('port', 8477)}/", file=sys.stderr)
            if transport == "stdio":
                from mcp.server.stdio import stdio_server
                async with stdio_server() as (r, w):
                    await server.run(r, w, server.create_initialization_options())
            else:
                app = httpauth.guard(server.streamable_http_app(host=host, json_response=True), token)
                if token is None:
                    print("[lookfirst] WARNING: HTTP without token – every local process can call tools; set http.token_file", file=sys.stderr)
                await uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning")).serve()
            if web is not None:
                web.should_exit = True  # clean shutdown of the approval page when the client disconnects


def main(argv=None):
    p = argparse.ArgumentParser(prog="lookfirst", description="Gatekeeper between AI agents and tools (MCP proxy).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve"); s.add_argument("--config", required=True); s.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8470)
    k = sub.add_parser("keygen"); k.add_argument("--config", required=True)
    v = sub.add_parser("verify-log"); v.add_argument("--config", required=True)
    c = sub.add_parser("check", help="check configuration, audit key, token file and upstreams without starting the gate")
    c.add_argument("--config", required=True); c.add_argument("--timeout", type=float, default=10.0, help="seconds per upstream (default 10)")
    ps = sub.add_parser("pilot-status", help="evaluate launch gate criteria from audit log")
    ps.add_argument("--config", required=True); ps.add_argument("--json", action="store_true", help="output JSON only")
    d = sub.add_parser("demo"); d.add_argument("--yes", action="store_true", help="approve the transfer without asking (scripted run)")
    d.add_argument("--no", action="store_true", help="deny the transfer without asking"); d.add_argument("--keep", help="keep working files in this directory (for verify-log afterwards)")
    a = p.parse_args(argv)
    if a.cmd == "keygen":
        conf = cfg.load(a.config)
        if conf.audit_key.exists():
            raise SystemExit(f"key exists: {conf.audit_key} (not overwritten)")
        audit.generate_key(conf.audit_key)
        print(f"created {conf.audit_key} (0600) and {conf.audit_key}.pub")
        return 0
    if a.cmd == "verify-log":
        conf = cfg.load(a.config)
        verdict = audit.verify(conf.audit_log, audit.load_public(Path(str(conf.audit_key) + ".pub")))
        ok, problems, n = verdict
        print(f"{'OK' if ok else 'TAMPERED'}: {n} entries, {len(problems)} problem(s)" + (f", {len(verdict.warnings)} warning(s)" if verdict.warnings else ""))
        for pr in problems:
            print(f"  line {pr.line}: {pr.reason}")
        for w in verdict.warnings:
            print(f"  warning: {w}")
        return 0 if ok else 2
    if a.cmd == "check":
        from .check import main as check_main
        return check_main(a.config, a.timeout)
    if a.cmd == "pilot-status":
        import json
        from .pilot import evaluate_pilot_status
        conf = cfg.load(a.config)
        report = evaluate_pilot_status(conf)
        if a.json:
            print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        else:
            print(report.render_combined())
        return 0
    if a.cmd == "demo":
        from .demo import run_demo
        return run_demo("y" if a.yes else "n" if a.no else None, a.keep)
    anyio.run(serve, cfg.load(a.config), a.transport, a.host, a.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
