"""Scripted offline demo (``lookfirst demo``): starts the fake bank, puts the gate in front of it, and plays an MCP client
that (1) reads the balance – passes through, (2) tries a transfer – you approve or deny in the terminal, (3) shows the
read-back verdict and (4) verifies the audit log, then tampers with one line and verifies again. ~60 seconds."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

import anyio
import mcp.types as t
from mcp.client.session import ClientSession
from mcp.shared.memory import create_client_server_memory_streams

from . import audit, config as cfg, redact
from .confirm import Confirmer, PendingRegistry
from .proxy import Gate
from .upstream import Upstreams

DEMO_DIR = Path(__file__).resolve().parent.parent / "demo"


def say(msg):
    print(f"\n▶ {msg}", flush=True)


def find_decision_index(lines: list[str]) -> int:
    """Find the 0-based index of the decision entry to tamper with.
    Prefers 'decision' for tool 'ueberweisung', falls back to any 'decision'.
    Raises RuntimeError if no decision entry exists."""
    for idx, l in enumerate(lines):
        item = json.loads(l)
        if item.get("event") == "decision" and item.get("tool") == "ueberweisung":
            return idx
    for idx, l in enumerate(lines):
        item = json.loads(l)
        if item.get("event") == "decision":
            return idx
    raise RuntimeError("Audit log contains no 'decision' entry to tamper with")


async def _run(workdir: Path, answer: str | None = None):
    """``answer``: None = ask in the terminal; "y"/"n" = scripted (recordings, CI)."""
    shutil.copy(DEMO_DIR / "bank_server.py", workdir / "bank_server.py")
    shutil.copy(DEMO_DIR / "lookfirst.yaml", workdir / "lookfirst.yaml")
    shutil.copy(DEMO_DIR / "namen.txt", workdir / "namen.txt")
    conf = cfg.load(workdir / "lookfirst.yaml")
    conf.web = None
    audit.generate_key(conf.audit_key)
    log = audit.AuditLog(conf.audit_log, audit.load_private(conf.audit_key))
    confirmer = Confirmer(PendingRegistry(), conf.timeout_seconds, True, False, None)

    async def ask_terminal(ctx, params):
        print("\n┌─ lookfirst asks ─────────────────────────────")
        print("│ " + params.message.replace("\n", "\n│ "))
        print("└───────────────────────────────────────────────")
        if answer is None:
            ans = await anyio.to_thread.run_sync(lambda: input("Approve? [y/N] ").strip().lower())
        else:
            ans = answer
            print(f"Approve? [y/N] {ans}   (scripted)")
        return t.ElicitResult(action="accept", content={"approve": ans == "y"})

    async with Upstreams(conf) as ups:
        gate = Gate(conf, ups, log, confirmer, redact.identity)
        server = gate.server()
        async with create_client_server_memory_streams() as ((cr, cw), (sr, sw)):
            async with anyio.create_task_group() as tg:
                tg.start_soon(server.run, sr, sw, server.create_initialization_options())
                async with ClientSession(cr, cw, elicitation_callback=ask_terminal) as cs:
                    await cs.initialize()
                    say("Tools behind the gate: " + ", ".join(x.name for x in (await cs.list_tools()).tools))
                    say("1) Read-only call `kontostand` → passes through without questions")
                    r = await cs.call_tool("kontostand", {})
                    print("   ", r.content[0].text, "| gate:", r.structured_content["lookfirst"]["status"])
                    say("2) Writing call `ueberweisung` → preview, your decision, execution, read-back")
                    r = await cs.call_tool("ueberweisung", {"an": "Demo GmbH", "betrag": 120.5, "zweck": "Rechnung 42"})
                    g = r.structured_content["lookfirst"]
                    print("   ", r.content[0].text, "| gate:", json.dumps(g, ensure_ascii=False))
                    say("3) Balance after: " + (await cs.call_tool("kontostand", {})).content[0].text)
                    if gate._make_schleuse is not None:
                        say("3b) Schleuse: the bank lists transactions – what the AI client actually receives:")
                        r = await cs.call_tool("umsaetze", {})
                        print("   ", r.content[0].text)
                        tok = r.structured_content["umsaetze"][0]["iban"]
                        print(f"    The model only sees {tok}. Using it in a call works locally (resolved inside the gate),")
                        print("    an invented placeholder is refused:", (await cs.call_tool("umsaetze", {"x": "[[IBAN_000000]]"})).content[0].text)
                tg.cancel_scope.cancel()
    pub = audit.load_public(Path(str(conf.audit_key) + ".pub"))
    ok, problems, n = audit.verify(conf.audit_log, pub)
    say(f"4) verify-log: {'OK' if ok else 'TAMPERED'} – {n} signed, chained entries in {conf.audit_log.name}")
    for line in conf.audit_log.read_text(encoding="utf-8").splitlines():
        e = json.loads(line)
        print(f"    #{e['seq']} {e['event']:<9} {e['tool']:<13} {e['decision']:<8} {e['by']:<12} {e['readback']:<6} {e['note'][:40]}")
    lines = conf.audit_log.read_text(encoding="utf-8").splitlines()
    target_idx = find_decision_index(lines)
    target_seq = target_idx + 1
    say(f"5) Someone rewrites entry #{target_seq} – the decision – so it looks as if a human never approved …")
    e = json.loads(lines[target_idx])
    e["by"] = "auto"
    e["note"] = "approved automatically"
    lines[target_idx] = json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    conf.audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, problems, n = audit.verify(conf.audit_log, pub)
    print(f"    verify-log: {'OK' if ok else 'TAMPERED'} – " + "; ".join(f"line {p.line}: {p.reason}" for p in problems))
    say(f"Done. Working files are in {workdir} – try: lookfirst verify-log --config {workdir / 'lookfirst.yaml'}")


def run_demo(answer: str | None = None, keep: str | None = None) -> int:
    """``answer`` "y"/"n" skips the terminal question (scripted run); ``keep`` is a directory that is left behind afterwards so
    the real CLI (``lookfirst verify-log --config <keep>/lookfirst.yaml``) can be shown on the tampered log."""
    try:
        if keep:
            d = Path(keep); d.mkdir(parents=True, exist_ok=True)
            anyio.run(_run, d, answer)
        else:
            with tempfile.TemporaryDirectory(prefix="lookfirst-demo-") as d:
                anyio.run(_run, Path(d), answer)
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"demo error: {e}", file=sys.stderr)
        return 1
    return 0
