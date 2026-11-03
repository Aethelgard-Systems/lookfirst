"""Torwächter V1 tests – synthetic data, in-memory MCP client/servers. Run: python -m unittest discover tests"""
from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path

import anyio
import mcp.types as t

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.helpers import DEFAULT_RULES, GateHarness, bank_server  # noqa: E402
from torwaechter import audit, config as cfg, readback, rules  # noqa: E402
from torwaechter.config import Readback  # noqa: E402


def run(coro):
    return anyio.run(lambda: coro)


def accept(approve: bool, delay: float = 0):
    async def cb(ctx, params):
        if delay:
            await anyio.sleep(delay)
        return t.ElicitResult(action="accept", content={"approve": approve})
    return cb


def gate_of(res):
    return res.structured_content["torwaechter"]


class RulesTest(unittest.TestCase):
    def test_defaults_and_explicit_rules(self):
        h = GateHarness(); self.addCleanup(h.close)
        c = h.conf
        self.assertEqual(rules.decide(c, "kontostand", t.ToolAnnotations(readOnlyHint=True)), ("allow", "default:read_only"))
        self.assertEqual(rules.decide(c, "x", t.ToolAnnotations(destructiveHint=True)), ("confirm", "default:destructive"))
        self.assertEqual(rules.decide(c, "x", None), ("confirm", "default:unknown"))
        self.assertEqual(rules.decide(c, "x", t.ToolAnnotations(destructiveHint=False)), ("confirm", "default:non_destructive_write"))
        self.assertEqual(rules.decide(c, "loeschen", t.ToolAnnotations(readOnlyHint=True)), ("deny", "rule:loeschen"))  # rule beats annotation
        self.assertEqual(rules.decide(c, "ueberweisung", None), ("confirm", "rule:ueberweisung"))

    def test_config_validation(self):
        h = GateHarness(); self.addCleanup(h.close)
        bad = Path(h.dir, "bad.yaml")
        bad.write_text("upstreams: {a: {command: x, url: y}}", encoding="utf-8")
        with self.assertRaises(cfg.ConfigError):
            cfg.load(bad)
        bad.write_text("upstreams: {a: {command: x}}\nrules: {default: {read_only: maybe}}", encoding="utf-8")
        with self.assertRaises(cfg.ConfigError):
            cfg.load(bad)
        bad.write_text("upstreams: {}", encoding="utf-8")
        with self.assertRaises(cfg.ConfigError):
            cfg.load(bad)


Z = "0" * 64  # synthetic args_sha256 of hand-made previews


class GateTest(unittest.TestCase):
    def setUp(self):
        self.h = GateHarness(); self.addCleanup(self.h.close)

    def test_read_calls_pass_through_unchanged(self):
        async def go():
            async with self.h.client(accept(True)) as (cs, ups):
                direct = await ups["bank"].call_tool("kontostand", {})
                via = await cs.call_tool("kontostand", {})
                self.assertEqual([c.text for c in via.content], [c.text for c in direct.content])
                self.assertEqual({k: v for k, v in via.structured_content.items() if k != "torwaechter"}, direct.structured_content)
                self.assertEqual(gate_of(via)["status"], "allowed")
                self.assertEqual([x.name for x in (await cs.list_tools()).tools], ["kontostand", "ueberweisung", "notiz", "loeschen"])
        run(go())
        events = [json.loads(l)["event"] for l in self.h.conf.audit_log.read_text().splitlines()]
        self.assertEqual(events, ["allow", "execution_started", "result", "execution_resolved"])

    def test_approve_executes_and_reads_back_ok(self):
        async def go():
            async with self.h.client(accept(True)) as (cs, _):
                r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 25})
                g = gate_of(r)
                self.assertEqual((g["status"], g["approved_by"].split(":")[0], g["readback"]), ("executed", "elicitation", "ok"))  # v1.1: elicitation:<client>
                self.assertFalse(r.is_error)
        run(go())
        self.assertEqual(self.h.state["calls"], [("ueberweisung", {"an": "Demo", "betrag": 25})]); self.assertEqual(self.h.state["saldo"], 75.0)
        entries = [json.loads(l) for l in self.h.conf.audit_log.read_text().splitlines()]
        self.assertEqual([e["event"] for e in entries], ["preview", "decision", "execution_started", "result", "readback", "execution_resolved"])
        self.assertEqual(entries[0]["summary"], "Transfer 25 EUR to Demo"); self.assertEqual(entries[1]["decision"], "approve"); self.assertEqual(next(e for e in entries if e["event"] == "readback")["readback"], "ok")
        self.assertTrue(self.h.verify()[0])

    def test_deny_by_human_does_not_execute(self):
        async def go():
            async with self.h.client(accept(False)) as (cs, _):
                r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 25})
                self.assertTrue(r.is_error); self.assertEqual(gate_of(r)["status"], "denied")
        run(go())
        self.assertEqual(self.h.state["calls"], []); self.assertEqual(self.h.state["saldo"], 100.0)
        entries = [json.loads(l) for l in self.h.conf.audit_log.read_text().splitlines()]
        self.assertEqual([(e["event"], e["decision"]) for e in entries], [("preview", "confirm"), ("decision", "deny")])

    def test_timeout_is_a_denial(self):
        async def go():
            async with self.h.client(accept(True, delay=2.0)) as (cs, _):
                r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 25})
                self.assertTrue(r.is_error); self.assertIn("timeout", gate_of(r)["reason"])
        run(go())
        self.assertEqual(self.h.state["calls"], [])
        self.assertEqual(json.loads(self.h.conf.audit_log.read_text().splitlines()[1])["by"], "timeout")

    def test_deny_rule_and_unknown_tool_default_confirm(self):
        async def go():
            async with self.h.client(accept(True)) as (cs, _):
                r = await cs.call_tool("loeschen", {})
                self.assertTrue(r.is_error); self.assertEqual(gate_of(r)["reason"], "rule:loeschen")
                r = await cs.call_tool("notiz", {"text": "x"})  # no annotations → confirm → approved
                self.assertEqual((gate_of(r)["status"], gate_of(r)["readback"]), ("executed", "none"))
                r = await cs.call_tool("gibtsnicht", {})
                self.assertTrue(r.is_error)
        run(go())
        self.assertEqual(self.h.state["calls"], [("notiz", {"text": "x"})])

    def test_readback_failed_is_reported_never_silent(self):
        async def go():
            async with self.h.client(accept(True), servers={"bank": bank_server(self.h.state, lie=True)}) as (cs, _):
                r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 25})
                g = gate_of(r)
                self.assertEqual((g["status"], g["readback"]), ("executed", "fehlgeschlagen")); self.assertIn("saldo", g["readback_detail"])
        run(go())
        self.assertEqual(json.loads(self.h.conf.audit_log.read_text().splitlines()[-1])["readback"], "fehlgeschlagen")

    def test_no_elicitation_and_no_channel_denies(self):
        async def go():
            async with self.h.client(None) as (cs, _):  # client without elicitation capability
                r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 25})
                self.assertTrue(r.is_error); self.assertIn("no confirmation channel", gate_of(r)["reason"])
        run(go())
        self.assertEqual(self.h.state["calls"], [])

    def test_web_channel_and_webhook_decision(self):
        posted = []

        class Resp(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): pass

        def opener(req, timeout):
            posted.append(json.loads(req.data)); return Resp(b"{}")
        h = GateHarness(webhook={"url": "https://braucht-dich.invalid/hook"}, web_enabled=True, opener=opener); self.addCleanup(h.close)
        h.confirmer.timeout = 3

        async def go():
            async with h.client(None) as (cs, _):
                async def approve_later():
                    while not posted:
                        await anyio.sleep(0.01)
                    cid = posted[0]["id"]
                    self.assertEqual(h.registry.list_open()[0]["id"], cid)
                    self.assertFalse(h.registry.decide(cid, True, "webhook")) if False else None
                    h.registry.decide(cid, True, "webhook", "ok from Braucht dich")
                async with anyio.create_task_group() as tg:
                    tg.start_soon(approve_later)
                    r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 5})
                self.assertEqual((gate_of(r)["status"], gate_of(r)["approved_by"]), ("executed", "webhook"))
                self.assertEqual(h.registry.list_open(), [])
                self.assertFalse(h.registry.decide(posted[0]["id"], True, "web"))  # closed: no second decision
        run(go())
        self.assertEqual(posted[0]["tool"], "ueberweisung"); self.assertIn("token", posted[0])

    def test_two_upstreams_are_prefixed(self):
        h = GateHarness(upstreams={"bank": {"command": "true"}, "crm": {"command": "true"}},
                        rules={"default": DEFAULT_RULES["default"], "tools": {"bank__ueberweisung": {"action": "confirm", "readback": {"tool": "bank__kontostand", "expect": {"saldo": "$result.saldo"}}}}})
        self.addCleanup(h.close)
        other = {"saldo": 1.0, "calls": []}

        async def go():
            async with h.client(accept(True), servers={"bank": bank_server(h.state), "crm": bank_server(other)}) as (cs, _):
                names = [x.name for x in (await cs.list_tools()).tools]
                self.assertIn("bank__kontostand", names); self.assertIn("crm__ueberweisung", names)
                r = await cs.call_tool("bank__ueberweisung", {"an": "x", "betrag": 1})
                self.assertEqual(gate_of(r)["readback"], "ok")
                self.assertEqual(gate_of(await cs.call_tool("crm__kontostand", {}))["status"], "allowed")
        run(go())
        self.assertEqual(len(h.state["calls"]), 1); self.assertEqual(other["calls"], [])


    def test_audit_nacht04_redaction_reaches_log_channel_and_client_text(self):
        """Self-audit: the redaction hook runs once and its output is what the audit log, the human channel and the
        client-visible text see; the raw argument only reaches the upstream. Rules naming unknown tools are reported."""
        secret = "GEHEIM-4711"
        seen = []

        def hook(preview):
            return {**preview, "summary": preview["summary"].replace(secret, "[redacted]"), "arguments": {k: "[redacted]" for k in preview["arguments"]}}

        async def cb(ctx, params):
            seen.append(params.message)
            return t.ElicitResult(action="accept", content={"approve": True})
        h = GateHarness(rules={"default": DEFAULT_RULES["default"], "tools": {"ueberweisung": {"action": "confirm", "summary": "Transfer {betrag} EUR to {an}"}, "tippfehler": {"action": "deny"}}})
        self.addCleanup(h.close)

        async def go():
            async with h.client(cb, hook=hook) as (cs, _):
                self.assertEqual(h.gate.unmatched_rules(), ["tippfehler"])
                r = await cs.call_tool("ueberweisung", {"an": secret, "betrag": 1})
                self.assertEqual(gate_of(r)["status"], "executed")
        run(go())
        self.assertEqual(h.state["calls"], [("ueberweisung", {"an": secret, "betrag": 1})])  # upstream got the real value
        self.assertNotIn(secret, h.conf.audit_log.read_text()); self.assertNotIn(secret, "".join(seen)); self.assertIn("[redacted]", seen[0])
        self.assertIn("Transfer 1 EUR to [redacted]", h.conf.audit_log.read_text())

    def test_audit_nacht04_webhook_endpoint_rejects_bad_json_and_oversize(self):
        from starlette.testclient import TestClient
        from torwaechter import redact
        from torwaechter.web import create_app
        h = GateHarness(webhook={"url": "https://braucht-dich.invalid/hook"}, web_enabled=True, opener=lambda req, timeout: io.BytesIO(b"{}")); self.addCleanup(h.close)
        c = TestClient(create_app(h.registry, h.confirmer, redact.identity), base_url="http://127.0.0.1:8477")
        self.assertEqual(c.post("/decision/tw-x", content=b"{not json").status_code, 400)
        self.assertEqual(c.post("/decision/tw-x", content=b"[1]").status_code, 403)  # Objekt ohne Token
        self.assertEqual(c.post("/decision/tw-x", content=b'{"token":"' + b"x" * 70000 + b'"}').status_code, 400)
        self.assertEqual(c.post("/decision/tw-x", json={"token": h.confirmer.call_token("tw-x"), "decision": "approve"}).status_code, 404)  # unbekannter Aufruf
        self.assertEqual(c.post("/approve/tw-x", data={"csrf": "falsch"}).status_code, 403)

    def test_review304_web_page_refuses_foreign_host_origin_and_per_call_tokens(self):
        """Review #304 P1/P2: DNS-Rebinding (fremder Host) und Cross-Site-Anfragen werden abgewiesen; ein Webhook-Token gilt nur für
        seinen Aufruf; Webhook-URLs müssen https sein."""
        from starlette.testclient import TestClient
        from torwaechter import redact
        from torwaechter.confirm import Confirmer
        from torwaechter.web import create_app
        h = GateHarness(webhook={"url": "https://braucht-dich.invalid/hook"}, web_enabled=True, opener=lambda req, timeout: io.BytesIO(b"{}")); self.addCleanup(h.close)
        c = TestClient(create_app(h.registry, h.confirmer, redact.identity, "127.0.0.1", 8477), base_url="http://127.0.0.1:8477", follow_redirects=False)
        p1 = h.registry.open({"id": "tw-1", "tool": "ueberweisung", "arguments": {"an": "x"}, "summary": "s", "args_sha256": "0" * 64, "action": "confirm", "reason": "r"})
        page = c.get("/"); self.assertEqual(page.status_code, 200)
        csrf = page.text.split('name="csrf" value="')[1].split('"')[0]
        # DNS-Rebinding: Host nennt eine fremde Seite → kein Token, keine Freigabe, keine Vorschau
        self.assertEqual(c.get("/", headers={"host": "evil.example:8477"}).status_code, 403)
        self.assertEqual(c.get("/open", headers={"host": "evil.example"}).status_code, 403)
        self.assertEqual(c.post("/approve/tw-1", data={"csrf": csrf}, headers={"host": "evil.example:8477"}).status_code, 403)
        self.assertEqual(c.post("/approve/tw-1", data={"csrf": csrf}, headers={"origin": "http://evil.example"}).status_code, 403)
        self.assertEqual(c.post("/approve/tw-1", data={"csrf": csrf}, headers={"sec-fetch-site": "cross-site"}).status_code, 403)
        self.assertIsNone(p1.decision)
        # eigener Origin + CSRF: Freigabe
        self.assertEqual(c.post("/approve/tw-1", data={"csrf": csrf, "args_sha256": Z}, headers={"origin": "http://127.0.0.1:8477", "sec-fetch-site": "same-origin"}).status_code, 400)  # v1.1: Name Pflicht
        self.assertEqual(c.post("/approve/tw-1", data={"csrf": csrf, "actor": "marco", "args_sha256": Z}, headers={"origin": "http://127.0.0.1:8477", "sec-fetch-site": "same-origin"}).status_code, 303)
        self.assertTrue(p1.decision.approved); self.assertEqual((p1.decision.actor, p1.decision.label, p1.decision.note), ("marco", "web:marco", "self-declared"))
        # Token je Aufruf: das Token von tw-2 öffnet tw-3 nicht
        h.registry.open({"id": "tw-2", "tool": "t", "arguments": {}, "summary": "s", "args_sha256": "0" * 64, "action": "confirm", "reason": "r"})
        h.registry.open({"id": "tw-3", "tool": "t", "arguments": {}, "summary": "s", "args_sha256": "0" * 64, "action": "confirm", "reason": "r"})
        self.assertEqual(c.post("/decision/tw-3", json={"token": h.confirmer.call_token("tw-2"), "decision": "approve"}).status_code, 403)
        self.assertEqual(c.post("/decision/tw-3", json={"token": h.confirmer.webhook_secret, "decision": "approve"}).status_code, 403)  # Geheimnis selbst gilt nie
        self.assertEqual(c.post("/decision/tw-3", json={"token": h.confirmer.call_token("tw-3"), "decision": "approve", "args_sha256": Z}).status_code, 200)
        # Webhook-URL: nur https (http nur loopback)
        with self.assertRaises(ValueError):
            Confirmer(h.registry, 1, False, False, {"url": "http://braucht-dich.invalid/hook"})
        Confirmer(h.registry, 1, False, False, {"url": "http://127.0.0.1:9/hook"})


    def test_v11_identitaet_des_freigebenden_in_allen_kanaelen(self):
        """v1.1 (#291, Compliance-Lücke aus #355): wer entschieden hat, steht als ``kanal:akteur`` im Protokoll und in der Antwort –
        Web: SSO-Header (verifiziert) oder Formularname (self-declared); Webhook: ``actor`` im Body; Elicitation: MCP-Client-Name."""
        from starlette.testclient import TestClient
        from torwaechter import redact
        from torwaechter.web import create_app
        h = GateHarness(webhook={"url": "https://braucht-dich.invalid/hook"}, web_enabled=True, opener=lambda req, timeout: io.BytesIO(b"{}")); self.addCleanup(h.close)
        # Web mit SSO-Header: Formularname zählt nicht, Header zählt; bösartige Header-Werte werden verworfen → 400
        c = TestClient(create_app(h.registry, h.confirmer, redact.identity, "127.0.0.1", 8477, identity_header="X-Forwarded-User"), base_url="http://127.0.0.1:8477", follow_redirects=False)
        p1 = h.registry.open({"id": "tw-1", "tool": "t", "arguments": {}, "summary": "s", "args_sha256": "0" * 64, "action": "confirm", "reason": "r"})
        page = c.get("/", headers={"x-forwarded-user": "marco@example"}); csrf = page.text.split('name="csrf" value="')[1].split('"')[0]
        self.assertIn("Signed in as <b>marco@example</b>", page.text); self.assertNotIn('id="actor"', page.text)
        self.assertEqual(c.post("/approve/tw-1", data={"csrf": csrf, "actor": "faker", "args_sha256": Z}).status_code, 400)  # kein Header → kein Akteur
        self.assertEqual(c.post("/approve/tw-1", data={"csrf": csrf, "args_sha256": Z}, headers={"x-forwarded-user": "<script>"}).status_code, 400)
        self.assertEqual(c.post("/approve/tw-1", data={"csrf": csrf, "actor": "faker", "args_sha256": Z}, headers={"x-forwarded-user": "marco@example"}).status_code, 303)
        self.assertEqual((p1.decision.label, p1.decision.note), ("web:marco@example", ""))
        # Webhook: actor aus dem Body
        h.registry.open({"id": "tw-2", "tool": "t", "arguments": {}, "summary": "s", "args_sha256": "0" * 64, "action": "confirm", "reason": "r"})
        self.assertEqual(c.post("/decision/tw-2", json={"token": h.confirmer.call_token("tw-2"), "decision": "approve", "actor": "braucht-dich/MARCO", "args_sha256": Z}).status_code, 200)
        self.assertEqual(h.registry.items["tw-2"].decision.label, "webhook:braucht-dich/MARCO")
        # Elicitation: Client-Name landet im Protokoll als elicitation:<client>
        async def go():
            async with self.h.client(accept(True)) as (cs, _):
                r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 1})
                self.assertTrue(gate_of(r)["approved_by"].startswith("elicitation:"), gate_of(r))
        run(go())
        entries = [json.loads(l) for l in self.h.conf.audit_log.read_text().splitlines()]
        self.assertTrue(entries[1]["by"].startswith("elicitation:") and len(entries[1]["by"]) > len("elicitation:"), entries[1]["by"])


class FreigabeBindungTest(unittest.TestCase):
    """#668 P3: eine Freigabe gilt nur für Ziel, Operation und genau den gezeigten Inhalt. Synthetische Daten."""

    @staticmethod
    def webhook_harness(posted, web_enabled=False):
        class Resp(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): pass

        def opener(req, timeout):
            posted.append(json.loads(req.data)); return Resp(b"{}")
        return GateHarness(webhook={"url": "https://braucht-dich.invalid/hook"}, web_enabled=web_enabled, opener=opener)

    def test_lange_argumente_keine_elicitation_freigabe(self):
        asked = []

        async def cb(ctx, params):
            asked.append(params.message)
            return t.ElicitResult(action="accept", content={"approve": True})
        h = GateHarness(); self.addCleanup(h.close)
        lang = "Verwendungszweck " + "x" * 900  # synthetisch

        async def go():
            async with h.client(cb) as (cs, _):
                r = await cs.call_tool("notiz", {"text": lang})
                self.assertTrue(r.is_error); self.assertEqual(gate_of(r)["status"], "denied")
                self.assertIn("Vorschau zu lang für Elicitation", gate_of(r)["reason"])
                r = await cs.call_tool("notiz", {"text": "kurz"})  # kurze Argumente: Elicitation zeigt sie vollständig
                self.assertEqual(gate_of(r)["status"], "executed")
        run(go())
        self.assertEqual(len(asked), 1); self.assertIn('{"text": "kurz"}', asked[0])  # langer Aufruf wurde nie per Elicitation gefragt
        self.assertEqual(h.state["calls"], [("notiz", {"text": "kurz"})])
        self.assertEqual(json.loads(h.conf.audit_log.read_text().splitlines()[1])["by"], "policy")

    def test_lange_argumente_gehen_an_webhook_statt_elicitation(self):
        posted, asked = [], []

        async def cb(ctx, params):
            asked.append(1)
            return t.ElicitResult(action="accept", content={"approve": True})
        h = self.webhook_harness(posted); self.addCleanup(h.close)
        h.confirmer.timeout = 3
        lang = "y" * 900

        async def go():
            async with h.client(cb) as (cs, _):
                async def decide_later():
                    while not posted:
                        await anyio.sleep(0.01)
                    b = posted[0]
                    self.assertEqual(b["arguments"], {"text": lang})  # Webhook bekommt den vollständigen Inhalt
                    h.registry.decide(b["id"], True, "webhook")
                async with anyio.create_task_group() as tg:
                    tg.start_soon(decide_later)
                    r = await cs.call_tool("notiz", {"text": lang})
                self.assertEqual((gate_of(r)["status"], gate_of(r)["approved_by"]), ("executed", "webhook"))
        run(go())
        self.assertEqual(asked, [])

    def test_webhook_entscheidung_braucht_passenden_args_hash(self):
        from starlette.testclient import TestClient
        from torwaechter import preview as pv, redact
        from torwaechter.web import create_app
        posted = []
        h = self.webhook_harness(posted); self.addCleanup(h.close)
        h.confirmer.timeout = 3
        c = TestClient(create_app(h.registry, h.confirmer, redact.identity, "127.0.0.1", 8477), base_url="http://127.0.0.1:8477")

        async def go():
            async with h.client(None) as (cs, _):
                async def decide_later():
                    while not posted:
                        await anyio.sleep(0.01)
                    b = posted[0]
                    self.assertEqual(b["args_sha256"], pv.args_hash({"an": "Demo", "betrag": 5}))  # Vorschau enthält den Hash
                    base = {"token": b["token"], "decision": "approve"}
                    self.assertEqual(c.post(f"/decision/{b['id']}", json=base).status_code, 403)  # Hash fehlt
                    self.assertEqual(c.post(f"/decision/{b['id']}", json={**base, "args_sha256": pv.args_hash({"an": "Demo", "betrag": 500})}).status_code, 403)
                    self.assertEqual(c.post(f"/decision/{b['id']}", json={**base, "args_sha256": 7}).status_code, 403)
                    self.assertIsNone(h.registry.items[b["id"]].decision)  # 403 = keine Entscheidung
                    self.assertEqual(c.post(f"/decision/{b['id']}", json={**base, "args_sha256": b["args_sha256"]}).status_code, 200)
                async with anyio.create_task_group() as tg:
                    tg.start_soon(decide_later)
                    r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 5})
                self.assertEqual(gate_of(r)["status"], "executed")
        run(go())

    def test_webseite_freigabe_braucht_passenden_args_hash(self):
        from starlette.testclient import TestClient
        from torwaechter import redact
        from torwaechter.web import create_app
        h = GateHarness(web_enabled=True); self.addCleanup(h.close)
        c = TestClient(create_app(h.registry, h.confirmer, redact.identity, "127.0.0.1", 8477), base_url="http://127.0.0.1:8477", follow_redirects=False)
        sha = "a" * 64
        p = h.registry.open({"id": "tw-9", "tool": "ueberweisung", "arguments": {"an": "Demo"}, "summary": "s", "args_sha256": sha, "action": "confirm", "reason": "r"})
        page = c.get("/"); csrf = page.text.split('name="csrf" value="')[1].split('"')[0]
        self.assertIn(f'name="args_sha256" value="{sha}"', page.text)  # die Seite bindet das Formular an den gezeigten Inhalt
        self.assertEqual(c.post("/approve/tw-9", data={"csrf": csrf, "actor": "marco"}).status_code, 403)
        self.assertEqual(c.post("/approve/tw-9", data={"csrf": csrf, "actor": "marco", "args_sha256": "b" * 64}).status_code, 403)
        self.assertIsNone(p.decision)
        self.assertEqual(c.post("/approve/tw-9", data={"csrf": csrf, "actor": "marco", "args_sha256": sha}).status_code, 303)
        self.assertTrue(p.decision.approved)

    def test_geaenderte_argumente_brauchen_neue_freigabe(self):
        """Dieselbe Aktion mit anderen Argumenten: frühere Freigabe (Token + Hash) öffnet sie nicht; nur eine neue Entscheidung."""
        from starlette.testclient import TestClient
        from torwaechter import redact
        from torwaechter.web import create_app
        posted = []
        h = self.webhook_harness(posted); self.addCleanup(h.close)
        h.confirmer.timeout = 3
        c = TestClient(create_app(h.registry, h.confirmer, redact.identity, "127.0.0.1", 8477), base_url="http://127.0.0.1:8477")
        codes = []

        async def go():
            async with h.client(None) as (cs, _):
                async def decide(n, replay):
                    while len(posted) < n:
                        await anyio.sleep(0.01)
                    b = posted[n - 1]
                    if replay:  # alte Freigabe wiederverwenden: alt/alt, altes Token + neuer Hash, neues Token + alter Hash, alte Aufruf-ID
                        old = posted[0]
                        for tok, sha in ((old["token"], old["args_sha256"]), (old["token"], b["args_sha256"]), (b["token"], old["args_sha256"])):
                            codes.append(c.post(f"/decision/{b['id']}", json={"token": tok, "decision": "approve", "args_sha256": sha}).status_code)
                        codes.append(c.post(f"/decision/{old['id']}", json={"token": old["token"], "decision": "approve", "args_sha256": old["args_sha256"]}).status_code)
                        return  # keine neue Entscheidung → Timeout
                    codes.append(c.post(f"/decision/{b['id']}", json={"token": b["token"], "decision": "approve", "args_sha256": b["args_sha256"]}).status_code)
                async with anyio.create_task_group() as tg:
                    tg.start_soon(decide, 1, False)
                    r1 = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 5})
                h.confirmer.timeout = 0.5
                async with anyio.create_task_group() as tg:
                    tg.start_soon(decide, 2, True)
                    r2 = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 50})
                self.assertEqual(gate_of(r1)["status"], "executed")
                self.assertEqual(gate_of(r2)["status"], "denied"); self.assertIn("timeout", gate_of(r2)["reason"])
        run(go())
        self.assertEqual(codes, [200, 403, 403, 403, 404])  # alte Aufruf-ID ist geschlossen
        self.assertNotEqual(posted[0]["args_sha256"], posted[1]["args_sha256"])
        self.assertEqual(h.state["calls"], [("ueberweisung", {"an": "Demo", "betrag": 5})])  # 50 EUR nie ausgeführt
        decisions = [json.loads(l) for l in h.conf.audit_log.read_text().splitlines() if json.loads(l)["event"] == "decision"]
        self.assertEqual([(d["decision"], d["by"]) for d in decisions], [("approve", "webhook"), ("deny", "timeout")])

    def test_redaction_hook_kann_bindung_nicht_aendern(self):
        """Der Redaction-Hook darf die Anzeige maskieren, aber nicht Aufruf-ID oder Hash der auszuführenden Argumente."""
        from torwaechter import preview as pv
        posted = []
        h = self.webhook_harness(posted); self.addCleanup(h.close)
        h.confirmer.timeout = 3

        def hook(preview):
            return {**preview, "arguments": {"an": "[redacted]"}, "args_sha256": "f" * 64}

        async def go():
            async with h.client(None, hook=hook) as (cs, _):
                async def decide_later():
                    while not posted:
                        await anyio.sleep(0.01)
                    h.registry.decide(posted[0]["id"], True, "webhook")
                async with anyio.create_task_group() as tg:
                    tg.start_soon(decide_later)
                    await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 5})
        run(go())
        self.assertEqual(posted[0]["args_sha256"], pv.args_hash({"an": "Demo", "betrag": 5}))

    def webseite_freigabe_mit_hook(self, hook):
        """Ende-zu-Ende über die echte Freigabeseite: Seite laden, Felder unverändert aus dem HTML übernehmen, klicken."""
        from starlette.testclient import TestClient
        from torwaechter.web import create_app
        h = GateHarness(web_enabled=True); self.addCleanup(h.close)
        h.confirmer.timeout = 3
        c = TestClient(create_app(h.registry, h.confirmer, hook, "127.0.0.1", 8477), base_url="http://127.0.0.1:8477", follow_redirects=False)
        seen = {}

        def field(html_text, name):
            return html_text.split(f'name="{name}" value="')[1].split('"')[0]

        async def go():
            async with h.client(None, hook=hook) as (cs, _):
                async def click_later():
                    while not h.registry.list_open():
                        await anyio.sleep(0.01)
                    page = c.get("/").text
                    cid = page.split('action="/approve/')[1].split('"')[0]
                    seen.update(page_sha=field(page, "args_sha256"), open_sha=c.get("/open").json()["open"][0]["args_sha256"],
                                registry_preview_sha=next(iter(h.registry.items.values())).preview["args_sha256"])
                    seen["code"] = c.post(f"/approve/{cid}", data={"csrf": field(page, "csrf"), "actor": "marco", "args_sha256": seen["page_sha"]}).status_code
                async with anyio.create_task_group() as tg:
                    tg.start_soon(click_later)
                    seen["result"] = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 5})
        run(go())
        return h, seen

    def test_webseite_freigabe_trotz_hook_der_hash_in_kopie_aendert(self):
        """Review #683 (MITTEL): Seite und /open wenden den Hook erneut an; die Bindung muss trotzdem die der Registry bleiben,
        sonst endet ein gültiger Klick mit 403."""
        from torwaechter import preview as pv

        def hook(preview):
            return {**preview, "arguments": {"an": "[redacted]"}, "args_sha256": "f" * 64, "id": "tw-fremd"}
        h, seen = self.webseite_freigabe_mit_hook(hook)
        real = pv.args_hash({"an": "Demo", "betrag": 5})
        self.assertEqual((seen["page_sha"], seen["open_sha"]), (real, real))
        self.assertEqual(seen["code"], 303)
        self.assertEqual(gate_of(seen["result"])["status"], "executed")
        self.assertEqual(h.state["calls"], [("ueberweisung", {"an": "Demo", "betrag": 5})])

    def test_webseite_freigabe_trotz_hook_der_vorschau_in_place_aendert(self):
        """Review #683: ein Hook, der das Vorschau-Dict selbst verändert, verschiebt weder Gate- noch Registry-Bindung noch Protokoll."""
        from torwaechter import preview as pv

        def hook(preview):
            preview["arguments"] = {"an": "[redacted]"}
            preview["args_sha256"] = "e" * 64
            preview["id"] = "tw-fremd"
            return preview
        h, seen = self.webseite_freigabe_mit_hook(hook)
        real = pv.args_hash({"an": "Demo", "betrag": 5})
        self.assertEqual((seen["page_sha"], seen["open_sha"], seen["registry_preview_sha"]), (real, real, real))
        self.assertEqual(seen["code"], 303)
        self.assertEqual(gate_of(seen["result"])["status"], "executed")
        previews = [json.loads(l) for l in h.conf.audit_log.read_text().splitlines() if json.loads(l)["event"] == "preview"]
        self.assertEqual([x["args_sha256"] for x in previews], [real])


class ReadbackTest(unittest.TestCase):
    def test_verdicts(self):
        rule = Readback(tool="kontostand", args={"konto": "$args.an"}, expect={"saldo": "$result.saldo"})
        async def reader(ok, result):
            async def call_read(tool, args):
                self.assertEqual((tool, args), ("kontostand", {"konto": "A"}))
                return result, not ok
            return call_read
        async def go():
            self.assertEqual((await readback.check(rule, {"an": "A"}, {"saldo": 5}, await reader(True, {"saldo": 5})))[0], "ok")
            self.assertEqual((await readback.check(rule, {"an": "A"}, {"saldo": 5}, await reader(True, {"saldo": 6})))[0], "fehlgeschlagen")
            self.assertEqual((await readback.check(rule, {"an": "A"}, {"saldo": 5}, await reader(False, None)))[0], "unklar")
            self.assertEqual((await readback.check(rule, {"an": "A"}, {"saldo": 5}, await reader(True, {"x": 1})))[0], "unklar")
            self.assertEqual((await readback.check(rule, {"an": "A"}, None, await reader(True, {"saldo": 5})))[0], "unklar")
        run(go())


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.h = GateHarness(); self.addCleanup(self.h.close)
        for i in range(4):
            self.h.log.append("preview" if i % 2 == 0 else "decision", f"tw-{i // 2}", "ueberweisung", decision="approve" if i % 2 else "confirm", by="test")
        self.path = self.h.conf.audit_log
        self.pub = audit.load_public(Path(str(self.h.conf.audit_key) + ".pub"))

    def lines(self):
        return self.path.read_text(encoding="utf-8").splitlines()

    def write(self, lines):
        self.path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def test_intact_log_verifies_and_survives_restart(self):
        ok, problems, n = audit.verify(self.path, self.pub)
        self.assertTrue(ok); self.assertEqual(n, 4)
        again = audit.AuditLog(self.path, audit.load_private(self.h.conf.audit_key))  # continues the chain after restart
        again.append("allow", "tw-9", "kontostand")
        self.assertTrue(audit.verify(self.path, self.pub)[0]); self.assertEqual(json.loads(self.lines()[-1])["seq"], 5)

    def test_modified_removed_reordered_inserted_truncated_detected(self):
        L = self.lines()
        e = json.loads(L[1]); e["decision"] = "deny"; m = L[:]; m[1] = json.dumps(e, sort_keys=True, separators=(",", ":"))
        self.write(m); ok, p, _ = audit.verify(self.path, self.pub); self.assertFalse(ok); self.assertIn("modified", p[0].reason)
        self.write(L[:1] + L[2:]); ok, p, _ = audit.verify(self.path, self.pub); self.assertFalse(ok); self.assertTrue(any("chain broken" in x.reason for x in p))
        self.write([L[0], L[2], L[1], L[3]]); ok, p, _ = audit.verify(self.path, self.pub); self.assertFalse(ok)
        forged = json.loads(L[1]); forged["sig"] = "00" * 64; self.write(L[:1] + [json.dumps(forged, sort_keys=True, separators=(",", ":"))] + L[2:])
        ok, p, _ = audit.verify(self.path, self.pub); self.assertFalse(ok); self.assertTrue(any("signature" in x.reason for x in p))
        self.write(L[:3]); ok, p, _ = audit.verify(self.path, self.pub); self.assertFalse(ok); self.assertTrue(any("truncated" in x.reason for x in p))
        self.write(L); self.assertTrue(audit.verify(self.path, self.pub)[0])
        # a different key cannot sign a valid-looking entry
        other = audit.generate_key(Path(self.h.dir, "other.pem"))
        self.assertFalse(audit.verify(self.path, other)[0])

    def test_cli_verify_log(self):
        from torwaechter.cli import main
        out = io.StringIO()
        with __import__("contextlib").redirect_stdout(out):
            self.assertEqual(main(["verify-log", "--config", str(self.h.dir / "torwaechter.yaml")]), 0)
        self.assertIn("OK: 4 entries", out.getvalue())


if __name__ == "__main__":
    unittest.main()
