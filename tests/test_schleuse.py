"""Datenschutz-Schleuse (#604). Synthetische Daten: Test-IBANs mit gültiger Prüfziffer, erfundene Namen/Adressen."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import mcp.types as t
from mcp.server.lowlevel import Server

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.helpers import GateHarness  # noqa: E402
from tests.test_lookfirst import accept, gate_of, run  # noqa: E402
from lookfirst.schleuse import Schleuse, SchleuseError  # noqa: E402

IBAN = "DE89 3704 0044 0532 0130 00"      # Standard-Beispiel-IBAN (gültige Prüfziffer, kein echtes Konto)
IBAN2 = "GB82WEST12345698765432"
NAME = "Erika Mustermann"


def finanz_server(state: dict) -> Server:
    async def list_tools(ctx, params):
        return t.ListToolsResult(tools=[
            t.Tool(name="buchungen", description="list", inputSchema={"type": "object", "properties": {}}, annotations=t.ToolAnnotations(readOnlyHint=True)),
            t.Tool(name="konto_suchen", description="read; support: kontakt@example.org", inputSchema={"type": "object", "properties": {"iban": {"type": "string"}}},
                   title="Konto (title@example.org)", outputSchema={"type": "object", "description": "out@example.org"},
                   annotations=t.ToolAnnotations(readOnlyHint=True, title="ann@example.org"), _meta={"owner": "meta@example.org"}),
            t.Tool(name="ueberweisung", description="transfer", annotations=t.ToolAnnotations(destructiveHint=True),
                   inputSchema={"type": "object", "properties": {"iban": {"type": "string"}, "betrag": {"type": "number"}}}),
        ])

    async def call_tool(ctx, params):
        a = params.arguments or {}
        state["calls"].append((params.name, dict(a)))
        if params.name == "buchungen":
            text = f"12,50 EUR an {NAME}, IBAN {IBAN} EUR; Rückfragen: erika@example.org"
            return t.CallToolResult(content=[t.TextContent(type="text", text=text)],
                                    structuredContent={"buchungen": [{"empfaenger": NAME, "iban": IBAN, "betrag": 12.5}, {"iban": IBAN2, "betrag": 3}]})
        if params.name == "konto_suchen":
            return t.CallToolResult(content=[t.TextContent(type="text", text=f"gefunden: {a.get('iban')}")], structuredContent={"iban": a.get("iban")})
        return t.CallToolResult(content=[t.TextContent(type="text", text=f"überwiesen an {a.get('iban')}")], structuredContent={"ok": True})
    return Server("finanz", version="0", on_list_tools=list_tools, on_call_tool=call_tool)


class Unit(unittest.TestCase):
    def test_detects_masks_and_resolves_only_own(self):
        s = Schleuse(names=(NAME,), patterns={"KUNDENNR": r"K-\d{6}"})
        out = s.mask_text(f"{NAME} {IBAN} EUR K-123456 +49 30 1234567 4111 1111 1111 1111 x@y.de 2026-10-26 50,00")
        for raw in (NAME, IBAN, "K-123456", "+49 30 1234567", "4111 1111 1111 1111", "x@y.de"):
            self.assertNotIn(raw, out)
        self.assertIn("EUR", out); self.assertIn("2026-10-26", out); self.assertIn("50,00", out)   # Kontext bleibt lesbar
        self.assertEqual(s.mask_text(IBAN), s.mask_text(IBAN))                                      # gleicher Wert → gleicher Platzhalter
        self.assertIn(IBAN, s.resolve(out))
        with self.assertRaises(SchleuseError):
            s.resolve("[[IBAN_abcdef]]")                                                            # nie ausgegeben → abgelehnt

    def test_review608_lowercase_iban_typed_exemptions_and_lock(self):
        s = Schleuse(max_failures=2)
        low = "de89370400440532013000"
        out = s.mask_text(f"iban {low} ok")
        self.assertNotIn(low, out); self.assertIn(low, s.resolve(out))                          # Kleinbuchstaben + Rundweg
        m = s.mask({"id": "synthetic@example.org", "args_sha256": "kein hash x@example.org", "call_id": "tw-0123456789abcdef",
                    "result_sha256": "a" * 64})
        self.assertNotIn("example.org", json.dumps(m))                                           # Ausnahme nur bei echtem Format
        self.assertEqual((m["call_id"], m["result_sha256"]), ("tw-0123456789abcdef", "a" * 64))
        for _ in range(2):
            with self.assertRaises(SchleuseError):
                s.resolve("[[IBAN_" + "0" * 32 + "]]")
        with self.assertRaisesRegex(SchleuseError, "locked"):                                    # Versuchslimit sperrt auch gültige
            s.resolve(out)

    def test_fail_closed_invalid_iban_and_expiry(self):
        now = [0.0]
        s = Schleuse(ttl_seconds=10, clock=lambda: now[0])
        out = s.mask_text("DE00 1234 5678 9012 3456 78 EUR")                                         # Prüfziffer falsch → trotzdem maskiert
        self.assertNotIn("1234 5678", out); self.assertTrue(out.endswith(" EUR"))
        tok = s.mask_text(IBAN)
        now[0] = 11
        with self.assertRaises(SchleuseError):
            s.resolve(tok)

    def test_placeholders_are_random_not_hashes(self):
        a, b = Schleuse(), Schleuse()
        self.assertNotEqual(a.mask_text(IBAN), b.mask_text(IBAN))


class Gate(unittest.TestCase):
    def setUp(self):
        self.h = GateHarness(upstreams={"finanz": {"command": "true"}}, rules={"default": {"read_only": "allow"}, "tools": {}})
        self.addCleanup(self.h.close)
        names = self.h.dir / "namen.txt"
        names.write_text(NAME + "\n", encoding="utf-8")
        self.h.conf.schleuse = {"detect": ["IBAN", "EMAIL"], "names_file": "namen.txt"}
        self.h.conf.base = self.h.dir
        self.state = {"calls": []}

    def test_result_masked_placeholder_resolved_for_local_tool(self):
        seen = {}

        async def go():
            async with self.h.client(accept(True), servers={"finanz": finanz_server(self.state)}) as (cs, _):
                r = await cs.call_tool("buchungen", {})
                blob = json.dumps({"c": [c.text for c in r.content], "s": r.structured_content}, ensure_ascii=False)
                for raw in (IBAN, IBAN2, NAME, "erika@example.org"):
                    self.assertNotIn(raw, blob)                                  # Weg A: nichts davon erreicht den Client
                tok = r.structured_content["buchungen"][0]["iban"]
                self.assertRegex(tok, r"^\[\[IBAN_[0-9a-f]{32}\]\]$")                 # 128 Bit
                # Weg B: Modell nutzt den Platzhalter; lokal wird das Original verwendet, zurück kommt wieder ein Platzhalter
                r2 = await cs.call_tool("ueberweisung", {"iban": tok, "betrag": 5})
                seen["text"] = r2.content[0].text
                self.assertEqual(gate_of(r2)["status"], "executed")
                # Erfundener Platzhalter: abgelehnt, nichts ausgeführt
                r3 = await cs.call_tool("konto_suchen", {"iban": "[[IBAN_000000]]"})
                self.assertTrue(r3.is_error); self.assertEqual(gate_of(r3)["status"], "denied")
        run(go())
        self.assertEqual(self.state["calls"][1], ("ueberweisung", {"iban": IBAN, "betrag": 5}))   # Upstream bekam das Original
        self.assertNotIn(IBAN, seen["text"])                                                          # Antwort wieder maskiert
        self.assertEqual([c[0] for c in self.state["calls"]], ["buchungen", "ueberweisung"])         # konto_suchen nie ausgeführt
        log = self.h.conf.audit_log.read_text()
        self.assertNotIn(IBAN, log); self.assertNotIn(NAME, log)                                      # Protokoll ohne Klartext
        self.assertIn('"event":"schleuse"', log.replace(" ", ""))
        self.assertTrue(self.h.verify()[0])

    def test_review608_audit_free_text_tool_list_and_session_binding(self):
        self.h.conf.tool_rules["ueberweisung"] = __import__("lookfirst.config", fromlist=["ToolRule"]).ToolRule(
            action="confirm", readback=__import__("lookfirst.config", fromlist=["Readback"]).Readback(
                tool="konto_suchen", args={"iban": IBAN2}, expect={"iban": "$args.iban"}))

        async def go():
            async with self.h.client(accept(True), servers={"finanz": finanz_server(self.state)}) as (cs, _):
                tools = await cs.list_tools()
                dumped = json.dumps([x.model_dump(by_alias=True) for x in tools.tools])
                for mail in ("kontakt@", "title@", "out@", "ann@", "meta@"):                  # Review #608: alle Metadatenfelder
                    self.assertNotIn(mail + "example.org", dumped)
                self.assertEqual({x.name for x in tools.tools}, {"buchungen", "konto_suchen", "ueberweisung"})
                ks = next(x for x in tools.tools if x.name == "konto_suchen")
                self.assertTrue(ks.annotations.read_only_hint)
                r = await cs.call_tool("buchungen", {})
                tok = r.structured_content["buchungen"][0]["iban"]
                r2 = await cs.call_tool("ueberweisung", {"iban": tok, "betrag": 1})
                self.assertEqual(gate_of(r2)["readback"], "fehlgeschlagen")
                self.assertNotIn(IBAN2, json.dumps(r2.structured_content))
                # Sitzungsbindung: eine andere Sitzung kennt den Platzhalter nicht
                other = type("Ctx", (), {"session": type("S", (), {})()})()
                with self.assertRaises(Exception):
                    self.h.gate.schleuse_for(other).resolve(tok)
        run(go())
        log = self.h.conf.audit_log.read_text()
        for raw in (IBAN, IBAN2, "DE89370400440532013000", "GB82WEST12345698765432"):
            self.assertNotIn(raw, log)                                                           # auch Rücklese-Detail maskiert
        self.assertTrue(self.h.verify()[0])

    def test_without_config_nothing_changes(self):
        self.h.conf.schleuse = None

        async def go():
            async with self.h.client(accept(True), servers={"finanz": finanz_server(self.state)}) as (cs, _):
                r = await cs.call_tool("buchungen", {})
                self.assertIn(IBAN, r.content[0].text)
        run(go())


if __name__ == "__main__":
    unittest.main()
