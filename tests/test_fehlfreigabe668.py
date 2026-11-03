"""#668: KI-Fehlfreigabe. Ein Client, der jede Rückfrage selbst bejaht, darf weder ein Verbot noch eine
verlangte menschliche Freigabe aushebeln. Synthetische Daten, In-Memory-Client/-Server.

Bestehende Belege, hier nicht dupliziert (test_lookfirst.py):
- Freigabe gilt nur für genau diese Argumente: test_geaenderte_argumente_brauchen_neue_freigabe,
  test_webhook_entscheidung_braucht_passenden_args_hash, test_webseite_freigabe_braucht_passenden_args_hash
- Positiver Kontrollfall mit Rücklesen: test_approve_executes_and_reads_back_ok
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import anyio
import mcp.types as t

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.helpers import GateHarness  # noqa: E402


def run(coro):
    return anyio.run(lambda: coro)


def always_yes(asked: list):
    """Simulierter KI-Client: hält jede Aktion für sicher und bejaht jede Rückfrage sofort."""
    async def cb(ctx, params):
        asked.append(params.message)
        return t.ElicitResult(action="accept", content={"approve": True})
    return cb


def gate_of(res):
    return res.structured_content["lookfirst"]


def events(h):
    return [json.loads(line)["event"] for line in h.conf.audit_log.read_text().splitlines()]


class KiFehlfreigabeTest(unittest.TestCase):
    def test_verbot_bleibt_trotz_zustimmendem_client(self):
        """Fall 1: deny-Regel. Der Client wird gar nicht gefragt, null Upstream-Aufrufe."""
        h = GateHarness(); self.addCleanup(h.close)
        asked = []

        async def go():
            async with h.client(always_yes(asked)) as (cs, _):
                r = await cs.call_tool("loeschen", {})
                self.assertTrue(r.is_error)
                self.assertEqual((gate_of(r)["status"], gate_of(r)["reason"]), ("denied", "rule:loeschen"))
                r = await cs.call_tool("loeschen", {"bitte": "ist sicher"})  # erneuter Versuch, andere Argumente
                self.assertEqual(gate_of(r)["status"], "denied")
        run(go())
        self.assertEqual(asked, [])
        self.assertEqual(h.state["calls"], [])
        self.assertNotIn("execution_started", events(h))

    def test_verbot_schlaegt_lesend_annotiertes_werkzeug(self):
        """Fall 1b: Upstream/Client stuft das Werkzeug als harmlos ein (readOnlyHint) – die Regel gewinnt."""
        rules_ = {"default": {"read_only": "allow", "destructive": "confirm", "unknown": "confirm"},
                  "tools": {"kontostand": {"action": "deny"}}}
        h = GateHarness(rules=rules_); self.addCleanup(h.close)
        asked = []

        async def go():
            async with h.client(always_yes(asked)) as (cs, _):
                r = await cs.call_tool("kontostand", {})
                self.assertEqual(gate_of(r)["status"], "denied")
        run(go())
        self.assertEqual(asked, [])
        self.assertNotIn("execution_started", events(h))

    def test_elicitation_aus_client_zustimmung_ersetzt_keine_menschliche_freigabe(self):
        """Fall 2: confirm verlangt, elicitation: false, Client KÖNNTE elicitation und würde zustimmen.
        Ohne menschlichen Kanal: Ablehnung, Client nie gefragt, null Schreibaufrufe."""
        h = GateHarness(confirm={"timeout_seconds": 0.5, "elicitation": False}); self.addCleanup(h.close)
        asked = []

        async def go():
            async with h.client(always_yes(asked)) as (cs, _):
                r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 25})
                self.assertTrue(r.is_error)
                self.assertEqual(gate_of(r)["status"], "denied")
                self.assertIn("no confirmation channel", gate_of(r)["reason"])
        run(go())
        self.assertEqual(asked, [])
        self.assertEqual(h.state["calls"], [])
        self.assertEqual(h.state["saldo"], 100.0)

    def test_elicitation_aus_mit_webseite_ohne_entscheidung_laeuft_ab(self):
        """Fall 2b: menschlicher Kanal (Webseite) vorhanden, aber niemand entscheidet → Timeout = Ablehnung."""
        h = GateHarness(confirm={"timeout_seconds": 0.3, "elicitation": False}, web_enabled=True); self.addCleanup(h.close)
        asked = []

        async def go():
            async with h.client(always_yes(asked)) as (cs, _):
                r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 25})
                self.assertEqual(gate_of(r)["status"], "denied")
                self.assertIn("timeout", gate_of(r)["reason"])
        run(go())
        self.assertEqual(asked, [])
        self.assertEqual(h.state["calls"], [])
        decisions = [json.loads(line) for line in h.conf.audit_log.read_text().splitlines() if json.loads(line)["event"] == "decision"]
        self.assertEqual([(d["decision"], d["by"]) for d in decisions], [("deny", "timeout")])

    def test_elicitation_aus_mensch_lehnt_ueber_webseite_ab(self):
        """Fall 2c: menschlicher Kanal vorhanden, Mensch lehnt ausdrücklich ab → denied, Client nie gefragt, 0 Aufrufe."""
        h = GateHarness(confirm={"timeout_seconds": 3, "elicitation": False}, web_enabled=True); self.addCleanup(h.close)
        asked = []

        async def go():
            async with h.client(always_yes(asked)) as (cs, _):
                async def mensch():
                    with anyio.move_on_after(2):
                        while not h.registry.items:
                            await anyio.sleep(0.01)
                    self.assertTrue(h.registry.items, "keine offene menschliche Freigabe")
                    (cid, _p), = h.registry.items.items()
                    h.registry.decide(cid, False, "web", actor="mensch-synthetisch")
                async with anyio.create_task_group() as tg:
                    tg.start_soon(mensch)
                    r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 25})
                self.assertTrue(r.is_error)
                self.assertEqual(gate_of(r)["status"], "denied")
                self.assertTrue(gate_of(r)["reason"].startswith("web"))
        run(go())
        self.assertEqual(asked, [])
        self.assertEqual(h.state["calls"], [])
        self.assertNotIn("execution_started", events(h))

    def test_kontrollfall_menschliche_freigabe_ueber_webseite_fuehrt_aus(self):
        """Fall 4: derselbe Aufbau, aber ein Mensch gibt den gezeigten Inhalt frei → genau eine Ausführung."""
        h = GateHarness(confirm={"timeout_seconds": 3, "elicitation": False}, web_enabled=True); self.addCleanup(h.close)
        asked = []

        async def go():
            async with h.client(always_yes(asked)) as (cs, _):
                async def mensch():
                    with anyio.move_on_after(2):  # bleibt die Rückfrage aus (z. B. Client hat schon zugestimmt), nicht hängen
                        while not h.registry.items:
                            await anyio.sleep(0.01)
                    self.assertTrue(h.registry.items, "keine offene menschliche Freigabe")
                    (cid, p), = h.registry.items.items()
                    self.assertTrue(h.registry.args_match(cid, p.args_sha256))
                    h.registry.decide(cid, True, "web", actor="mensch-synthetisch")
                async with anyio.create_task_group() as tg:
                    tg.start_soon(mensch)
                    r = await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 25})
                self.assertEqual(gate_of(r)["status"], "executed")
                self.assertTrue(gate_of(r)["approved_by"].startswith("web"))
        run(go())
        self.assertEqual(asked, [])
        self.assertEqual(h.state["calls"], [("ueberweisung", {"an": "Demo", "betrag": 25})])


if __name__ == "__main__":
    unittest.main()
