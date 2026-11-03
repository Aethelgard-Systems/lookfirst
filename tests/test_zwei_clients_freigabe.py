"""#668 P1: Torwächter Zwei-Client-Test.

Zwei MCP-Clients am selben Torwächter:
- Jede Freigabe darf nur genau einmal wirken (Single-Use-Invariante).
- Eine Freigabe für Client A schaltet Client B niemals frei.
- Serialisierung und Parallellauf: Werkzeugaufrufe beider Clients erhalten getrennte
  Bestätigungs-IDs; eine erteilte Freigabe führt zu genau einer Upstream-Ausführung.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

import anyio

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.helpers import GateHarness  # noqa: E402


def run(coro):
    return anyio.run(lambda: coro)


def gate_of(res):
    return res.structured_content["torwaechter"]


class ZweiClientsFreigabeTest(unittest.TestCase):
    def setUp(self):
        # Web-Kanal aktiv, Elicitation aus -> Freigaben laufen kontrollierbar über h.registry
        self.h = GateHarness(
            confirm={"timeout_seconds": 2.0, "elicitation": False},
            web_enabled=True,
        )
        self.addCleanup(self.h.close)

    def test_freigabe_von_client_a_kann_nicht_von_client_b_wiederverwendet_werden(self):
        """P1: Client A erhält Freigabe; dieselbe Freigabe ist danach verbraucht und nützt Client B nichts."""
        async def go():
            async with self.h.two_clients() as (ca, cb, gate):
                # 1. Beide Clients können Werkzeuge auflisten
                tools_a = [x.name for x in (await ca.list_tools()).tools]
                tools_b = [x.name for x in (await cb.list_tools()).tools]
                self.assertIn("ueberweisung", tools_a)
                self.assertIn("ueberweisung", tools_b)

                # 2. Client A initiiert bestätigungspflichtigen Transfer
                cid_a = None

                async def approve_a():
                    nonlocal cid_a
                    with anyio.move_on_after(1.5):
                        while not self.h.registry.items:
                            await anyio.sleep(0.01)
                    self.assertTrue(self.h.registry.items, "Kein Pending-Eintrag für Client A")
                    (cid_a, p), = self.h.registry.items.items()
                    # 1. Erste Entscheidung: Freigabe erteilen
                    self.assertTrue(self.h.registry.decide(cid_a, True, "web", actor="mensch-a"))
                    # P2: Zweites decide() auf den NOCH OFFENEN Eintrag versuchen -> MUSS False liefern
                    self.assertFalse(
                        self.h.registry.decide(cid_a, False, "web", actor="replay-auf-offenen-eintrag"),
                        "Zweites decide() auf noch offenen Eintrag darf nicht wirken (Single-Use-Invariante)",
                    )
                    # Erste Entscheidung bleibt unverändert erhalten
                    self.assertIsNotNone(p.decision)
                    self.assertTrue(p.decision.approved)
                    self.assertEqual(p.decision.actor, "mensch-a")

                async with anyio.create_task_group() as tg:
                    tg.start_soon(approve_a)
                    res_a = await ca.call_tool("ueberweisung", {"an": "Empfaenger", "betrag": 25.0})

                self.assertEqual(gate_of(res_a)["status"], "executed")
                self.assertFalse(res_a.is_error)
                self.assertEqual(self.h.state["saldo"], 75.0)
                self.assertEqual(len(self.h.state["calls"]), 1)

                # 3. Versuch, dieselbe Freigabe (cid_a) erneut zu entscheiden -> MUSS scheitern (geschlossen / verbraucht)
                self.assertFalse(
                    self.h.registry.decide(cid_a, True, "web", actor="replay-angriff"),
                    "Bereits entschiedene Freigabe darf kein zweites Mal entschieden werden",
                )

                # 4. Client B versucht denselben Transfer mit identischen Parametern
                # Client B darf NICHT von der vorherigen Freigabe für A profitieren
                cid_b = None

                async def handle_b():
                    nonlocal cid_b
                    with anyio.move_on_after(1.5):
                        while not self.h.registry.open_items():
                            await anyio.sleep(0.01)
                    open_b = self.h.registry.open_items()
                    self.assertTrue(open_b, "Client B muss eigenen Pending-Eintrag erzeugen")
                    cid_b = open_b[0].id
                    # Neue, andere ID als bei A
                    self.assertNotEqual(cid_b, cid_a, "Client B muss eine frische call_id erhalten")
                    # Wir lehnen B ab
                    self.assertTrue(self.h.registry.decide(cid_b, False, "web", actor="mensch-b-ablehnung"))

                async with anyio.create_task_group() as tg:
                    tg.start_soon(handle_b)
                    res_b = await cb.call_tool("ueberweisung", {"an": "Empfaenger", "betrag": 25.0})

                self.assertTrue(res_b.is_error)
                self.assertEqual(gate_of(res_b)["status"], "denied")

                # Saldo bleibt bei 75.0 – Bank wurde genau EINMAL belastet!
                self.assertEqual(self.h.state["saldo"], 75.0)
                self.assertEqual(len(self.h.state["calls"]), 1)

        run(go())
        self.assertTrue(self.h.verify()[0])

    def test_serialisierte_anfragen_zweier_clients_verlangen_zwei_unabhaengige_freigaben(self):
        """P1: Beide Clients fordern parallel dasselbe Schreibwerkzeug an. Torwächter serialisiert und
        erfordert für jeden Client eine eigenständige Freigabe; eine Freigabe führt zu genau 1 Ausführung."""
        async def go():
            async with self.h.two_clients() as (ca, cb, gate):
                cids_seen = []

                async def controller():
                    # 1. Erste Freigabe (Client A) abwarten und bewilligen
                    with anyio.move_on_after(1.5):
                        while not self.h.registry.open_items():
                            await anyio.sleep(0.01)
                    open_first = self.h.registry.open_items()
                    self.assertEqual(len(open_first), 1)
                    cid_first = open_first[0].id
                    cids_seen.append(cid_first)
                    self.assertTrue(self.h.registry.decide(cid_first, True, "web", actor="mensch-a-ok"))

                    # 2. Zweite Freigabe (Client B nach Serialisierung) abwarten und ablehnen
                    with anyio.move_on_after(1.5):
                        while not self.h.registry.open_items():
                            await anyio.sleep(0.01)
                    open_second = self.h.registry.open_items()
                    self.assertEqual(len(open_second), 1)
                    cid_second = open_second[0].id
                    cids_seen.append(cid_second)
                    self.assertNotEqual(cid_first, cid_second)
                    self.assertTrue(self.h.registry.decide(cid_second, False, "web", actor="mensch-b-nein"))

                res_a = None
                res_b = None

                async def call_a():
                    nonlocal res_a
                    res_a = await ca.call_tool("ueberweisung", {"an": "Lieferant", "betrag": 30.0})

                async def call_b():
                    nonlocal res_b
                    res_b = await cb.call_tool("ueberweisung", {"an": "Lieferant", "betrag": 30.0})

                async with anyio.create_task_group() as tg:
                    tg.start_soon(controller)
                    tg.start_soon(call_a)
                    tg.start_soon(call_b)

                # Genau einer ausgeführt (A), genau einer abgelehnt (B)
                statuses = {gate_of(res_a)["status"], gate_of(res_b)["status"]}
                self.assertEqual(statuses, {"executed", "denied"})

                # Bank exakt 1x aufgerufen: Saldo 100 -> 70
                self.assertEqual(self.h.state["saldo"], 70.0)
                self.assertEqual(len(self.h.state["calls"]), 1)
                self.assertEqual(self.h.state["calls"][0], ("ueberweisung", {"an": "Lieferant", "betrag": 30.0}))

        run(go())
        self.assertTrue(self.h.verify()[0])

    def test_zwei_verschiedene_tools_parallel_in_registry_nur_bewilligtes_wird_ausgefuehrt(self):
        """P1: Zwei Clients rufen unterschiedliche bestätigungspflichtige Werkzeuge zeitgleich auf.
        Beide stehen parallel in der Registry; nur das freigegebene Werkzeug wird ausgeführt."""
        async def go():
            async with self.h.two_clients() as (ca, cb, gate):
                cids = {}

                async def controller():
                    # Warten bis BEIDE Aufrufe parallel in der Registry registriert sind
                    with anyio.move_on_after(1.5):
                        while len(self.h.registry.open_items()) < 2:
                            await anyio.sleep(0.01)
                    open_list = self.h.registry.open_items()
                    self.assertEqual(len(open_list), 2)
                    for p in open_list:
                        cids[p.preview["tool"]] = p.id

                    # Bewillige nur 'ueberweisung' (Client A), lehne 'notiz' (Client B) ab
                    self.assertTrue(self.h.registry.decide(cids["ueberweisung"], True, "web", actor="mensch"))
                    self.assertTrue(self.h.registry.decide(cids["notiz"], False, "web", actor="mensch"))

                res_a = None
                res_b = None

                async def call_a():
                    nonlocal res_a
                    res_a = await ca.call_tool("ueberweisung", {"an": "Test", "betrag": 15.0})

                async def call_b():
                    nonlocal res_b
                    res_b = await cb.call_tool("notiz", {"text": "Wichtige Notiz"})

                async with anyio.create_task_group() as tg:
                    tg.start_soon(controller)
                    tg.start_soon(call_a)
                    tg.start_soon(call_b)

                self.assertEqual(gate_of(res_a)["status"], "executed")
                self.assertEqual(gate_of(res_b)["status"], "denied")

                # Nur 'ueberweisung' wurde upstream ausgeführt
                self.assertEqual(self.h.state["calls"], [("ueberweisung", {"an": "Test", "betrag": 15.0})])
                self.assertEqual(self.h.state["saldo"], 85.0)

        run(go())
        self.assertTrue(self.h.verify()[0])


if __name__ == "__main__":
    unittest.main()
