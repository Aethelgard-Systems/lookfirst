"""#668 P5: Sitzungstrennung der Schleuse über echten Streamable-HTTP-Transport (uvicorn auf 127.0.0.1, zwei Clients).

Aufbau wie ``lookfirst serve --transport http``: ``httpauth.guard(server.streamable_http_app(host, json_response=True), token)``.
Synthetischer Upstream liefert eine Beispiel-IBAN. Client A bekommt den Platzhalter; Client B (eigene MCP-Sitzung, gleicher
Token) darf ihn weder auflösen noch A's Freigabe-Dialog sehen. Synthetische Daten only.
"""
from __future__ import annotations

import json
import socket
import sys
import unittest
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

import anyio
import httpx2
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.helpers import GateHarness, serve_in_memory  # noqa: E402
from tests.test_schleuse import IBAN, finanz_server  # noqa: E402
from tests.test_lookfirst import accept, gate_of, run  # noqa: E402
from lookfirst import httpauth, redact  # noqa: E402
from lookfirst.proxy import Gate  # noqa: E402
from lookfirst.upstream import Upstreams  # noqa: E402

TOKEN = b"p5-" + b"t" * 40
RAW = IBAN.replace(" ", "")


class MehrClientHttp(unittest.TestCase):
    def setUp(self):
        self.h = GateHarness(upstreams={"finanz": {"command": "true"}}, confirm={"timeout_seconds": 5, "elicitation": True},
                             rules={"default": {"read_only": "allow", "destructive": "confirm", "unknown": "confirm"}, "tools": {}})
        self.addCleanup(self.h.close)
        self.h.conf.schleuse = {"detect": ["IBAN", "EMAIL"]}
        self.h.conf.base = self.h.dir
        self.state = {"calls": []}

    @asynccontextmanager
    async def http_gate(self):
        """Gate hinter echtem uvicorn auf Loopback (freier Port), wie in cli.serve."""
        async with serve_in_memory(finanz_server(self.state)) as up:
            ups = await Upstreams.from_sessions(self.h.conf, {"finanz": up})
            gate = Gate(self.h.conf, ups, self.h.log, self.h.confirmer, redact.identity)
            app = httpauth.guard(gate.server().streamable_http_app(host="127.0.0.1", json_response=True), TOKEN)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            srv = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="on"))
            async with anyio.create_task_group() as tg:
                tg.start_soon(lambda: srv.serve(sockets=[sock]))
                while not srv.started:
                    await anyio.sleep(0.02)
                yield gate, f"http://127.0.0.1:{port}/mcp"
                srv.should_exit = True
            sock.close()

    @staticmethod
    @asynccontextmanager
    async def client(url: str, elicitation_callback=None):
        async with AsyncExitStack() as st:
            http = await st.enter_async_context(httpx2.AsyncClient(headers={"Authorization": "Bearer " + TOKEN.decode()}, timeout=10))
            r, w = await st.enter_async_context(streamable_http_client(url, http_client=http))
            cs = await st.enter_async_context(ClientSession(r, w, elicitation_callback=elicitation_callback))
            await cs.initialize()
            yield cs

    def test_placeholder_of_a_not_usable_by_b(self):
        asked = {"A": 0, "B": 0}

        def counting(who):
            inner = accept(True)

            async def cb(ctx, params):
                asked[who] += 1
                return await inner(ctx, params)
            return cb

        async def go():
            async with self.http_gate() as (gate, url):
                async with self.client(url, counting("A")) as a, self.client(url, counting("B")) as b:
                    ra = await a.call_tool("buchungen", {})
                    tok = ra.structured_content["buchungen"][0]["iban"]
                    self.assertRegex(tok, r"^\[\[IBAN_[0-9a-f]{32}\]\]$")
                    self.assertNotIn(RAW, json.dumps(ra.model_dump(by_alias=True)).replace(" ", ""))

                    # B: A's Platzhalter → abgelehnt, nichts erreicht den Upstream, kein Klartext zurück
                    n = len(self.state["calls"])
                    for tool, args in (("konto_suchen", {"iban": tok}), ("ueberweisung", {"iban": tok, "betrag": 1})):
                        rb = await b.call_tool(tool, args)
                        self.assertTrue(rb.is_error)
                        self.assertEqual(gate_of(rb)["status"], "denied")
                        self.assertIn("schleuse", gate_of(rb)["reason"])
                        self.assertNotIn(RAW, json.dumps(rb.model_dump(by_alias=True)).replace(" ", ""))
                    self.assertEqual(len(self.state["calls"]), n)
                    self.assertEqual(len(gate._sessions), 2)                                    # zwei getrennte Schleusen
                    self.assertEqual(asked["B"], 0)

                    # A: derselbe Platzhalter wird aufgelöst; Freigabe-Dialog geht nur an A, B bekommt keinen
                    ok = await a.call_tool("ueberweisung", {"iban": tok, "betrag": 1})
                    self.assertEqual(gate_of(ok)["status"], "executed")
                    self.assertEqual(self.state["calls"][-1], ("ueberweisung", {"iban": IBAN, "betrag": 1}))
                    self.assertEqual((asked["A"], asked["B"]), (1, 0))

                    # B's eigener Platzhalter für denselben Wert ist ein anderer (kein gemeinsames Wörterbuch)
                    tb = (await b.call_tool("buchungen", {})).structured_content["buchungen"][0]["iban"]
                    self.assertNotEqual(tb, tok)

                # Neue Sitzung (z. B. Wiederverbindung) kennt alte Platzhalter nicht: fail-closed
                async with self.client(url, counting("B")) as c:
                    rc = await c.call_tool("konto_suchen", {"iban": tok})
                    self.assertEqual(gate_of(rc)["status"], "denied")
        run(go())
        self.assertNotIn(RAW, self.h.conf.audit_log.read_text().replace(" ", ""))
        self.assertTrue(self.h.verify()[0])

    def test_unknown_session_id_rejected(self):
        async def go():
            async with self.http_gate() as (_, url):
                async with httpx2.AsyncClient(timeout=10) as http:
                    hdr = {"Authorization": "Bearer " + TOKEN.decode(), "Accept": "application/json, text/event-stream",
                           "Content-Type": "application/json", "mcp-session-id": "0" * 32}
                    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
                    r = await http.post(url, headers=hdr, json=body)
                    self.assertGreaterEqual(r.status_code, 400)                                 # erfundene Sitzung → kein Zugriff
                    r = await http.post(url, headers={k: v for k, v in hdr.items() if k != "Authorization"}, json=body)
                    self.assertEqual(r.status_code, 401)
        run(go())


if __name__ == "__main__":
    unittest.main()
