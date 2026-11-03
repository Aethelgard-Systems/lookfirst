"""Adversarial Security Gegenpruefung fuer lookfirst (CLAUDE-ARGON-LOOKFIRST-GEGENPRUEFUNG-20261103-01).

Umfassende Pruefung der 7 Sicherheits-Bereiche gemaess Auftrag:
1. Vorschau/Freigabe (Null Schreibwirkung bei Timeout/Deny/Malformed)
2. Wiederverwendung & Argumentbindung (args_sha256, Replay, Single-Use)
3. Zwei Sitzungen / Clients (Session-Isolation, Elicitation-Targeting, Token)
4. Ruecklesen & Pruefprotokoll (audit hash chain, tampered lines, truncation mit/ohne .head)
5. Maskierung / Schleuse (Zeilenumbruch, Unicode, Base64, JSON-Keys, Binaries)
6. Webhook / Entscheidungsweg (HMAC call token, HTTPS-Pflicht, HostGuard DNS-Rebinding)
7. Autonomer Client & Dokumentation (Elicitation-Grenzen, Start-Warnungen)
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import anyio
import mcp.types as t
import yaml
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.helpers import GateHarness
from lookfirst import audit, config as cfg, redact
from lookfirst.confirm import Confirmer, Decision, PendingRegistry
from lookfirst.proxy import Gate
from lookfirst.schleuse import PLACEHOLDER, SECRET_KEY_NAME, Schleuse, SchleuseError
from lookfirst.web import create_app


def run(coro):
    return anyio.run(lambda: coro)


def gate_of(res):
    return res.structured_content["lookfirst"]


class TestBereich1VorschauFreigabe(unittest.TestCase):
    """Bereich 1: Kann ein Aufruf ohne vollstaendige Bestaetigung ausgefuehrt werden?
    Ablehnen und Timeout = null Schreibwirkung?
    """

    def setUp(self):
        self.h = GateHarness(
            confirm={"timeout_seconds": 1.0, "elicitation": True},
            rules={"default": {"read_only": "allow", "destructive": "confirm", "unknown": "confirm"}, "tools": {}},
            web_enabled=True,
        )
        self.addCleanup(self.h.close)

    def test_elicitation_user_rejects_zero_write_impact(self):
        """User lehnt Elicitation explizit ab (approve=False)."""
        async def mock_elicit(ctx, params):
            return t.ElicitResult(action="accept", content={"approve": False})

        async def go():
            async with self.h.client(elicitation_callback=mock_elicit) as (c, _):
                initial_saldo = self.h.state["saldo"]
                initial_calls = len(self.h.state["calls"])
                res = await c.call_tool("ueberweisung", {"an": "Bob", "betrag": 50.0})

                self.assertTrue(res.is_error)
                self.assertEqual(gate_of(res)["status"], "denied")
                self.assertIn("user rejected", gate_of(res)["reason"])
                # NULL Schreibwirkung belegt
                self.assertEqual(self.h.state["saldo"], initial_saldo)
                self.assertEqual(len(self.h.state["calls"]), initial_calls)

        run(go())

    def test_elicitation_action_cancel_zero_write_impact(self):
        """User bricht Elicitation-Dialog ab (action != 'accept')."""
        async def mock_elicit(ctx, params):
            return t.ElicitResult(action="cancel", content=None)

        async def go():
            async with self.h.client(elicitation_callback=mock_elicit) as (c, _):
                initial_saldo = self.h.state["saldo"]
                res = await c.call_tool("ueberweisung", {"an": "Bob", "betrag": 50.0})

                self.assertTrue(res.is_error)
                self.assertEqual(gate_of(res)["status"], "denied")
                self.assertIn("action=cancel", gate_of(res)["reason"])
                self.assertEqual(self.h.state["saldo"], initial_saldo)

        run(go())

    def test_elicitation_malformed_response_fails_closed(self):
        """Client liefert malformed Content (z.B. String statt Dict oder approve='true' als String)."""
        async def mock_elicit_string(ctx, params):
            return t.ElicitResult(action="accept", content="approve")

        async def mock_elicit_wrong_bool(ctx, params):
            return t.ElicitResult(action="accept", content={"approve": "true"})

        async def go():
            async with self.h.client(elicitation_callback=mock_elicit_string) as (c, _):
                res1 = await c.call_tool("ueberweisung", {"an": "Bob", "betrag": 10.0})
                self.assertTrue(res1.is_error)
                self.assertEqual(gate_of(res1)["status"], "denied")

            async with self.h.client(elicitation_callback=mock_elicit_wrong_bool) as (c, _):
                res2 = await c.call_tool("ueberweisung", {"an": "Bob", "betrag": 10.0})
                self.assertTrue(res2.is_error)
                self.assertEqual(gate_of(res2)["status"], "denied")

        run(go())

    def test_elicitation_timeout_zero_write_impact(self):
        """Elicitation antwortet nicht innerhalb des Timeouts."""
        async def mock_elicit_hangs(ctx, params):
            await anyio.sleep(5.0)
            return t.ElicitResult(action="accept", content={"approve": True})

        async def go():
            # Kurzer Timeout
            self.h.confirmer.timeout = 0.2
            async with self.h.client(elicitation_callback=mock_elicit_hangs) as (c, _):
                initial_saldo = self.h.state["saldo"]
                res = await c.call_tool("ueberweisung", {"an": "Bob", "betrag": 20.0})
                self.assertTrue(res.is_error)
                self.assertEqual(gate_of(res)["status"], "denied")
                self.assertIn("timeout", gate_of(res)["reason"])
                self.assertEqual(self.h.state["saldo"], initial_saldo)

        run(go())

    def test_web_denial_and_timeout_zero_write_impact(self):
        """Freigabe ueber Web-Oberflaeche explizit abgelehnt bzw. Timeout."""
        async def go():
            # Elicitation deaktivieren fuer diesen Test
            self.h.confirmer.use_elicitation = False
            self.h.confirmer.timeout = 0.2

            async with self.h.client() as (c, _):
                # 1. Timeout
                initial_saldo = self.h.state["saldo"]
                res_to = await c.call_tool("ueberweisung", {"an": "Bob", "betrag": 15.0})
                self.assertTrue(res_to.is_error)
                self.assertEqual(gate_of(res_to)["status"], "denied")
                self.assertIn("timeout", gate_of(res_to)["reason"])
                self.assertEqual(self.h.state["saldo"], initial_saldo)

                # 2. Explizites Web-Deny
                async def deny_on_web():
                    while not self.h.registry.open_items():
                        await anyio.sleep(0.01)
                    item = self.h.registry.open_items()[0]
                    self.h.registry.decide(item.id, False, "web", actor="admin")

                async with anyio.create_task_group() as tg:
                    tg.start_soon(deny_on_web)
                    res_deny = await c.call_tool("ueberweisung", {"an": "Bob", "betrag": 15.0})

                self.assertTrue(res_deny.is_error)
                self.assertEqual(gate_of(res_deny)["status"], "denied")
                self.assertEqual(self.h.state["saldo"], initial_saldo)

        run(go())

    def test_oversized_args_skipped_for_elicitation(self):
        """Argumente > MAX_ELICIT_ARGS (800 Zeichen) duerfen nicht per Elicitation entschieden werden."""
        async def mock_elicit_approve(ctx, params):
            # Duerfte gar nicht aufgerufen werden, wenn kein Web/Webhook konfiguriert ist!
            return t.ElicitResult(action="accept", content={"approve": True})

        async def go():
            self.h.confirmer.web_enabled = False
            self.h.confirmer.webhook = None
            huge_data = "x" * 850
            async with self.h.client(elicitation_callback=mock_elicit_approve) as (c, _):
                res = await c.call_tool("ueberweisung", {"an": "Bob", "verwendungszweck": huge_data})
                self.assertTrue(res.is_error)
                self.assertEqual(gate_of(res)["status"], "denied")
                self.assertIn("Vorschau zu lang für Elicitation", gate_of(res)["reason"])
                self.assertEqual(self.h.state["saldo"], 100.0)

        run(go())


class TestBereich2WiederverwendungArgumentBindung(unittest.TestCase):
    """Bereich 2: Gilt Freigabe fuer geaenderte Argumente (args_sha256)?
    Wiederverwendung / Zweitnutzung moeglich?
    """

    def setUp(self):
        self.registry = PendingRegistry()
        self.confirmer = Confirmer(self.registry, 2.0, False, True, None)
        self.app = create_app(self.registry, self.confirmer, redact.identity, host="127.0.0.1", port=8477)
        self.client = TestClient(self.app, base_url="http://127.0.0.1:8477")

    def test_web_approve_with_tampered_args_sha256_fails_403(self):
        """Formular sendet abweichenden args_sha256 -> 403 Forbidden, keine Freigabe."""
        preview = {
            "id": "tw-test01",
            "summary": "Transfer 10 EUR",
            "tool": "ueberweisung",
            "arguments": {"betrag": 10},
            "args_sha256": hashlib.sha256(b'{"betrag":10}').hexdigest(),
        }
        pending = self.registry.open(preview)

        # GET Index holt CSRF
        r_get = self.client.get("/")
        self.assertEqual(r_get.status_code, 200)
        csrf = r_get.text.split('name="csrf" value="')[1].split('"')[0]

        # POST mit gefaelschtem SHA (z.B. hash von {"betrag": 1000})
        tampered_sha = hashlib.sha256(b'{"betrag":1000}').hexdigest()
        r_post = self.client.post(
            "/approve/tw-test01",
            data={"csrf": csrf, "args_sha256": tampered_sha, "actor": "attacker"},
        )
        self.assertEqual(r_post.status_code, 403)
        self.assertIn("args_sha256 missing or does not match", r_post.json()["error"])
        self.assertIsNone(pending.decision)

    def test_single_use_invariant_and_replay_prevented(self):
        """Bereits entschiedene Freigabe kann kein zweites Mal entschieden werden."""
        preview = {
            "id": "tw-test02",
            "summary": "Transfer 20 EUR",
            "tool": "ueberweisung",
            "arguments": {"betrag": 20},
            "args_sha256": hashlib.sha256(b'{"betrag":20}').hexdigest(),
        }
        pending = self.registry.open(preview)

        # Erste Entscheidung: OK
        self.assertTrue(self.registry.decide("tw-test02", True, "web", actor="marco"))

        # Zweiter decide-Aufruf auf selbe ID (waehrend noch im Dictionary)
        self.assertFalse(self.registry.decide("tw-test02", False, "web", actor="replay"))
        self.assertTrue(pending.decision.approved)

        # Nach close() aus der Registry:
        self.registry.close("tw-test02")
        self.assertFalse(self.registry.decide("tw-test02", True, "web", actor="replay"))
        self.assertIsNone(self.registry.args_match("tw-test02", preview["args_sha256"]))


class TestBereich3ZweiSitzungenClients(unittest.TestCase):
    """Bereich 3: Elicitation-Targeting und Session-Isolation."""

    def setUp(self):
        self.h = GateHarness(
            confirm={"timeout_seconds": 2.0, "elicitation": True},
            web_enabled=True,
        )
        self.addCleanup(self.h.close)

    def test_elicitation_only_queries_requesting_client(self):
        """Client A loest Bestaetigung aus; Client B darf KEINEN Elicitation-Prompt erhalten."""
        asked_a = []
        asked_b = []

        async def elicit_a(ctx, params):
            asked_a.append(params)
            return t.ElicitResult(action="accept", content={"approve": True})

        async def elicit_b(ctx, params):
            asked_b.append(params)
            return t.ElicitResult(action="accept", content={"approve": True})

        async def go():
            async with self.h.two_clients(elicitation_a=elicit_a, elicitation_b=elicit_b) as (ca, cb, gate):
                res = await ca.call_tool("ueberweisung", {"an": "Charlie", "betrag": 5.0})
                self.assertEqual(gate_of(res)["status"], "executed")
                self.assertEqual(len(asked_a), 1)
                # Client B wurde NICHT gefragt!
                self.assertEqual(len(asked_b), 0)

        run(go())

    def test_client_b_cannot_reuse_or_claim_client_a_approval(self):
        """Freigabe aus Sitzung A kann nicht in Sitzung B wiederverwendet werden."""
        asked_a = []
        asked_b = []

        async def elicit_a(ctx, params):
            asked_a.append(params)
            return t.ElicitResult(action="accept", content={"approve": True})

        async def elicit_b(ctx, params):
            asked_b.append(params)
            return t.ElicitResult(action="accept", content={"approve": False})

        async def go():
            async with self.h.two_clients(elicitation_a=elicit_a, elicitation_b=elicit_b) as (ca, cb, gate):
                # 1. Client A führt Überweisung aus -> Elicitation A bestätigt -> executed
                res_a = await ca.call_tool("ueberweisung", {"an": "Target", "betrag": 50.0})
                gate_a = gate_of(res_a)
                self.assertEqual(gate_a["status"], "executed")
                self.assertEqual(len(asked_a), 1)

                # 2. Client B versucht dieselbe Überweisung -> B's Elicitation lehnt ab -> denied
                res_b = await cb.call_tool("ueberweisung", {"an": "Target", "betrag": 50.0})
                gate_b = gate_of(res_b)
                self.assertEqual(gate_b["status"], "denied")
                self.assertIn("user rejected", gate_b["reason"])
                self.assertEqual(len(asked_b), 1)
                self.assertNotEqual(gate_a["id"], gate_b["id"], "Jeder Aufruf erhält eine frische, unvorhersehbare ID")

        run(go())

    def test_http_bearer_token_adversarial_countercases(self):
        """HTTP-Transport erfordert striktes Bearer-Token (401 bei Fehlen, falschem Token oder Header-Manipulation)."""
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.testclient import TestClient
        from lookfirst import httpauth

        token = b"secure-test-token-at-least-32-chars-long"

        async def endpoint(request):
            return JSONResponse({"status": "ok"})

        inner_app = Starlette(routes=[Route("/mcp", endpoint, methods=["POST", "GET"])])
        app = httpauth.guard(inner_app, token)
        client = TestClient(app)

        # 1. Kein Authorization-Header -> 401
        r_none = client.post("/mcp", json={})
        self.assertEqual(r_none.status_code, 401)

        # 2. Falscher Token -> 401
        r_wrong = client.post("/mcp", headers={"Authorization": "Bearer wrong-token-12345678901234567890"}, json={})
        self.assertEqual(r_wrong.status_code, 401)

        # 3. Basic Auth statt Bearer -> 401
        r_basic = client.post("/mcp", headers={"Authorization": "Basic dXNlcjpwYXNz"}, json={})
        self.assertEqual(r_basic.status_code, 401)

        # 4. Bearer mit Extra-Tokens -> 401
        r_inject = client.post("/mcp", headers={"Authorization": "Bearer " + token.decode() + " extra"}, json={})
        self.assertEqual(r_inject.status_code, 401)

        # 5. Korrekter Bearer Token -> 200
        r_ok = client.post("/mcp", headers={"Authorization": "Bearer " + token.decode()}, json={})
        self.assertEqual(r_ok.status_code, 200)
        self.assertEqual(r_ok.json(), {"status": "ok"})


class TestBereich4AuditLogIntegritaetUndTruncation(unittest.TestCase):
    """Bereich 4: Erkennt verify-log veraenderte, entfernte, umsortierte, eingefuegte
    und gefaelschte Eintraege? Abschneiden am Ende mit und ohne .head-Datei.
    """

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.dir = Path(self.tmpdir.name)
        self.key_path = self.dir / "audit.key"
        self.pub = audit.generate_key(self.key_path)
        self.priv = audit.load_private(self.key_path)
        self.log_path = self.dir / "audit.jsonl"
        self.log = audit.AuditLog(self.log_path, self.priv)

        # 3 Eintraege erzeugen
        self.log.append("preview", "tw-1", "tool1", summary="s1")
        self.log.append("decision", "tw-1", "tool1", decision="approve", by="web:marco")
        self.log.append("result", "tw-1", "tool1", note="ok")

    def test_intact_log_verifies_clean(self):
        ok, problems, n = audit.verify(self.log_path, self.pub)
        self.assertTrue(ok)
        self.assertEqual(len(problems), 0)
        self.assertEqual(n, 3)

    def test_entry_modified_detected(self):
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        e = json.loads(lines[1])
        e["summary"] = "manipuliert"  # Hash wird nicht neu berechnet
        lines[1] = json.dumps(e)
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, problems, n = audit.verify(self.log_path, self.pub)
        self.assertFalse(ok)
        self.assertTrue(any("hash mismatch" in p.reason for p in problems))

    def test_entry_removed_detected(self):
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        # Zeile 2 loeschen
        del lines[1]
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, problems, n = audit.verify(self.log_path, self.pub)
        self.assertFalse(ok)
        self.assertTrue(any("chain broken" in p.reason for p in problems))

    def test_entries_reordered_detected(self):
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, problems, n = audit.verify(self.log_path, self.pub)
        self.assertFalse(ok)
        self.assertTrue(any("chain broken" in p.reason or "sequence gap" in p.reason for p in problems))

    def test_entry_inserted_detected(self):
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        lines.insert(1, lines[0])  # Duplikat eingefuegt
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, problems, n = audit.verify(self.log_path, self.pub)
        self.assertFalse(ok)
        self.assertTrue(any("chain broken" in p.reason or "sequence gap" in p.reason for p in problems))

    def test_truncation_with_head_file_detected_as_error(self):
        """Ende abgeschnitten WAEHREND .head existiert -> Fehler (TAMPERED)."""
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        # Letzten Eintrag loeschen, aber .head unveraendert lassen
        lines = lines[:2]
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, problems, n = audit.verify(self.log_path, self.pub)
        self.assertFalse(ok)
        self.assertTrue(any("head mismatch" in p.reason for p in problems))

    def test_truncation_without_head_file_produces_warning(self):
        """Ende abgeschnitten UND .head-Datei geloescht -> ok=True, aber WARNUNG."""
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        lines = lines[:1]
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        head_path = Path(str(self.log_path) + ".head")
        head_path.unlink()

        verdict = audit.verify(self.log_path, self.pub)
        ok, problems, n = verdict
        self.assertTrue(ok, "Hashkette fuer verbleibende Zeilen ist rein formal intakt")
        self.assertEqual(len(problems), 0)
        self.assertTrue(len(verdict.warnings) > 0)
        self.assertIn("head sidecar missing", verdict.warnings[0])

    def test_forged_entry_signature_detected(self):
        """Eintrag mit fremdem Ed25519-Schluessel signiert -> verify-log meldet 'signature invalid'."""
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        e = json.loads(lines[1])
        attacker_key_path = self.dir / "attacker.key"
        audit.generate_key(attacker_key_path)
        attacker_priv = audit.load_private(attacker_key_path)
        e["sig"] = attacker_priv.sign(bytes.fromhex(e["hash"])).hex()
        lines[1] = json.dumps(e)
        self.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ok, problems, n = audit.verify(self.log_path, self.pub)
        self.assertFalse(ok)
        self.assertTrue(any("signature invalid" in p.reason for p in problems))

    def test_forged_head_signature_detected(self):
        """Head-Sidecar mit fremdem Schluessel signiert -> verify-log meldet 'head sidecar unsigned, damaged or forged'."""
        head_path = Path(str(self.log_path) + ".head")
        self.assertTrue(head_path.exists())
        h = json.loads(head_path.read_text(encoding="utf-8"))
        attacker_key_path = self.dir / "attacker_head.key"
        audit.generate_key(attacker_key_path)
        attacker_priv = audit.load_private(attacker_key_path)
        h["sig"] = attacker_priv.sign(audit.head_message(h["seq"], h["hash"])).hex()
        head_path.write_text(json.dumps(h), encoding="utf-8")

        ok, problems, n = audit.verify(self.log_path, self.pub)
        self.assertFalse(ok)
        self.assertTrue(any("head sidecar unsigned, damaged or forged" in p.reason for p in problems))


class TestBereich5MaskierungDatenschutzSchleuse(unittest.TestCase):
    """Bereich 5: Umgehungsversuche gegen Datenschutz-Schleuse:
    Zeilenumbruch, Unicode, Base64, JSON-Keys, Nicht-Text.
    """

    def setUp(self):
        self.s = Schleuse()

    @unittest.expectedFailure
    def test_iban_with_newline_evasion(self):
        """SOLL: Zeilenumbruch innerhalb einer IBAN muss erkannt und maskiert werden (Befund B5.1: Regex matcht nicht ueber Newlines)."""
        newline_iban = "DE89\n3704\n0044\n0532\n0130\n00"
        out = self.s.mask_text(f"Konto: {newline_iban}")
        self.assertNotIn("3704", out)
        self.assertRegex(out, r"\[\[IBAN_[0-9a-f]{32}\]\]")

    @unittest.expectedFailure
    def test_iban_with_unicode_confusables_evasion(self):
        """SOLL: Zero-Width Space (\\u200b) in IBAN muss neutralisiert und maskiert werden (Befund B5.1: Evasion via Confusables)."""
        zw_iban = "DE89\u200b370400440532013000"
        out = self.s.mask_text(f"Konto: {zw_iban}")
        self.assertNotIn("370400440532013000", out)
        self.assertRegex(out, r"\[\[IBAN_[0-9a-f]{32}\]\]")

    @unittest.expectedFailure
    def test_base64_encoded_secret_evasion(self):
        """SOLL: Base64-kodierte Secrets/IBANs in Freitext muessen erkannt und maskiert werden (Befund B5.1: Regex scannt nur Klartext)."""
        secret = "sk-ant-api03-verysecretkey123456789"
        b64_secret = base64.b64encode(secret.encode()).decode()
        out_secret = self.s.mask_text(f"Datenpaket: {b64_secret}")
        self.assertNotIn(b64_secret, out_secret)
        self.assertRegex(out_secret, r"\[\[GEHEIMNIS_")

        raw_iban = "DE89370400440532013000"
        b64_iban = base64.b64encode(raw_iban.encode()).decode()
        out_iban = self.s.mask_text(f"Zahlungsreferenz: {b64_iban}")
        self.assertNotIn(b64_iban, out_iban)
        self.assertRegex(out_iban, r"\[\[IBAN_")

    @unittest.expectedFailure
    def test_json_key_variation_password_vs_custom_key(self):
        """SOLL: Auch Keys wie 'db_password' und 'access_token' muessen als Geheimnis maskiert werden (Befund B5.2: SECRET_KEY_NAME unvollstaendig)."""
        data = {
            "password": "geheim12345",
            "db_password": "geheim12345",
            "access_token": "geheim12345",
            "auth_token": "geheim12345",
        }
        masked = self.s.mask(data)
        self.assertRegex(masked["password"], r"^\[\[GEHEIMNIS_")
        self.assertRegex(masked["auth_token"], r"^\[\[GEHEIMNIS_")
        self.assertRegex(masked["db_password"], r"^\[\[GEHEIMNIS_")
        self.assertRegex(masked["access_token"], r"^\[\[GEHEIMNIS_")

    def test_non_text_content_fail_closed(self):
        """Nicht-textlicher Inhalt (Image / Binary) wird im Proxy fail-closed zurueckgehalten."""
        content = t.ImageContent(type="image", data="binary", mimeType="image/png")
        masked_c = Gate._mask_content(self.s, content)
        self.assertIn("nicht-textlicher Inhalt zurückgehalten", masked_c.text)


class TestBereich6WebhookEntscheidungsweg(unittest.TestCase):
    """Bereich 6: Webhook HMAC Token, HTTPS-Pflicht, HostGuard."""

    def test_webhook_https_enforcement(self):
        """confirm.webhook.url muss https:// sein (ausser localhost)."""
        reg = PendingRegistry()
        # HTTP zu externer Domain -> muss ValueError werfen
        with self.assertRaises(ValueError):
            Confirmer(reg, 2.0, False, False, {"url": "http://evil.com/webhook"})

        # HTTP zu localhost/127.0.0.1 -> erlaubt
        c_local = Confirmer(reg, 2.0, False, False, {"url": "http://127.0.0.1:9000/hook"})
        self.assertIsNotNone(c_local.webhook_secret)

        # HTTPS zu extern -> erlaubt
        c_https = Confirmer(reg, 2.0, False, False, {"url": "https://aethelgard.org/hook"})
        self.assertIsNotNone(c_https.webhook_secret)

    def test_webhook_decision_api_token_and_hash_checks(self):
        """POST /decision/{call_id} verlangt gueltigen HMAC-Token und uebereinstimmenden args_sha256."""
        reg = PendingRegistry()
        confirmer = Confirmer(reg, 2.0, False, False, {"url": "https://example.invalid/hook"})
        app = create_app(reg, confirmer, redact.identity, host="127.0.0.1", port=8477)
        client = TestClient(app, base_url="http://127.0.0.1:8477")

        preview = {
            "id": "tw-wh01",
            "summary": "Transfer",
            "tool": "ueberweisung",
            "arguments": {"amount": 50},
            "args_sha256": hashlib.sha256(b'{"amount":50}').hexdigest(),
        }
        reg.open(preview)
        valid_token = confirmer.call_token("tw-wh01")

        # 1. Kein Token -> 403
        r1 = client.post("/decision/tw-wh01", json={"decision": "approve", "args_sha256": preview["args_sha256"]})
        self.assertEqual(r1.status_code, 403)

        # 2. Falscher Token -> 403
        r2 = client.post("/decision/tw-wh01", json={"token": "invalid", "decision": "approve", "args_sha256": preview["args_sha256"]})
        self.assertEqual(r2.status_code, 403)

        # 3. Token fuer andere call_id verwendet -> 403
        other_token = confirmer.call_token("tw-wh99")
        r3 = client.post("/decision/tw-wh01", json={"token": other_token, "decision": "approve", "args_sha256": preview["args_sha256"]})
        self.assertEqual(r3.status_code, 403)

        # 4. Gueltiger Token, aber falscher args_sha256 -> 403
        r4 = client.post("/decision/tw-wh01", json={"token": valid_token, "decision": "approve", "args_sha256": "wrong_hash"})
        self.assertEqual(r4.status_code, 403)

        # 5. Gueltiger Token und gueltiger args_sha256 -> 200 OK
        r5 = client.post("/decision/tw-wh01", json={"token": valid_token, "decision": "approve", "args_sha256": preview["args_sha256"]})
        self.assertEqual(r5.status_code, 200)
        self.assertEqual(r5.json()["status"], "recorded")

    def test_host_guard_dns_rebinding_protection(self):
        """HostGuard blockiert fremde Host- und Origin-Header."""
        reg = PendingRegistry()
        confirmer = Confirmer(reg, 2.0, False, True, None)
        app = create_app(reg, confirmer, redact.identity, host="127.0.0.1", port=8477)
        client = TestClient(app)

        # Rebinding-Angriff mit DNS Host
        r_host = client.get("/", headers={"Host": "attacker.com"})
        self.assertEqual(r_host.status_code, 403)

        # Cross-Site Origin
        r_origin = client.get("/", headers={"Host": "127.0.0.1:8477", "Origin": "http://attacker.com"})
        self.assertEqual(r_origin.status_code, 403)

        # Sec-Fetch-Site cross-site
        r_sfs = client.get("/", headers={"Host": "127.0.0.1:8477", "Sec-Fetch-Site": "cross-site"})
        self.assertEqual(r_sfs.status_code, 403)


class TestBereich7AutonomerClientDokumentation(unittest.TestCase):
    """Bereich 7: Elicitation-Grenze ehrlich im README dokumentiert und Verhalten bei Start."""

    def test_readme_and_threat_model_document_autonomous_client_limit(self):
        root = Path(__file__).resolve().parents[1]
        readme_en = (root / "README.md").read_text(encoding="utf-8")
        readme_de = (root / "README.de.md").read_text(encoding="utf-8")
        threat = (root / "docs" / "threat-model.md").read_text(encoding="utf-8")

        self.assertIn("confirm.elicitation: false", readme_en)
        self.assertIn("confirm.elicitation: false", readme_de)
        self.assertIn("B4", threat)
        self.assertIn("autonomous agent", threat)

    def test_unmatched_rules_warns_on_stderr(self):
        """Regel-Tippfehler (unmatched_rules) erzeugen eine sichtbare Warnung auf sys.stderr beim Start (cli.py:43)."""
        demo_dir = Path(__file__).resolve().parents[1] / "demo"
        pkg_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            key_path = p / "audit.key"
            audit.generate_key(key_path)
            cfg_file = p / "lookfirst.yaml"
            for f in ("bank_server.py", "namen.txt"):
                (p / f).write_text((demo_dir / f).read_text(encoding="utf-8"), encoding="utf-8")
            data = yaml.safe_load((demo_dir / "lookfirst.yaml").read_text(encoding="utf-8"))
            data["upstreams"]["bank"]["command"] = sys.executable
            data["audit"]["key"] = str(key_path)
            data["audit"]["log"] = str(p / "audit.log")
            data["rules"]["tools"]["tippfehler_rule"] = {"action": "deny"}
            # Kein fester Web-Port um Port-Konflikte zu vermeiden:
            if "confirm" in data and isinstance(data["confirm"], dict):
                data["confirm"].pop("web", None)
            cfg_file.write_text(yaml.safe_dump(data), encoding="utf-8")

            env = {
                **os.environ,
                "PYTHONPATH": f"{pkg_root}:{pkg_root / 'src'}:{os.environ.get('PYTHONPATH', '')}",
            }
            cmd = [sys.executable, "-m", "lookfirst.cli", "serve", "--config", str(cfg_file)]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15.0,
                    cwd=str(p),
                    stdin=subprocess.DEVNULL,
                    env=env,
                )
                stderr = proc.stderr
            except subprocess.TimeoutExpired as e:
                stderr = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")

            self.assertIn("WARNING: rule for 'tippfehler_rule' matches no upstream tool", stderr)

    def _run_serve_with_elicitation(self, td: str):
        """Hilfsfunktion: Startet lookfirst.cli serve im Subprozess mit reiner Elicitation-Konfiguration."""
        p = Path(td)
        key_path = p / "audit.key"
        audit.generate_key(key_path)
        cfg_file = p / "lookfirst.yaml"
        demo_dir = Path(__file__).resolve().parents[1] / "demo"
        pkg_root = Path(__file__).resolve().parents[1]
        for f in ("bank_server.py", "namen.txt"):
            (p / f).write_text((demo_dir / f).read_text(encoding="utf-8"), encoding="utf-8")
        data = yaml.safe_load((demo_dir / "lookfirst.yaml").read_text(encoding="utf-8"))
        data["upstreams"]["bank"]["command"] = sys.executable
        data["audit"]["key"] = str(key_path)
        data["audit"]["log"] = str(p / "audit.log")
        # Nur Elicitation aktiv, kein Web-Approval:
        data["confirm"] = {"timeout_seconds": 5, "elicitation": True}
        cfg_file.write_text(yaml.safe_dump(data), encoding="utf-8")

        src_dir = str(pkg_root / "src")
        pkg_str = str(pkg_root)
        existing_pp = os.environ.get("PYTHONPATH", "")
        env = {
            **os.environ,
            "PYTHONPATH": f"{pkg_str}:{src_dir}:{existing_pp}",
        }
        cmd = [sys.executable, "-m", "lookfirst.cli", "serve", "--config", str(cfg_file)]
        timed_out = False
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15.0,
                cwd=str(p),
                stdin=subprocess.DEVNULL,
                env=env,
            )
            stderr = proc.stderr or ""
            returncode = proc.returncode
        except subprocess.TimeoutExpired as e:
            timed_out = True
            stderr = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
            returncode = None
        return timed_out, returncode, stderr

    def test_autonomous_client_server_starts_without_crash(self):
        """Startnachweis (normaler Test ohne expectedFailure): Prüft, dass lookfirst.cli serve mit Elicitation-Config fehlerfrei startet."""
        with tempfile.TemporaryDirectory() as td:
            timed_out, returncode, stderr = self._run_serve_with_elicitation(td)
            # Vorbedingung: Der Server startete fehlerfrei und blockierte im Server-Loop (Timeout)
            # oder beendete sich regulär ohne Traceback/Crash:
            self.assertTrue(
                timed_out or returncode == 0,
                f"Server startete nicht ordnungsgemäß (returncode={returncode}): {stderr}"
            )
            self.assertNotIn("Traceback (most recent call last)", stderr, f"Server crashte beim Start: {stderr}")

    @unittest.expectedFailure
    def test_autonomous_client_start_warning_behavior(self):
        """SOLL: Wenn lookfirst gestartet wird und nur Elicitation aktiv ist, soll auf stderr vor autonomen Clients gewarnt werden (Befund B7.1)."""
        with tempfile.TemporaryDirectory() as td:
            _timed_out, _returncode, stderr = self._run_serve_with_elicitation(td)
            # Soll-Verhalten laut B7.1: Startwarnung vor Elicitation ohne menschlichen Kanal
            self.assertTrue(
                any(term in (stderr or "").lower() for term in ("autonomous", "warning: only elicitation", "ohne mensch")),
                f"Startwarnung für autonome Elicitation fehlt auf stderr (Befund B7.1). Erhalten: {stderr!r}"
            )


if __name__ == "__main__":
    unittest.main()
