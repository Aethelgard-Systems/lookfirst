"""Tests for torwaechter pilot-status and launch gate evaluation (#609/#807)."""
from __future__ import annotations

import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from torwaechter import audit, cli, config as cfg
from torwaechter.pilot import evaluate_pilot_status


def make_conf_and_keys(d: Path) -> cfg.Config:
    conf_path = d / "torwaechter.yaml"
    key_path = d / "audit.key"
    log_path = d / "audit.jsonl"
    conf_path.write_text(f"""
upstreams:
  mock:
    command: python3
    args: [-c, "print()"]
audit:
  key: {key_path}
  log: {log_path}
""", encoding="utf-8")
    audit.generate_key(key_path)
    return cfg.load(conf_path)


class TestPilotStatus(unittest.TestCase):
    def test_missing_log_returns_open_gate_with_zero_operations(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            conf = make_conf_and_keys(d)
            # Log file intentionally not created
            rep = evaluate_pilot_status(conf)
            self.assertFalse(rep.audit_exists)
            self.assertFalse(rep.audit_verified)
            self.assertEqual(rep.real_operations_total, 0)
            self.assertEqual(rep.gate_status, "OFFEN")
            data = rep.to_dict()
            self.assertEqual(data["gate"]["status"], "OFFEN")
            self.assertFalse(data["gate"]["operations_met"])
            self.assertFalse(data["gate"]["days_met"])

    def test_demo_entries_do_not_count_as_real_operations(self):
        """Demo log entries (offline bank demo) must NEVER count as real operations."""
        from torwaechter import demo
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            rc = demo.run_demo(answer="y", keep=str(d))
            self.assertEqual(rc, 0)
            
            # Die Demo manipuliert am Ende absichtlich Zeile 6. Wir prüfen das Log mit den Demo-Einträgen.
            conf_path = d / "torwaechter.yaml"
            conf = cfg.load(conf_path)
            rep = evaluate_pilot_status(conf)
            self.assertEqual(rep.real_operations_total, 0, "Demo-Tools/Akteure dürfen nicht als echte Vorgänge zählen")
            self.assertEqual(rep.gate_status, "OFFEN")

    def test_synthetic_pilot_log_progression(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            conf = make_conf_and_keys(d)
            priv = audit.load_private(conf.audit_key)
            now = time.time()

            # 1. Pilot-Start: 0 echte Vorgänge, nur System-Initialisierung
            log_start = audit.AuditLog(conf.audit_log, priv, now=lambda: now)
            log_start.append("allow", "tw-0", "aufgabe_lesen", decision="allow", by="rule:aufgabe_lesen")
            rep_start = evaluate_pilot_status(conf, now=now)
            self.assertTrue(rep_start.audit_verified)
            self.assertEqual(rep_start.real_operations_total, 0)
            self.assertEqual(rep_start.gate_status, "OFFEN")

            # 2. Einige Tage später: 5 echte Vorgänge (4 Freigaben, 1 Timeout-Ablehnung) vor 3 Tagen
            three_days_ago = now - (3 * 86400)
            cur_time = three_days_ago
            def clock():
                nonlocal cur_time
                cur_time += 1.0
                return cur_time

            log_mid = audit.AuditLog(conf.audit_log, priv, now=clock)
            for i in range(1, 5):
                log_mid.append("preview", f"tw-{i}", "aufgabe_anlegen", summary=f"Task {i}", decision="confirm")
                log_mid.append("decision", f"tw-{i}", "aufgabe_anlegen", decision="approve", by="web:marco")
                log_mid.append("execution_started", f"tw-{i}", "aufgabe_anlegen")
                log_mid.append("result", f"tw-{i}", "aufgabe_anlegen", note="ok")
                log_mid.append("readback", f"tw-{i}", "aufgabe_anlegen", readback="ok")
                log_mid.append("execution_resolved", f"tw-{i}", "aufgabe_anlegen")

            # Ein Vorgang mit Ablehnung via Timeout (zählt als timeouts, NICHT als echter Vorgang)
            log_mid.append("preview", "tw-5", "aufgabe_anlegen", summary="Task 5", decision="confirm")
            log_mid.append("decision", "tw-5", "aufgabe_anlegen", decision="deny", by="timeout", note="no decision within 120s")

            rep_mid = evaluate_pilot_status(conf, now=now)
            self.assertTrue(rep_mid.audit_verified)
            self.assertEqual(rep_mid.real_operations_total, 4, "Timeout darf nicht als echter Vorgang zählen")
            self.assertEqual(rep_mid.timeouts_total, 1, "Timeout muss als Kennzahl separat ausgewiesen werden")
            self.assertEqual(rep_mid.approvals_total, 4)
            self.assertEqual(rep_mid.denials_total, 0)
            self.assertGreaterEqual(rep_mid.days_since_first_op, 2.9)
            self.assertLessEqual(rep_mid.days_since_first_op, 3.1)
            self.assertEqual(rep_mid.unclear_outcomes_total, 0)
            self.assertEqual(rep_mid.gate_status, "OFFEN", "4 Vorgänge und 3 Tage reichen noch nicht für Launch Gate")

            # 3. Kriterium erfüllen: Neue log-Datei mit 21 echten Vorgängen über 8 Tage
            conf.audit_log.unlink()
            Path(str(conf.audit_log) + ".head").unlink(missing_ok=True)
            
            eight_days_ago = now - (8.5 * 86400)
            cur_t = eight_days_ago
            def clock_8d():
                nonlocal cur_t
                val = cur_t
                cur_t += (8.0 * 86400) / 30.0  # verteilt über 8 Tage
                return val

            log_met = audit.AuditLog(conf.audit_log, priv, now=clock_8d)
            for i in range(1, 22):
                log_met.append("preview", f"tw-{i}", "aufgabe_anlegen", decision="confirm")
                log_met.append("decision", f"tw-{i}", "aufgabe_anlegen", decision="approve" if i != 10 else "deny",
                               by="web:marco" if i != 10 else "elicitation:claude")
                if i != 10:
                    log_met.append("execution_started", f"tw-{i}", "aufgabe_anlegen")
                    log_met.append("result", f"tw-{i}", "aufgabe_anlegen")
                    log_met.append("readback", f"tw-{i}", "aufgabe_anlegen", readback="ok")
                    log_met.append("execution_resolved", f"tw-{i}", "aufgabe_anlegen")

            rep_met = evaluate_pilot_status(conf, now=now)
            self.assertTrue(rep_met.audit_verified)
            self.assertEqual(rep_met.real_operations_total, 21)
            self.assertEqual(rep_met.approvals_total, 20)
            self.assertEqual(rep_met.denials_total, 1)
            self.assertGreaterEqual(rep_met.days_since_first_op, 7.5)
            self.assertEqual(rep_met.unclear_outcomes_total, 0)
            self.assertEqual(rep_met.gate_status, "ERFUELLT", ">=20 Vorgänge und >=7 Tage -> Gate erfüllt!")

    def test_unclear_and_tampered_prevents_erfuellt(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            conf = make_conf_and_keys(d)
            priv = audit.load_private(conf.audit_key)
            now = time.time()
            ten_days_ago = now - (10 * 86400)
            cur_t = ten_days_ago
            def clock_10d():
                nonlocal cur_t
                cur_t += 100.0
                return cur_t

            log = audit.AuditLog(conf.audit_log, priv, now=clock_10d)
            # 22 Vorgänge vor 10 Tagen
            for i in range(1, 23):
                log.append("preview", f"tw-{i}", "aufgabe_anlegen", decision="confirm")
                log.append("decision", f"tw-{i}", "aufgabe_anlegen", decision="approve", by="web:marco")
                log.append("execution_started", f"tw-{i}", "aufgabe_anlegen")
                if i == 5:
                    # Ein unklarer Ausgang: Tool bleibt blockiert
                    log.append("execution_blocked", f"tw-{i}", "aufgabe_anlegen", note="upstream timeout")
                else:
                    log.append("result", f"tw-{i}", "aufgabe_anlegen")
                    log.append("readback", f"tw-{i}", "aufgabe_anlegen", readback="ok")
                    log.append("execution_resolved", f"tw-{i}", "aufgabe_anlegen")

            rep = evaluate_pilot_status(conf, now=now)
            self.assertTrue(rep.audit_verified)
            self.assertEqual(rep.real_operations_total, 22)
            self.assertEqual(rep.unclear_outcomes_total, 1)

            # Nun manipulieren wir das Log (Tampering)
            lines = conf.audit_log.read_text(encoding="utf-8").splitlines()
            tampered_entry = json.loads(lines[3])
            tampered_entry["note"] = "tampered note"
            lines[3] = json.dumps(tampered_entry)
            conf.audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

            rep_tampered = evaluate_pilot_status(conf, now=now)
            self.assertFalse(rep_tampered.audit_verified)
            self.assertEqual(rep_tampered.gate_status, "OFFEN", "Manipuliertes Log darf niemals ERFUELLT sein")

    def test_timeouts_do_not_count_towards_real_operations(self):
        """P2 Befund: Timeouts bedeuten kein menschliches Handeln und dürfen das Gate nicht erfüllen."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            conf = make_conf_and_keys(d)
            priv = audit.load_private(conf.audit_key)
            now = time.time()
            ten_days_ago = now - (10 * 86400)
            cur_t = ten_days_ago
            def clock():
                nonlocal cur_t
                cur_t += 3600.0
                return cur_t

            log = audit.AuditLog(conf.audit_log, priv, now=clock)

            # 25 Timeouts über 10 Tage (Liegenlassen)
            for i in range(1, 26):
                log.append("preview", f"tw-{i}", "aufgabe_anlegen", decision="confirm")
                log.append("decision", f"tw-{i}", "aufgabe_anlegen", decision="deny", by="timeout", note="no decision within 120s")

            rep = evaluate_pilot_status(conf, now=now)
            self.assertTrue(rep.audit_verified)
            self.assertEqual(rep.real_operations_total, 0, "Timeouts dürfen 0 echte Vorgänge zählen")
            self.assertEqual(rep.timeouts_total, 25, "Alle 25 Timeouts müssen gezählt werden")
            self.assertEqual(rep.gate_status, "OFFEN", "Gate darf trotz 25 Timeouts und 10 Tagen niemals ERFUELLT sein")

    def test_missing_head_warning_prevents_erfuellt(self):
        """P2 Befund CODEX: Verifier-Warnungen (z. B. fehlender Head Sidecar) dürfen kein erfülltes Launch-Gate ergeben."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            conf = make_conf_and_keys(d)
            priv = audit.load_private(conf.audit_key)
            now = time.time()
            ten_days_ago = now - (10 * 86400)
            cur_t = ten_days_ago
            def clock():
                nonlocal cur_t
                cur_t += 3600.0
                return cur_t

            log = audit.AuditLog(conf.audit_log, priv, now=clock)
            for i in range(1, 22):
                log.append("preview", f"tw-{i}", "aufgabe_anlegen", decision="confirm")
                log.append("decision", f"tw-{i}", "aufgabe_anlegen", decision="approve", by="web:marco")
                log.append("execution_started", f"tw-{i}", "aufgabe_anlegen")
                log.append("result", f"tw-{i}", "aufgabe_anlegen")
                log.append("readback", f"tw-{i}", "aufgabe_anlegen", readback="ok")
                log.append("execution_resolved", f"tw-{i}", "aufgabe_anlegen")

            # Vor Entfernung des Heads: Gate erfüllt
            rep_clean = evaluate_pilot_status(conf, now=now)
            self.assertEqual(rep_clean.gate_status, "ERFUELLT")
            self.assertEqual(rep_clean.audit_warnings, [])

            # Nun entfernen wir den Head Sidecar (.head)
            head_path = Path(str(conf.audit_log) + ".head")
            head_path.unlink()

            rep_warn = evaluate_pilot_status(conf, now=now)
            self.assertTrue(rep_warn.audit_verified, "Log selbst ist intern integer")
            self.assertGreater(len(rep_warn.audit_warnings), 0, "Warnung über fehlenden Head muss erfasst sein")
            self.assertIn("head sidecar missing", rep_warn.audit_warnings[0])
            self.assertEqual(rep_warn.gate_status, "OFFEN", "Fehlender Head ist unvollständige Evidenz -> Gate bleibt OFFEN")
            self.assertFalse(rep_warn.to_dict()["gate"]["audit_clean"])

    def test_cli_pilot_status_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            conf = make_conf_and_keys(d)
            log = audit.AuditLog(conf.audit_log, audit.load_private(conf.audit_key))
            log.append("preview", "tw-1", "aufgabe_anlegen", decision="confirm")
            log.append("decision", "tw-1", "aufgabe_anlegen", decision="approve", by="web:marco")

            conf_path = str(d / "torwaechter.yaml")

            # 1. Standardaufruf: kurz + JSON
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                rc = cli.main(["pilot-status", "--config", conf_path])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("[torwaechter pilot-status] Gate-Ampel:", out)
            self.assertIn("JSON:", out)
            self.assertIn('"gate":', out)

            # 2. Flag --json: reines JSON
            buf_json = io.StringIO()
            with patch("sys.stdout", buf_json):
                rc = cli.main(["pilot-status", "--config", conf_path, "--json"])
            self.assertEqual(rc, 0)
            parsed = json.loads(buf_json.getvalue())
            self.assertIn("gate", parsed)
            self.assertEqual(parsed["gate"]["status"], "OFFEN")
            self.assertEqual(parsed["metrics"]["real_operations"], 1)


if __name__ == "__main__":
    unittest.main()
