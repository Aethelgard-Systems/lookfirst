"""Tests for the scripted offline demo and decision manipulation."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from torwaechter import demo


class TestDemo(unittest.TestCase):
    def test_demo_yes_and_no_manipulates_exact_decision_entry(self):
        for ans in ("y", "n"):
            with self.subTest(answer=ans):
                with tempfile.TemporaryDirectory() as tmp:
                    d = Path(tmp)
                    rc = demo.run_demo(answer=ans, keep=str(d))
                    self.assertEqual(rc, 0)
                    log_file = d / "torwaechter-audit.jsonl"
                    self.assertTrue(log_file.exists())
                    lines = [json.loads(l) for l in log_file.read_text(encoding="utf-8").splitlines()]
                    
                    # Finde den manipulierten Eintrag (by='auto', note='approved automatically')
                    tampered = [e for e in lines if e.get("by") == "auto"]
                    self.assertEqual(len(tampered), 1, "Genau ein Eintrag muss manipuliert sein")
                    self.assertEqual(tampered[0]["event"], "decision", "Manipulierter Eintrag muss das decision-Event sein")
                    self.assertEqual(tampered[0]["tool"], "ueberweisung", "Manipulierter Eintrag muss das Tool ueberweisung betreffen")
                    self.assertEqual(tampered[0]["seq"], 6, "Decision fuer ueberweisung muss Eintrag #6 sein")

                    # Bei Ablehnung (ans='n') muss der Grund 'user rejected' lauten (nicht 'action=accept')
                    if ans == "n":
                        # Beachte: tampered[0] hat by='auto' bekommen, aber vorher war die decision deny mit 'user rejected'
                        self.assertEqual(tampered[0]["decision"], "deny")
                        self.assertEqual(tampered[0]["note"], "approved automatically")

    def test_find_decision_index_without_decision_raises_error(self):
        sample_lines = [
            json.dumps({"seq": 1, "event": "start", "tool": "init"}),
            json.dumps({"seq": 2, "event": "call", "tool": "kontostand"}),
            json.dumps({"seq": 3, "event": "result", "tool": "kontostand"}),
        ]
        with self.assertRaises(RuntimeError) as cm:
            demo.find_decision_index(sample_lines)
        self.assertIn("no 'decision' entry", str(cm.exception))

    def test_find_decision_index_selects_ueberweisung_decision(self):
        sample_lines = [
            json.dumps({"seq": 1, "event": "start"}),
            json.dumps({"seq": 2, "event": "decision", "tool": "anderes_tool"}),
            json.dumps({"seq": 3, "event": "decision", "tool": "ueberweisung"}),
        ]
        self.assertEqual(demo.find_decision_index(sample_lines), 2)


if __name__ == "__main__":
    unittest.main()
