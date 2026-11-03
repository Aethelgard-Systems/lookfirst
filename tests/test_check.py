"""#668 P6: ``lookfirst check`` – understandable output, exit codes, no secrets. Synthetic data only."""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from lookfirst import audit, check, cli
from tests.helpers import DEFAULT_RULES, bank_server, serve_in_memory

DEMO = Path(__file__).resolve().parent.parent / "demo"


async def in_memory_probe(up, timeout):
    async with serve_in_memory(bank_server({"saldo": 1.0, "calls": []})) as s:
        return [tool.name for tool in (await s.list_tools()).tools]


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, data: dict, key=True) -> str:
        base = {"upstreams": {"bank": {"command": "true"}}, "rules": DEFAULT_RULES,
                "confirm": {"timeout_seconds": 5, "elicitation": True, "web": {"host": "127.0.0.1", "port": 8477}},
                "audit": {"log": "audit.jsonl", "key": "key.pem"}}
        base.update(data)
        path = self.dir / "lookfirst.yaml"
        path.write_text(yaml.safe_dump(base), encoding="utf-8")
        if key and not (self.dir / "key.pem").exists():
            audit.generate_key(self.dir / "key.pem")
        return str(path)

    def test_bad_config_is_explained_exit_2(self):
        bad = dict(DEFAULT_RULES, tools={"ueberweisung": {"action": "vielleicht"}})
        code, out = check.run(self.write({"rules": bad}), probe=in_memory_probe)
        self.assertEqual(code, 2)
        self.assertIn("ERROR  config", out)
        self.assertIn("rules.tools.ueberweisung: action must be one of", out)
        self.assertIn("1 error(s)", out)
        code, out = check.run(str(self.dir / "fehlt.yaml"))
        self.assertEqual(code, 2)
        self.assertIn("file not found", out)

    def test_missing_key_points_to_keygen(self):
        path = self.write({}, key=False)
        code, out = check.run(path, probe=in_memory_probe)
        self.assertEqual(code, 2)
        line = next(x for x in out.splitlines() if x.startswith("ERROR  audit key"))
        self.assertIn(f"lookfirst keygen --config {path}", line)

    def test_good_config_exit_0_and_unmatched_rule_is_warning(self):
        code, out = check.run(self.write({}), probe=in_memory_probe)
        self.assertEqual(code, 0, out)
        self.assertNotIn("ERROR", out)
        self.assertIn("OK     upstream   bank", out)
        self.assertIn("all 2 tool rule(s) match a tool", out)
        rules = dict(DEFAULT_RULES, tools={**DEFAULT_RULES["tools"], "bank.loeschen": {"action": "deny"}})
        code, out = check.run(self.write({"rules": rules}), probe=in_memory_probe)
        self.assertEqual(code, 0, out)
        self.assertIn("WARN   rules      rule 'bank.loeschen' matches no tool", out)

    def test_token_file_problems_never_print_the_token(self):
        (self.dir / "token").write_text("kurz-SYNTHETISCH", encoding="utf-8")
        code, out = check.run(self.write({"http": {"token_file": "token"}}), probe=in_memory_probe)
        self.assertEqual(code, 2)
        self.assertIn("ERROR  http", out)
        self.assertNotIn("kurz-SYNTHETISCH", out)
        good = "x" * 40
        (self.dir / "token").write_text(good, encoding="utf-8")
        code, out = check.run(self.write({"http": {"token_file": "token"}}), probe=in_memory_probe)
        self.assertEqual(code, 0, out)
        self.assertNotIn(good, out)

    def test_unreachable_upstream_and_url_without_credentials(self):
        cfgp = self.write({"upstreams": {"bank": {"command": str(self.dir / "gibt-es-nicht")},
                                         "crm": {"url": "http://nutzer:GEHEIM@127.0.0.1:9/mcp?key=GEHEIM"}}})
        code, out = check.run(cfgp, timeout=5)
        self.assertEqual(code, 2)
        self.assertIn("ERROR  upstream   bank", out)
        self.assertIn("ERROR  upstream   crm (http://127.0.0.1:9/mcp) not reachable", out)
        self.assertNotIn("GEHEIM", out)
        self.assertIn("tool names not checked", out)

    def test_malformed_upstream_url_is_error_not_traceback(self):
        """WORK #684: bad port / broken IPv6 → ERROR upstream + exit 2, other checks still run, no secrets."""
        probed = []

        async def probe(up, timeout):
            probed.append(up.url or up.command)
            return await in_memory_probe(up, timeout)

        for url in ("http://nutzer:GEHEIM@localhost:abc/mcp?key=GEHEIM", "http://nutzer:GEHEIM@[::1/mcp?key=GEHEIM",
                    "http://nutzer:GEHEIM@localhost:99999/mcp", "ftp://nutzer:GEHEIM@127.0.0.1/mcp"):
            probed.clear()
            code, out = check.run(self.write({"upstreams": {"bank": {"command": "true"}, "crm": {"url": url}}}), probe=probe)
            self.assertEqual(code, 2, out)
            line = next(x for x in out.splitlines() if x.startswith("ERROR  upstream   crm"))
            self.assertIn("invalid url", line)
            self.assertIn("OK     upstream   bank", out)
            self.assertIn("OK     audit key", out)
            self.assertIn("tool names not checked", out)
            self.assertNotIn("GEHEIM", out)
            self.assertNotIn("Traceback", out)
            self.assertEqual(probed, ["true"], "a malformed url must not be probed")
        self.assertEqual(check.safe_url("http://localhost:abc/mcp"), "(invalid url)")

    def test_real_stdio_upstream_via_cli(self):
        """End to end through the CLI with the demo bank as a real subprocess."""
        for f in ("bank_server.py", "namen.txt"):
            (self.dir / f).write_text((DEMO / f).read_text(encoding="utf-8"), encoding="utf-8")
        data = yaml.safe_load((DEMO / "lookfirst.yaml").read_text(encoding="utf-8"))
        data["upstreams"]["bank"]["command"] = sys.executable
        (self.dir / "lookfirst.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
        args = ["check", "--config", str(self.dir / "lookfirst.yaml"), "--timeout", "20"]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(args), 2)  # no key yet
        self.assertIn("lookfirst keygen", buf.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            cli.main(["keygen", "--config", str(self.dir / "lookfirst.yaml")])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(args), 0, buf.getvalue())
        self.assertIn("OK     upstream   bank (command", buf.getvalue())
        self.assertIn("schleuse   on: IBAN, EMAIL", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
