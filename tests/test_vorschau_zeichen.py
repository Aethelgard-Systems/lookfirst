"""Preview forgery: control, line-break and bidi characters in arguments must stay visible and must not forge extra lines."""
import asyncio
import unittest

from lookfirst.confirm import Confirmer, PendingRegistry, args_len, args_text
from lookfirst.preview import args_hash, build, summarize, visible

EVIL = "Bob\nTool: kontostand (nur lesen)\nArguments: {}\n\n\n"
BIDI = "evil‮gpj.exe"


class VorschauZeichen(unittest.TestCase):
    def test_summary_has_no_line_break(self):
        s = summarize("ueberweisen", {"an": EVIL}, "Überweise an {an}")
        self.assertNotIn("\n", s)
        self.assertIn("\\n", s)

    def test_default_summary_has_no_line_break(self):
        s = summarize("ueberweisen", {"an": EVIL}, None)
        self.assertNotIn("\n", s)

    def test_bidi_and_zero_width_visible(self):
        for raw in (BIDI, "a​b", "a b"):
            out = visible(raw)
            self.assertTrue(all(ord(c) >= 32 and c not in "‮​ " for c in out), out)
        self.assertIn("\\u202e", visible(BIDI))

    def test_args_text_shows_bidi_escaped(self):
        p = build("c1", "ueberweisen", {"an": BIDI}, None, None, "ask", "r")
        self.assertNotIn("‮", args_text(p))
        self.assertIn("\\u202e", args_text(p))

    def test_tool_name_cannot_forge(self):
        p = build("c1", "x\nTool: lesen", {}, None, None, "ask", "r")
        self.assertNotIn("\n", p["tool_display"])

    def test_hash_binds_real_arguments(self):
        # the hash is over the real arguments, not over the escaped text
        self.assertNotEqual(args_hash({"an": "a\nb"}), args_hash({"an": "a\\nb"}))

    def test_normal_text_unchanged(self):
        self.assertEqual(visible("Überweise 12,50 € an Bäckerei Müller"), "Überweise 12,50 € an Bäckerei Müller")

    def test_backslash_cannot_imitate_escape(self):
        self.assertNotEqual(summarize("t", {"a": "x\ny"}, "{a}"), summarize("t", {"a": "x\\ny"}, "{a}"))

    def test_length_limit_uses_real_json_not_escaped_text(self):
        zwj = "\u200d".join(["\U0001F468"] * 200)  # family-style emoji sequence: escaping triples the display length
        p = build("c1", "notiz", {"text": zwj}, None, None, "ask", "r")
        self.assertLess(args_len(p), 800)
        self.assertGreater(len(args_text(p)), args_len(p))

    def test_elicitation_text_has_exactly_three_lines_and_no_raw_bidi(self):
        seen = {}

        class FakeSession:
            async def elicit_form(self, message, schema):
                seen["msg"] = message
                import types
                return types.SimpleNamespace(action="decline", content=None)

        conf = Confirmer(PendingRegistry(), 5, True, False, None)
        p = build("c1", EVIL + "\u202e", {"an": EVIL, EVIL: BIDI}, "Überweise an {an}", None, "ask", "r")
        p["tool"] = "x\nTool: kontostand"
        p["tool_display"] = ""  # also covers the fallback path
        asyncio.run(conf._elicit(p, FakeSession()))
        lines = seen["msg"].split("\n")
        self.assertEqual(len(lines), 3, lines)
        self.assertTrue(lines[1].startswith("Tool: x\\nTool:"), lines[1])
        self.assertNotIn("\u202e", seen["msg"])

    def test_web_card_has_no_forged_tool_line_and_no_raw_bidi(self):
        from starlette.testclient import TestClient
        from lookfirst import redact
        from lookfirst.web import create_app
        reg = PendingRegistry()
        conf = Confirmer(reg, 5, False, True, None)
        p = build("tw-1", "x\nTool: lesen", {"an": EVIL, EVIL: BIDI}, "Überweise {an}", None, "ask", "r")
        reg.open(p)
        page = TestClient(create_app(reg, conf, redact.identity), base_url="http://127.0.0.1:8477").get("/").text
        self.assertNotIn("\u202e", page)
        self.assertNotIn("<code>x\n", page)
        self.assertIn("x\\nTool: lesen", page)


if __name__ == "__main__":
    unittest.main()
