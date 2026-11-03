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

    def test_blank_looking_characters_are_visible(self):
        for raw in ("\u3000", "\u00a0", "\u2003", "\u3164", "\u115f", "\u2800", "\u180e"):
            out = visible("a" + raw + "b")
            self.assertNotIn(raw, out)
            self.assertIn("\\u", out)
        self.assertEqual(visible("a b"), "a b")  # the normal space stays
        self.assertEqual(visible("é"), "é")  # accented text stays readable

    def test_hard_cap_on_display_length_keeps_long_forms_out_of_elicitation(self):
        from lookfirst.confirm import MAX_ELICIT_ARGS, too_long_for_form
        tags = "".join(chr(0xE0000 + i) for i in range(60, 400))  # tag characters: tiny JSON, ten-fold escaped display
        p = build("c1", "notiz", {"text": tags}, None, None, "ask", "r")
        self.assertLess(args_len(p), MAX_ELICIT_ARGS)
        self.assertTrue(too_long_for_form(p))

    def test_webhook_body_carries_safe_display_fields(self):
        import json
        import tempfile
        sent = {}

        class Resp:
            def read(self):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(req, timeout=0):
            sent["body"] = json.loads(req.data.decode())
            return Resp()

        with tempfile.TemporaryDirectory() as d:
            import pathlib
            tok = pathlib.Path(d) / "t"
            tok.write_text("secret", encoding="utf-8")
            conf = Confirmer(PendingRegistry(), 5, False, False, {"url": "http://127.0.0.1:9/x", "token_file": str(tok)}, opener=opener)
            p = build("c1", "x\nTool: lesen", {"an": BIDI}, None, None, "ask", "r")
            conf._post_webhook(p)
        self.assertNotIn("\u202e", sent["body"]["arguments_display"])
        self.assertIn("\\u202e", sent["body"]["arguments_display"])
        self.assertNotIn("\n", sent["body"]["tool_display"])
        self.assertEqual(sent["body"]["arguments"], {"an": BIDI})  # machines get the real arguments

    def test_open_api_view_has_safe_display_fields(self):
        from starlette.testclient import TestClient
        from lookfirst import redact
        from lookfirst.web import create_app
        reg = PendingRegistry()
        conf = Confirmer(reg, 5, False, True, None)
        reg.open(build("tw-2", "x\nTool: lesen", {"an": BIDI}, None, None, "ask", "r"))
        data = TestClient(create_app(reg, conf, redact.identity), base_url="http://127.0.0.1:8477").get("/open").json()["open"][0]
        self.assertNotIn("\u202e", data["arguments_display"])
        self.assertNotIn("\n", data["tool_display"])


if __name__ == "__main__":
    unittest.main()
