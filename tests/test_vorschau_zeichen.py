"""Preview forgery: control, line-break and bidi characters in arguments must stay visible and must not forge extra lines."""
import unittest

from lookfirst.confirm import args_text
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


if __name__ == "__main__":
    unittest.main()
