"""#604-Folgeschritt (Cloakroom-Vergleich, MARCO-Beschluss 27.10.): Zugangsdaten in Werkzeug-Antworten verlassen das Haus
nur als Platzhalter. Alle Werte synthetisch (keine echten Schlüssel)."""
import re
import unittest

from torwaechter.schleuse import PLACEHOLDER, Schleuse

FAKE = {
    "github": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "github_pat": "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnop",
    "anthropic": "sk-ant-" + "api03-abcdefghijklmnopqrstuv",
    "openai": "sk-proj-" + "abcdefghijklmnopqrstuvwx",
    "aws": "AKIA" + "ABCDEFGHIJKLMNOP",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJlLXN5bnRo",
    "key": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsynthetischAAAA\n-----END OPENSSH PRIVATE KEY-----",
}


class Geheimnis(unittest.TestCase):
    def setUp(self):
        self.s = Schleuse()

    def test_bekannte_formen_werden_ersetzt(self):
        for name, value in FAKE.items():
            with self.subTest(name=name):
                out = self.s.mask_text(f"Wert: {value} Ende")
                self.assertNotIn(value, out)
                self.assertRegex(out, r"\[\[GEHEIMNIS_[0-9a-f]{32}\]\]")

    def test_benannter_wert_nur_wert_ersetzt(self):
        cases = ["password=Sommer2026!x", 'api_key: "abcdef1234567890"', "Passwort: KaffeeTasse77",
                 "Authorization: Bearer abcdefghijklmno", "https://marco:SuperGeheim9@example.invalid/x"]
        for text in cases:
            with self.subTest(text=text):
                out = self.s.mask_text(text)
                self.assertIn("[[GEHEIMNIS_", out)
                self.assertNotRegex(out, r"Sommer2026|abcdef1234567890|KaffeeTasse77|abcdefghijklmno|SuperGeheim9")
        self.assertTrue(self.s.mask_text("password=Sommer2026!x").startswith("password=[[GEHEIMNIS_"))

    def test_harmlose_kontrollen_bleiben(self):
        for text in ["sk-learn ist eine Bibliothek", "Passwort vergessen?", "token budget 4000",
                     "Der Bearer-Token ist abgelaufen.", "Kontostand 1.234,56 EUR", "password reset link"]:
            with self.subTest(text=text):
                self.assertEqual(self.s.mask_text(text), text)

    def test_rueckweg_nur_eigene_platzhalter(self):
        out = self.s.mask_text(FAKE["github"])
        tok = PLACEHOLDER.search(out).group(0)
        self.assertEqual(self.s.resolve(tok), FAKE["github"])

    def test_platzhalter_wird_nicht_doppelt_maskiert(self):
        once = self.s.mask_text("token: " + FAKE["openai"])
        self.assertEqual(self.s.mask_text(once), once)

    def test_klammern_um_platzhalter_bleiben_heil(self):
        """WORK-Review #661: maskieren, in Klammern setzen, erneut maskieren → einmal auflösen ergibt den Originaltext."""
        once = self.s.mask_text("token: abcdef123456")
        for wrapped in (f"({once})", f"[{once}]", f"{{{once}}}", f"<{once}>"):
            with self.subTest(wrapped=wrapped):
                twice = self.s.mask_text(wrapped)
                self.assertEqual(twice, wrapped)
                self.assertEqual(self.s.resolve(twice), wrapped.replace(once, "token: abcdef123456"))

    def test_sonderzeichen_im_wert_ganz_maskiert(self):
        """WORK-Nachreview #661: Klammern sind echte Passwortzeichen."""
        for value in ("Abcd(Secret42)", "Synthetic(Secret42)", "x[y]{z}<w>Pass9", "Kl@mmer)(Test1",
                      "Abcd[[ABC]]Secret42", "[[NOTE_zz]]Secret42x"):
            with self.subTest(value=value):
                out = self.s.mask_text("password=" + value)
                self.assertNotIn("Secret42", out)
                self.assertNotIn(value, out)
                self.assertEqual(self.s.resolve(out), "password=" + value)

    def test_echter_platzhalter_neben_unechtem_stabil(self):
        once = self.s.mask_text("token: abcdef123456 und password=Abcd[[ABC]]Secret42")
        self.assertNotIn("Secret42", once)
        self.assertEqual(self.s.mask_text(once), once)
        self.assertEqual(self.s.resolve(once), "token: abcdef123456 und password=Abcd[[ABC]]Secret42")

    def test_mehrfach_maskieren_gemischt_stabil(self):
        raw = "(token: " + FAKE["openai"] + "), Mail an a.b@example.invalid [IBAN DE89370400440532013000]"
        once = self.s.mask_text(raw)
        twice = self.s.mask_text(f"({once})")
        thrice = self.s.mask_text(twice)
        self.assertEqual(twice, f"({once})")
        self.assertEqual(thrice, twice)
        self.assertEqual(self.s.resolve(thrice), f"({raw})")

    def test_getrennter_json_schluessel(self):
        out = self.s.mask({"password": "Kurz12", "Token": "abcd", "user": "synthetisch", "note": "kein geheimnis"})
        self.assertRegex(out["password"], r"^\[\[GEHEIMNIS_[0-9a-f]{32}\]\]$")
        self.assertRegex(out["Token"], r"^\[\[GEHEIMNIS_")
        self.assertEqual(out["user"], "synthetisch")
        self.assertEqual(out["note"], "kein geheimnis")
        self.assertEqual(self.s.resolve(out["password"]), "Kurz12")

    def test_interne_hashes_bleiben(self):
        h = "a" * 64
        self.assertEqual(self.s.mask({"sha256": h, "id": "tw-0123456789abcdef"}), {"sha256": h, "id": "tw-0123456789abcdef"})


if __name__ == "__main__":
    unittest.main()
