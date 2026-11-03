"""Datenschutz-Schleuse (#604): private Angaben verlassen das Haus nur als Platzhalter.

Weg A – Ergebnis → Modell: Bevor eine Werkzeug-Antwort (Text und strukturierter Inhalt) an den KI-Client geht, werden
erkannte private Angaben durch Platzhalter wie ``[[IBAN_3f9a1c]]`` ersetzt. Das gilt für jede Antwort des Torwächters,
auch für Ablehnungs- und Rücklese-Texte.

Weg B – Modell → lokales Werkzeug: Verwendet der Client einen Platzhalter in Argumenten, übersetzt der Torwächter ihn
lokal zurück – aber nur Platzhalter, die **diese** Schleuse selbst ausgegeben hat. Ein unbekannter Platzhalter wird
abgelehnt (das Modell kann keine Daten „erraten“ und auflösen lassen).

Grundsätze: Erkennung deterministisch (Muster + Prüfziffern + eigene Namensliste), keine KI. Platzhalter sind zufällig
(kein Hash des Originals → kein Wörterbuch-Angriff auf kurze Werte). Zuordnung nur im Arbeitsspeicher, begrenzt und mit
Ablauf. Grenze: Die Schleuse reduziert den Abfluss, sie anonymisiert nicht vollständig – Beträge, Daten und Händler im
Kontext bleiben deutbar.
"""
from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

PLACEHOLDER = re.compile(r"\[\[([A-Z][A-Z0-9_]{1,23})_([0-9a-f]{6,64})\]\]")   # weit erkennen, nur eigene (32 hex) auflösbar

IBAN = re.compile(r"\b[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,30}\b")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+\b")
PHONE = re.compile(r"(?<![\w+])(?:\+\d{2,3}[ /-]?|0)\d{2,5}(?:[ /-]?\d{2,8}){1,3}(?![\w])")
CARD = re.compile(r"\b\d{4}(?:[ -]?\d{4}){2,3}(?:[ -]?\d{1,3})?\b")  # 4er-Gruppen; nie lange Ziffernketten verschlucken


# Zugangsdaten mit bekannter Form (#604-Folgeschritt, Cloakroom-Vergleich 27.10.; Musterliste angelehnt an
# shanjeevrajendran/cloakroom rules.py @a242de3, Apache-2.0, eigene Ausdrücke). Ganzer Treffer wird ersetzt.
SECRET_SHAPES = [
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----",
    r"\b(?:AKIA|ASIA)[A-Z2-7]{16}\b",                                  # AWS-Schlüssel-ID
    r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}",  # GitHub
    r"\bsk-ant-[A-Za-z0-9_-]{20,}",                                     # Anthropic
    r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}",               # OpenAI
    r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",                   # Stripe
    r"\bxox[abposr]-[A-Za-z0-9-]{10,}",                                 # Slack
    r"\bhf_[A-Za-z0-9]{30,}\b",                                        # Hugging Face
    r"\bAIza[0-9A-Za-z_-]{35}\b",                                      # Google-API
    r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",  # JWT
]
# Benannter Wert: nur der Wert wird ersetzt, der Schlüsselname bleibt lesbar („password=[[GEHEIMNIS_…]]“).
SECRET_KEYED = (r"(?i:(?:\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<url>(?:(?!\[\[[A-Z][A-Z0-9_]{1,23}_[0-9a-f]{6,64}\]\])[^\s@/]){3,})@)"
                r"|(?:\b(?:password|passwd|passwort|kennwort|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key"
                r"|auth[_-]?token|client[_-]?secret|private[_-]?key)[\"']?\s*[:=]\s*[\"']?(?:(?:bearer|basic|token)\s+)?"
                r"(?P<val>(?:(?!\[\[[A-Z][A-Z0-9_]{1,23}_[0-9a-f]{6,64}\]\])[^\s\"',;]){8,}))"
                r"|(?:\bAuthorization:\s*(?:Bearer|Basic|Token)\s+(?P<hdr>(?:(?!\[\[[A-Z][A-Z0-9_]{1,23}_[0-9a-f]{6,64}\]\])[^\s\"',;]){8,})))")
# WORK-Review #661: Ein Wert endet nur vor einem vollständigen Platzhalter „[[LABEL_hex]]“ (geschützte Spanne); Klammern und
# platzhalterähnlicher Text im Wert selbst („Abcd[[ABC]]x“) bleiben Teil des Werts.
SECRET_KEY_NAME = re.compile(r"(?i)^[\"']?(?:password|passwd|passwort|kennwort|passphrase|pwd|secret|token|api[_-]?key|access[_-]?key"
                             r"|auth[_-]?token|client[_-]?secret|private[_-]?key|authorization)[\"']?$")
SECRET = re.compile("|".join("(?:" + x + ")" for x in SECRET_SHAPES) + "|" + SECRET_KEYED)


def _iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1
    except ValueError:
        return False


def _luhn_ok(raw: str) -> bool:
    d = [int(c) for c in raw if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            n -= 9 if n > 9 else 0
        total += n
    return total % 10 == 0


def _phone_ok(raw: str) -> bool:
    digits = sum(c.isdigit() for c in raw)
    return 8 <= digits <= 15


BUILTIN: dict[str, tuple[re.Pattern, Callable[[str], bool] | None]] = {
    "IBAN": (IBAN, _iban_ok),
    "KARTE": (CARD, _luhn_ok),
    "EMAIL": (EMAIL, None),
    "TELEFON": (PHONE, _phone_ok),
    "GEHEIMNIS": (SECRET, None),
}


def _internal(key, value) -> bool:
    if not isinstance(key, str) or not isinstance(value, str):
        return False
    if key.endswith("sha256"):
        return re.fullmatch(r"[0-9a-f]{64}", value) is not None
    if key in ("id", "call_id"):
        return re.fullmatch(r"tw-[0-9a-f]{16}", value) is not None
    return False


class SchleuseError(ValueError):
    """A call refers to a placeholder this gate never issued (or one that expired)."""


@dataclass
class Schleuse:
    detect: tuple[str, ...] = ("IBAN", "KARTE", "EMAIL", "TELEFON", "GEHEIMNIS")
    names: tuple[str, ...] = ()
    patterns: dict[str, str] = field(default_factory=dict)
    ttl_seconds: float = 8 * 3600
    max_entries: int = 10000
    max_failures: int = 3
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self):
        unknown = set(self.detect) - set(BUILTIN)
        if unknown:
            raise ValueError(f"schleuse.detect: unknown {sorted(unknown)}")
        # Zugangsdaten zuerst: sonst schnappt z. B. EMAIL „passwort@host“ aus einer URL mit Kennwort.
        order = sorted(self.detect, key=lambda k: k != "GEHEIMNIS")
        self._rules: list[tuple[str, re.Pattern, Callable[[str], bool] | None]] = [(k, *BUILTIN[k]) for k in order]
        for label, rx in self.patterns.items():
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,23}", label):
                raise ValueError(f"schleuse.patterns: label {label!r} must be UPPER_CASE")
            self._rules.append((label, re.compile(rx), None))
        clean = sorted({n.strip() for n in self.names if len(n.strip()) >= 3}, key=len, reverse=True)
        if clean:
            self._rules.append(("NAME", re.compile(r"(?<!\w)(?:" + "|".join(re.escape(n) for n in clean) + r")(?!\w)", re.IGNORECASE), None))
        self._by_token: dict[str, tuple[str, float]] = {}
        self._by_value: dict[tuple[str, str], str] = {}
        self.counts = {"ersetzt": 0, "aufgeloest": 0, "fehlversuche": 0}

    @classmethod
    def from_config(cls, data: dict | None, base: Path) -> "Schleuse | None":
        if not data or data.get("enabled") is False:
            return None
        names: list[str] = []
        if data.get("names_file"):
            names = (base / str(data["names_file"])).read_text(encoding="utf-8").splitlines()
        return cls(detect=tuple(data.get("detect", ("IBAN", "KARTE", "EMAIL", "TELEFON", "GEHEIMNIS"))), names=tuple(names),
                   patterns=dict(data.get("patterns") or {}), ttl_seconds=float(data.get("ttl_seconds", 8 * 3600)))

    # ---- Weg A: Text → Platzhalter -------------------------------------------------------------------------------------
    def _token(self, label: str, value: str) -> str:
        now = self.clock()
        key = (label, value)
        tok = self._by_value.get(key)
        if tok and now - self._by_token[tok][1] <= self.ttl_seconds:
            return tok
        if len(self._by_token) >= self.max_entries:
            self._expire(now, force=True)
        tok = f"[[{label}_{secrets.token_hex(16)}]]"   # 128 Bit: nicht erratbar
        self._by_token[tok] = (value, now)
        self._by_value[key] = tok
        return tok

    def _expire(self, now: float, force: bool = False):
        old = [t for t, (_, ts) in self._by_token.items() if now - ts > self.ttl_seconds]
        if force and not old:
            old = sorted(self._by_token, key=lambda t: self._by_token[t][1])[: max(1, len(self._by_token) // 10)]
        for t in old:
            value, _ = self._by_token.pop(t)
            self._by_value = {k: v for k, v in self._by_value.items() if v != t}

    def mask_text(self, text: str) -> str:
        if not isinstance(text, str) or not text:
            return text
        for label, rx, ok in self._rules:
            def repl(m, label=label, ok=ok):
                raw = m.group(0)
                if PLACEHOLDER.fullmatch(raw):
                    return raw
                if label == "IBAN":
                    # Greedy match may swallow following upper-case words ("… 00 EUR"): longest valid prefix wins.
                    for end in range(len(raw), 14, -1):
                        cand = raw[:end]
                        if not cand.endswith(" ") and _iban_ok(cand):
                            self.counts["ersetzt"] += 1
                            return self._token(label, cand) + raw[end:]
                    # Fail-closed: looks like an IBAN but no valid checksum (typo?) – mask it anyway, minus trailing words.
                    core = re.sub(r"(?:[ ][A-Za-z]{2,})+$", "", raw)
                    self.counts["ersetzt"] += 1
                    return self._token(label, core) + raw[len(core):]
                if label == "GEHEIMNIS":
                    named = next(((g, m.start(g), m.end(g)) for g in ("url", "val", "hdr") if m.group(g)), None)
                    if named:  # nur den Wert ersetzen
                        g, a, b = named
                        if PLACEHOLDER.fullmatch(m.group(g)):
                            return raw
                        self.counts["ersetzt"] += 1
                        off = m.start(0)
                        return raw[: a - off] + self._token(label, m.group(g)) + raw[b - off:]
                if ok and not ok(raw):
                    return raw
                self.counts["ersetzt"] += 1
                return self._token(label, raw)
            text = rx.sub(repl, text)
        return text

    def mask(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.mask_text(value)
        if isinstance(value, list):
            return [self.mask(v) for v in value]
        if isinstance(value, dict):
            # Nur nachweislich interne Formate bleiben: SHA-256-Hex in *sha256-Feldern, Gate-IDs „tw-“+16 hex. Alles andere wird geprüft.
            out = {}
            for k, v in value.items():
                if _internal(k, v):
                    out[k] = v
                elif ("GEHEIMNIS" in self.detect and isinstance(k, str) and SECRET_KEY_NAME.fullmatch(k)
                      and isinstance(v, str) and len(v) >= 4 and not PLACEHOLDER.fullmatch(v)):
                    # Getrennter JSON-Schlüssel/Wert (WORK-Review #661): {"password": "…"} → ganzer Wert ist Geheimnis
                    self.counts["ersetzt"] += 1
                    out[k] = self._token("GEHEIMNIS", v)
                else:
                    out[k] = self.mask(v)
            return {self.mask_text(k) if isinstance(k, str) else k: v for k, v in out.items()}
        return value

    # ---- Weg B: Platzhalter → Original (nur eigene) --------------------------------------------------------------------
    def resolve(self, value: Any) -> Any:
        if isinstance(value, str):
            def repl(m):
                tok = m.group(0)
                if self.counts["fehlversuche"] >= self.max_failures:
                    raise SchleuseError("too many unknown placeholders in this session – resolution locked")
                hit = self._by_token.get(tok)
                if hit is None or self.clock() - hit[1] > self.ttl_seconds:
                    self.counts["fehlversuche"] += 1
                    raise SchleuseError(f"unknown or expired placeholder {tok}")
                self.counts["aufgeloest"] += 1
                return hit[0]
            return PLACEHOLDER.sub(repl, value)
        if isinstance(value, list):
            return [self.resolve(v) for v in value]
        if isinstance(value, dict):
            return {k: self.resolve(v) for k, v in value.items()}
        return value
