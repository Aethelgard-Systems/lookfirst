"""Human-readable preview of a pending call. Never executes anything."""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def args_hash(arguments: dict | None) -> str:
    return hashlib.sha256(canonical(arguments or {}).encode("utf-8")).hexdigest()


def visible(text: str, keep_layout: bool = False, json_text: bool = False) -> str:
    """Make control, line-break and invisible/bidi characters visible (``\\n``, ``\\u202e``) so an argument cannot
    forge extra lines or reverse text in what the human reads. The args hash is computed on the real arguments."""
    # json_text: backslashes already are JSON escapes; plain text: a real backslash is doubled so it cannot imitate an escape
    return "".join(c if keep_layout and c in "\n " or (json_text and c == "\\") else _escape(c) for c in text)


# Letters/symbols that render as empty space or invisible marks (Default_Ignorable_Code_Point in category Mn,
# Hangul fillers, empty Braille pattern, Mongolian variation/vowel separators, Khmer inherent vowels,
# combining grapheme joiner, Khitan small script filler, ideographic half fill space and object replacement):
_INVISIBLE_MARKS = frozenset(
    "\u034f"                    # COMBINING GRAPHEME JOINER (Mn, Default_Ignorable)
    "\u115f\u1160"              # HANGUL CHOSEONG/JUNGSEONG FILLER (Lo, Default_Ignorable)
    "\u17b4\u17b5"              # KHMER VOWEL INHERENT AQ/AA (Mn, Default_Ignorable)
    "\u180b\u180c\u180d\u180f"  # MONGOLIAN FREE VARIATION SELECTORS 1-4 (Mn, Default_Ignorable)
    "\u180e"                    # MONGOLIAN VOWEL SEPARATOR (Cf, Default_Ignorable)
    "\u2800"                    # BRAILLE PATTERN BLANK (So)
    "\u303f"                    # IDEOGRAPHIC HALF FILL SPACE (So)
    "\u3164"                    # HANGUL FILLER (Lo, Default_Ignorable)
    "\uffa0"                    # HALFWIDTH HANGUL FILLER (Lo, Default_Ignorable)
    "\ufffc"                    # OBJECT REPLACEMENT CHARACTER (So)
    "\U00016fe4"                # KHITAN SMALL SCRIPT FILLER (Mn)
)
_BLANK_FILLERS = _INVISIBLE_MARKS


def _escape(c: str) -> str:
    if c == "\\":
        return "\\\\"
    if c == "\n":
        return "\\n"
    if c == "\r":
        return "\\r"
    if c == "\t":
        return "\\t"
    # Zs: every space except U+0020 (NBSP, ideographic space ...) and blank-looking fillers are invisible or look like spaces
    if (unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")
            or (c != " " and unicodedata.category(c) == "Zs")
            or c in _INVISIBLE_MARKS
            or "\ufe00" <= c <= "\ufe0f"
            or "\U000e0100" <= c <= "\U000e01ef"):
        return f"\\u{ord(c):04x}" if ord(c) < 0x10000 else f"\\U{ord(c):08x}"
    return c


MAX_SUMMARY = 400  # a summary is one line for a human; the arguments themselves are never fully reproduced here


def summarize(tool_name: str, arguments: dict | None, template: str | None, description: str | None = None) -> str:
    arguments = arguments or {}
    if template:
        try:
            return visible(template.format(**{k: _short(v) for k, v in arguments.items()}))[:MAX_SUMMARY]
        except (KeyError, IndexError, ValueError, AttributeError):
            pass
    parts = ", ".join(f"{k}={_short(v)}" for k, v in arguments.items()) or "no arguments"
    return visible(f"{tool_name}({parts})" + (f" – {description}" if description else ""))[:MAX_SUMMARY]


def _short(v, n=80) -> str:
    s = v if isinstance(v, str) else canonical(v)
    return s if len(s) <= n else s[: n - 1] + "…"


def build(call_id: str, tool_name: str, arguments: dict | None, template: str | None, description: str | None, action: str, reason: str) -> dict:
    return {"id": call_id, "tool": tool_name, "arguments": arguments or {}, "args_sha256": args_hash(arguments),
            "tool_display": visible(tool_name), "summary": summarize(tool_name, arguments, template, description), "action": action, "reason": reason}
