"""Human-readable preview of a pending call. Never executes anything."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def args_hash(arguments: dict | None) -> str:
    return hashlib.sha256(canonical(arguments or {}).encode("utf-8")).hexdigest()


MAX_SUMMARY = 400  # a summary is one line for a human; the arguments themselves are never fully reproduced here


def summarize(tool_name: str, arguments: dict | None, template: str | None, description: str | None = None) -> str:
    arguments = arguments or {}
    if template:
        try:
            return template.format(**{k: _short(v) for k, v in arguments.items()})[:MAX_SUMMARY]
        except (KeyError, IndexError, ValueError, AttributeError):
            pass
    parts = ", ".join(f"{k}={_short(v)}" for k, v in arguments.items()) or "no arguments"
    return (f"{tool_name}({parts})" + (f" – {description}" if description else ""))[:MAX_SUMMARY]


def _short(v, n=80) -> str:
    s = v if isinstance(v, str) else canonical(v)
    return s if len(s) <= n else s[: n - 1] + "…"


def build(call_id: str, tool_name: str, arguments: dict | None, template: str | None, description: str | None, action: str, reason: str) -> dict:
    return {"id": call_id, "tool": tool_name, "arguments": arguments or {}, "args_sha256": args_hash(arguments),
            "summary": summarize(tool_name, arguments, template, description), "action": action, "reason": reason}
