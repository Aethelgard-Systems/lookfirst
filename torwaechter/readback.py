"""Read-back after execution: call a *reading* tool and compare expected fields.

Result: ``ok`` (all expectations met) | ``unklar`` (read tool failed/unavailable or field missing) | ``fehlgeschlagen`` (value differs).
Placeholders in ``args``/``expect``: ``$args.<key>`` → argument of the executed call, ``$result.<key>`` → field of its structured
result (dotted paths allowed). A write is never reported as done without a read-back verdict.
"""
from __future__ import annotations

from typing import Any


def _resolve(value: Any, args: dict, result: dict | None):
    if isinstance(value, str) and value.startswith("$"):
        src, _, path = value[1:].partition(".")
        base = args if src == "args" else result if src == "result" else None
        return _dig(base, path)
    if isinstance(value, dict):
        return {k: _resolve(v, args, result) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, args, result) for v in value]
    return value


class Missing:
    pass


def _dig(obj, path: str):
    cur = obj
    for part in [p for p in path.split(".") if p]:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return Missing
    return cur


async def check(rule, call_args: dict, result_structured: dict | None, call_read) -> tuple[str, str]:
    """``call_read(tool, args)`` → (structured_result | None, is_error). Returns (verdict, detail)."""
    read_args = _resolve(rule.args, call_args, result_structured)
    try:
        read_result, is_error = await call_read(rule.tool, read_args)
    except Exception as e:  # noqa: BLE001 – any failure of the read path is "unclear", never "ok"
        return "unklar", f"read tool failed: {type(e).__name__}"
    if is_error or not isinstance(read_result, dict):
        return "unklar", "read tool returned an error or no structured result"
    for key, expected in rule.expect.items():
        want = _resolve(expected, call_args, result_structured)
        got = _dig(read_result, key)
        if want is Missing or got is Missing:
            return "unklar", f"field {key} missing"
        if got != want and not (isinstance(got, (int, float)) and isinstance(want, (int, float)) and abs(got - want) < 1e-9):
            return "fehlgeschlagen", f"{key}: expected {want!r}, read {got!r}"
    return "ok", "read-back matches"
