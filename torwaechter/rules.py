"""Decide what happens to a tool call: allow | confirm | deny.

Order: explicit rule for the tool → defaults by the upstream's tool annotations:
readOnlyHint → ``read_only`` (default allow); destructiveHint → ``destructive`` (default confirm);
a write that declares destructiveHint=false → ``non_destructive_write`` (default confirm); no annotations → ``unknown`` (default confirm).
Unknown always errs on the side of asking a human.
"""
from __future__ import annotations

from .config import Config


def _hint(annotations, snake: str, camel: str):
    if annotations is None:
        return None
    v = getattr(annotations, snake, None)
    return v if v is not None else getattr(annotations, camel, None)


def classify(annotations) -> str:
    if _hint(annotations, "read_only_hint", "readOnlyHint") is True:
        return "read_only"
    d = _hint(annotations, "destructive_hint", "destructiveHint")
    if d is True:
        return "destructive"
    if d is False:
        return "non_destructive_write"
    return "unknown"


def decide(config: Config, tool_name: str, annotations) -> tuple[str, str]:
    """→ (action, reason)."""
    rule = config.tool_rules.get(tool_name)
    if rule and rule.action:
        return rule.action, f"rule:{tool_name}"
    kind = classify(annotations)
    return config.default_actions[kind], f"default:{kind}"
