"""Redaction hook ("Privat-Schleuse") – V1 stub.

A hook is a dotted path ``package.module:function``; it receives the preview dict before it is shown to a human or sent to a
webhook and returns a (possibly redacted) copy. The default hook returns the preview unchanged. Placeholders for IBANs,
names and other private data are handled by the Datenschutz-Schleuse (``schleuse.py``), which runs before this hook.
"""
from __future__ import annotations

import importlib
from typing import Callable


def identity(preview: dict) -> dict:
    return preview


def load(spec: str | None) -> Callable[[dict], dict]:
    if not spec:
        return identity
    mod, _, fn = spec.partition(":")
    hook = getattr(importlib.import_module(mod), fn or "redact")
    if not callable(hook):
        raise ValueError(f"redact hook {spec} is not callable")
    return hook
