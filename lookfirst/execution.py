"""Single-worker execution interlock, recovered from the existing signed audit log.

Write-ahead start records also block after interruption before an error can be logged.
This is not upstream idempotency or a multi-process audit writer.
"""
import json
from pathlib import Path

import anyio

from .audit import verify


class ExecutionSafety:
    def __init__(self, audit):
        self.audit = audit
        self.blocked: dict[str, str] = {}
        self._locks = {}
        if not audit.path.exists() and Path(str(audit.path) + ".head").exists():
            raise ValueError("execution recovery requires the missing audit log")
        if audit.path.exists():
            verdict = verify(audit.path, audit.key.public_key())
            if not verdict[0] or verdict.warnings:
                raise ValueError("execution recovery requires a verified audit log and signed head")
            for line in audit.path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                entry = json.loads(line)
                name, event = entry["tool"], entry["event"]
                if event in ("execution_started", "execution_blocked"):
                    self.blocked[name] = entry["call_id"]
                elif event in ("execution_resolved", "execution_unblocked"):
                    self.blocked.pop(name, None)

    def lock(self, name):
        return self._locks.setdefault(name, anyio.Lock())

    def start(self, call_id, name, args_sha256):
        # Persist before dispatch. If the append fails, no upstream call is made.
        self.audit.append("execution_started", call_id, name, args_sha256=args_sha256, readback="unklar")
        self.blocked[name] = call_id

    def block(self, call_id, name, note):
        self.blocked[name] = call_id
        self.audit.append("execution_blocked", call_id, name, readback="unklar", note=note)

    def resolve(self, call_id, name):
        self.audit.append("execution_resolved", call_id, name)
        self.blocked.pop(name, None)

    def unblock(self, call_id, name, decision):
        self.audit.append("execution_unblocked", call_id, name, decision="approve", by=decision.label,
                          note="human unlock; previous outcome remains unclear; no retry performed")
        self.blocked.pop(name, None)
