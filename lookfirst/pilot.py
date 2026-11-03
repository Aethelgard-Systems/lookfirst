"""lookfirst pilot-status and launch gate evaluation.

Measures the criteria for completing the local pilot phase (#609/#807):
- Launch gate criteria: >= 1 week (7 days) and >= 20 real operations without tampering
- Real operations: human confirmations/denials (web, webhook, elicitation)
  Timeouts (unanswered calls) are reported separately as metrics, not counted towards the gate.
  Scripted demo runs, automated tests and automated policy/schleuse denials are excluded.
- Tracks denials, timeouts and unclear/blocked execution outcomes
- Output: short summary + JSON, gate traffic light (OFFEN / ERFUELLT)
"""
from __future__ import annotations

import datetime
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import audit, config as cfg

DEMO_TOOLS = frozenset({"kontostand", "umsaetze", "ueberweisung"})
DEMO_ACTORS = frozenset({"auto", "test", "demo", "scripted"})
HUMAN_CHANNELS = ("web", "webhook", "elicitation")


@dataclass
class PilotStatusReport:
    config_path: str
    audit_log_path: str
    audit_exists: bool
    audit_verified: bool
    audit_problems: list[str]
    audit_entries_total: int
    real_operations_total: int
    approvals_total: int
    denials_total: int
    timeouts_total: int
    unclear_outcomes_total: int
    days_since_first_op: float
    first_op_timestamp: str | None
    last_op_timestamp: str | None
    audit_warnings: list[str] = field(default_factory=list)
    channels_breakdown: dict[str, int] = field(default_factory=lambda: {"web": 0, "webhook": 0, "elicitation": 0})
    gate_operations_target: int = 20
    gate_days_target: float = 7.0
    gate_status: str = "OFFEN"  # "OFFEN" | "ERFUELLT"

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": {
                "status": self.gate_status,
                "operations_target": self.gate_operations_target,
                "operations_actual": self.real_operations_total,
                "operations_met": self.real_operations_total >= self.gate_operations_target,
                "days_target": self.gate_days_target,
                "days_actual": round(self.days_since_first_op, 1),
                "days_met": self.days_since_first_op >= self.gate_days_target,
                "audit_verified": self.audit_verified,
                "audit_clean": self.audit_verified and not self.audit_warnings,
            },
            "metrics": {
                "audit_entries_total": self.audit_entries_total,
                "real_operations": self.real_operations_total,
                "approvals": self.approvals_total,
                "denials": self.denials_total,
                "timeouts": self.timeouts_total,
                "channels": self.channels_breakdown,
                "unclear_outcomes": self.unclear_outcomes_total,
                "first_operation": self.first_op_timestamp,
                "last_operation": self.last_op_timestamp,
            },
            "audit": {
                "path": self.audit_log_path,
                "exists": self.audit_exists,
                "verified": self.audit_verified,
                "problems": self.audit_problems,
                "warnings": self.audit_warnings,
            },
        }

    def render_short(self) -> str:
        symbol = "🟢" if self.gate_status == "ERFUELLT" else "🟡"
        if not self.audit_verified:
            verdict_str = "TAMPERED / FEHLER"
        elif self.audit_warnings:
            verdict_str = "WARNUNG (Evidenz unvollständig / Head fehlt)"
        else:
            verdict_str = "OK"
        days_str = f"{self.days_since_first_op:.1f}"
        first_str = f" (erster Vorgang: {self.first_op_timestamp})" if self.first_op_timestamp else " (noch kein echter Vorgang)"
        ch = self.channels_breakdown
        ch_str = f"[web: {ch.get('web', 0)}, webhook: {ch.get('webhook', 0)}, elicitation: {ch.get('elicitation', 0)}]"
        
        lines = [
            f"[lookfirst pilot-status] Gate-Ampel: {symbol} {self.gate_status}",
            f"  - Echte Vorgänge: {self.real_operations_total} / {self.gate_operations_target} Ziel (Freigaben: {self.approvals_total}, Ablehnungen: {self.denials_total}) {ch_str}",
            f"  - Timeouts:       {self.timeouts_total} (Liegenlassen zählt nicht als echter Vorgang)",
            f"  - Laufzeit:       {days_str} / {self.gate_days_target:.0f} Tage Ziel{first_str}",
            f"  - Unklare Ausgänge: {self.unclear_outcomes_total}",
            f"  - Audit-Log:      {verdict_str} ({self.audit_entries_total} Einträge geprüft)",
        ]
        if self.audit_problems:
            for p in self.audit_problems[:3]:
                lines.append(f"    ! Problem: {p}")
        if self.audit_warnings:
            for w in self.audit_warnings[:3]:
                lines.append(f"    ! Warnung: {w}")
        return "\n".join(lines)

    def render_combined(self) -> str:
        short = self.render_short()
        json_dump = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        return f"{short}\n\nJSON:\n{json_dump}"


def evaluate_pilot_status(conf: cfg.Config, now: float | None = None) -> PilotStatusReport:
    """Evaluate pilot status against the configured audit log.
    ``now``: float seconds since epoch (defaults to time.time())."""
    now_s = time.time() if now is None else now
    log_path = conf.audit_log
    key_pub_path = Path(str(conf.audit_key) + ".pub")

    if not log_path.exists():
        return PilotStatusReport(
            config_path=str(conf.audit_key.parent / "lookfirst.yaml"),
            audit_log_path=str(log_path),
            audit_exists=False,
            audit_verified=False,
            audit_problems=["Log-Datei existiert nicht"],
            audit_entries_total=0,
            real_operations_total=0,
            approvals_total=0,
            denials_total=0,
            timeouts_total=0,
            unclear_outcomes_total=0,
            days_since_first_op=0.0,
            first_op_timestamp=None,
            last_op_timestamp=None,
            gate_status="OFFEN",
        )

    if not key_pub_path.exists():
        return PilotStatusReport(
            config_path=str(conf.audit_key.parent / "lookfirst.yaml"),
            audit_log_path=str(log_path),
            audit_exists=True,
            audit_verified=False,
            audit_problems=[f"Öffentlicher Audit-Schlüssel fehlt: {key_pub_path}"],
            audit_entries_total=0,
            real_operations_total=0,
            approvals_total=0,
            denials_total=0,
            timeouts_total=0,
            unclear_outcomes_total=0,
            days_since_first_op=0.0,
            first_op_timestamp=None,
            last_op_timestamp=None,
            gate_status="OFFEN",
        )

    pub = audit.load_public(key_pub_path)
    verdict = audit.verify(log_path, pub)
    ok, problems, total_entries = verdict
    warnings = list(getattr(verdict, "warnings", []))
    prob_texts = [f"Zeile {p.line}: {p.reason}" for p in problems]
    warn_texts = [str(w) for w in warnings]

    real_ops = 0
    approvals = 0
    denials = 0
    timeouts = 0
    unclear_count = 0
    first_ts_ms: int | None = None
    last_ts_ms: int | None = None
    channels_breakdown = {"web": 0, "webhook": 0, "elicitation": 0}

    open_executions: set[str] = set()

    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue

        tool = str(e.get("tool") or "")
        event = str(e.get("event") or "")
        by = str(e.get("by") or "")
        decision = str(e.get("decision") or "")
        note = str(e.get("note") or "").lower()
        readback = str(e.get("readback") or "")
        call_id = str(e.get("call_id") or "")
        ts = e.get("ts")

        # Ausführungsstatus nachverfolgen
        if tool not in DEMO_TOOLS:
            if event == "execution_started":
                open_executions.add(call_id)
            elif event in ("execution_resolved", "execution_unblocked", "execution_blocked"):
                open_executions.discard(call_id)
                if event == "execution_blocked":
                    unclear_count += 1
            elif event == "readback" and readback in ("unklar", "fehlgeschlagen"):
                unclear_count += 1
            elif event == "result" and readback == "unklar":
                unclear_count += 1

        # Echte Vorgänge prüfen
        if event != "decision":
            continue

        # Demo-Ausschlusskriterien:
        # 1. Offline-Demo Tools (ueberweisung, kontostand, umsaetze)
        if tool in DEMO_TOOLS:
            continue
        # 2. Demo-/Test-Akteure
        if by in DEMO_ACTORS or by.startswith("test"):
            continue
        # 3. Markierungen in der Notiz
        if "scripted" in note or "approved automatically" in note or "demo" in note:
            continue

        # Timeouts: Kein menschlicher Beschluss -> separate Kennzahl, zählt NICHT zu real_operations
        if by == "timeout":
            timeouts += 1
            continue

        # Nur echte menschliche Kanäle (web, webhook, elicitation)
        matched_channel = None
        for ch_name in HUMAN_CHANNELS:
            if by.startswith(ch_name):
                matched_channel = ch_name
                break

        if matched_channel is None:
            continue

        real_ops += 1
        channels_breakdown[matched_channel] = channels_breakdown.get(matched_channel, 0) + 1

        if isinstance(ts, (int, float)):
            ts_int = int(ts)
            if first_ts_ms is None or ts_int < first_ts_ms:
                first_ts_ms = ts_int
            if last_ts_ms is None or ts_int > last_ts_ms:
                last_ts_ms = ts_int

        if decision == "approve":
            approvals += 1
        elif decision == "deny":
            denials += 1

    # Nicht aufgelöste Ausführungen zählen als unklar
    unclear_count += len(open_executions)

    days_since_first = 0.0
    first_iso = None
    last_iso = None

    if first_ts_ms is not None:
        first_s = first_ts_ms / 1000.0
        days_since_first = max(0.0, (now_s - first_s) / 86400.0)
        first_iso = datetime.datetime.fromtimestamp(first_s, datetime.timezone.utc).isoformat()
    if last_ts_ms is not None:
        last_iso = datetime.datetime.fromtimestamp(last_ts_ms / 1000.0, datetime.timezone.utc).isoformat()

    gate_met = ok and (not warn_texts) and (real_ops >= 20) and (days_since_first >= 7.0)
    gate_status = "ERFUELLT" if gate_met else "OFFEN"

    return PilotStatusReport(
        config_path=str(conf.audit_key.parent / "lookfirst.yaml"),
        audit_log_path=str(log_path),
        audit_exists=True,
        audit_verified=ok,
        audit_problems=prob_texts,
        audit_warnings=warn_texts,
        audit_entries_total=total_entries,
        real_operations_total=real_ops,
        approvals_total=approvals,
        denials_total=denials,
        timeouts_total=timeouts,
        channels_breakdown=channels_breakdown,
        unclear_outcomes_total=unclear_count,
        days_since_first_op=days_since_first,
        first_op_timestamp=first_iso,
        last_op_timestamp=last_iso,
        gate_operations_target=20,
        gate_days_target=7.0,
        gate_status=gate_status,
    )
