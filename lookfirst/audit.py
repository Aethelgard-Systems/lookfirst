"""Tamper-evident audit log: append-only JSONL, hash chain, Ed25519 signatures.

Entry layout (one JSON object per line, keys sorted):
  seq, ts, event, call_id, tool, args_sha256, summary, decision, by, result_sha256, readback, note,
  prev  – hash of the previous entry ("0"*64 for the first),
  hash  – sha256 over canonical JSON of all fields above (including prev),
  sig   – Ed25519 signature (hex) over ``hash``.
``ts`` is **integer milliseconds** (a float such as ``1760000000.0`` would serialise differently in other languages and
break cross-verification with the JS implementation). ``verify(path, public_key)`` recomputes every hash, checks each
signature and the chain; any edited, removed, reordered or inserted line is reported with its line number. A ``<log>.head``
sidecar holds ``{"hash","seq","sig"}`` – the last hash and seq, signed over ``head:<seq>:<hash>`` – so truncation at the end is
detected while the sidecar is present; a forged sidecar is a failure, a missing one a warning (format shared with agent-postbox evidence-v1).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS = "0" * 64
FIELDS = ("seq", "ts", "event", "call_id", "tool", "args_sha256", "summary", "decision", "by", "result_sha256", "readback", "note", "prev")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def generate_key(path: Path) -> Ed25519PublicKey:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = key.public_key()
    Path(str(path) + ".pub").write_bytes(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return pub


def load_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("audit key must be Ed25519")
    return key


def load_public(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key must be Ed25519")
    return key


class AuditLog:
    def __init__(self, path: Path, private_key: Ed25519PrivateKey, now=time.time):
        self.path, self.key, self.now, self.lock = Path(path), private_key, now, threading.Lock()
        self.seq, self.prev = 0, GENESIS
        if self.path.exists():
            last = None
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last = json.loads(line)
            if last:
                self.seq, self.prev = int(last["seq"]), last["hash"]

    def append(self, event: str, call_id: str, tool: str, *, args_sha256: str = "", summary: str = "", decision: str = "", by: str = "",
               result_sha256: str = "", readback: str = "", note: str = "") -> dict:
        with self.lock:
            entry = {"seq": self.seq + 1, "ts": int(round(self.now() * 1000)), "event": event, "call_id": call_id, "tool": tool, "args_sha256": args_sha256,
                     "summary": summary[:500], "decision": decision, "by": by, "result_sha256": result_sha256, "readback": readback, "note": note[:500], "prev": self.prev}
            entry["hash"] = sha256(canonical(entry))
            entry["sig"] = self.key.sign(bytes.fromhex(entry["hash"])).hex()
            line = canonical(entry) + "\n"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            Path(str(self.path) + ".head").write_text(canonical(signed_head(entry["seq"], entry["hash"], self.key)), encoding="utf-8")
            self.seq, self.prev = entry["seq"], entry["hash"]
            return entry


def head_message(seq: int, hash_: str) -> bytes:
    return f"head:{seq}:{hash_}".encode("utf-8")


def signed_head(seq: int, hash_: str, key: Ed25519PrivateKey) -> dict:
    return {"seq": seq, "hash": hash_, "sig": key.sign(head_message(seq, hash_)).hex()}


@dataclass
class Problem:
    line: int
    reason: str


class Verdict(tuple):
    """(ok, problems, entries) – plus ``.warnings`` (e.g. a missing head sidecar), so callers that unpack three values keep working."""
    warnings: list[str]

    def __new__(cls, ok, problems, entries, warnings=()):
        o = super().__new__(cls, (ok, problems, entries))
        o.warnings = list(warnings)
        return o


def verify(path: Path, public_key: Ed25519PublicKey) -> "Verdict":
    """→ (ok, problems, entries) [+ .warnings]. Checks hash recomputation, signature, chain order, integer ts and the signed head."""
    problems: list[Problem] = []
    warnings: list[str] = []
    prev, seq, n, last_hash = GENESIS, 0, 0, None
    path = Path(path)
    if not path.exists():
        return Verdict(False, [Problem(0, "log file missing")], 0)
    with path.open("r", encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            if not line.strip():
                continue
            n += 1
            try:
                e = json.loads(line)
            except ValueError:
                problems.append(Problem(ln, "not JSON")); continue
            if set(e) != set(FIELDS) | {"hash", "sig"}:
                problems.append(Problem(ln, "unexpected fields")); prev = e.get("hash", prev); seq += 1; continue  # seq weiterzählen: die Folgezeile ist nicht schuld
            body = {k: e[k] for k in FIELDS}
            if sha256(canonical(body)) != e["hash"]:
                problems.append(Problem(ln, "hash mismatch (entry modified)"))
            try:
                public_key.verify(bytes.fromhex(e["sig"]), bytes.fromhex(e["hash"]))
            except Exception:
                problems.append(Problem(ln, "signature invalid"))
            if e["prev"] != prev:
                problems.append(Problem(ln, "chain broken (entry removed, reordered or inserted before this line)"))
            if e["seq"] != seq + 1:
                problems.append(Problem(ln, f"sequence gap: expected {seq + 1}, got {e['seq']}"))
            if type(e.get("ts")) is not int:
                problems.append(Problem(ln, "ts must be integer milliseconds"))
            prev, seq, last_hash = e["hash"], int(e["seq"]) if isinstance(e["seq"], int) else seq + 1, e["hash"]
    head = Path(str(path) + ".head")
    if not head.exists():
        warnings.append("head sidecar missing: truncation at the end of the log cannot be ruled out")
    else:
        try:
            h = json.loads(head.read_text(encoding="utf-8"))
        except ValueError:
            h = None
        ok_sig = False
        if isinstance(h, dict) and isinstance(h.get("seq"), int) and isinstance(h.get("hash"), str) and isinstance(h.get("sig"), str):
            try:
                public_key.verify(bytes.fromhex(h["sig"]), head_message(h["seq"], h["hash"]))
                ok_sig = True
            except Exception:  # noqa: BLE001
                ok_sig = False
        if not ok_sig:
            problems.append(Problem(n, "head sidecar unsigned, damaged or forged"))
        elif h["hash"] != (last_hash or GENESIS) or h["seq"] != seq:
            problems.append(Problem(n, "head mismatch (entries truncated at the end or head stale)"))
    return Verdict(not problems, problems, n, warnings)
