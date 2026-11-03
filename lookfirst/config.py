"""Configuration (YAML). One file describes upstreams, rules, confirmation channels, read-back checks and the audit log.

Example (see lookfirst/demo_files/lookfirst.yaml):

    upstreams:
      bank: {command: "python", args: ["lookfirst/demo_files/bank_server.py"]}        # stdio
      crm:  {url: "http://127.0.0.1:9000/mcp"}                         # Streamable HTTP
    rules:
      default: {read_only: allow, destructive: confirm, unknown: confirm}
      tools:
        bank__ueberweisung:                                          # <upstream>__<tool> when more than one upstream
          action: confirm
          summary: "Transfer {betrag} EUR to {an}"
          readback: {tool: bank__kontostand, args: {}, expect: {saldo: "$result.saldo"}}
        bank__kontostand: {action: allow}
    confirm:
      timeout_seconds: 120
      elicitation: true
      web: {host: 127.0.0.1, port: 8477, identity_header: X-Forwarded-User}   # header optional (v1.1: verified actor)
      webhook: {url: "https://example.invalid/braucht-dich", token_file: "/path/token"}
    audit:
      log: "./lookfirst-audit.jsonl"
      key: "./lookfirst-ed25519.key"
    redact: {hook: null}
    http: {token_file: "./private/http-token"}                        # needed for --transport http off loopback (#668 P2)
    schleuse:                                                          # Datenschutz-Schleuse (#604), optional
      detect: [IBAN, KARTE, EMAIL, TELEFON, GEHEIMNIS]
      names_file: "./private/namen.txt"                                # one name per line, never committed
      patterns: {KUNDENNR: "K-\\d{6}"}
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ACTIONS = ("allow", "confirm", "deny")
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class ConfigError(ValueError):
    pass


@dataclass
class Upstream:
    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    cwd: str | None = None


@dataclass
class Readback:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    expect: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolRule:
    action: str | None = None
    summary: str | None = None
    readback: Readback | None = None


@dataclass
class Config:
    upstreams: dict[str, Upstream]
    default_actions: dict[str, str]
    tool_rules: dict[str, ToolRule]
    timeout_seconds: float
    elicitation: bool
    web: dict[str, Any] | None
    webhook: dict[str, Any] | None
    audit_log: Path
    audit_key: Path
    redact_hook: str | None
    server_name: str = "lookfirst"
    schleuse: dict | None = None
    base: Path | None = None
    http_token_file: Path | None = None
    upstream_timeout_seconds: float = 60.0

    @property
    def prefixed(self) -> bool:
        return len(self.upstreams) > 1


def _action(v, where):
    if v not in ACTIONS:
        raise ConfigError(f"{where}: action must be one of {ACTIONS}, got {v!r}")
    return v


def _schleuse(v):
    if v is None:
        return None
    if not isinstance(v, dict) or set(v) - {"enabled", "detect", "names_file", "patterns", "ttl_seconds"}:
        raise ConfigError("schleuse: mapping with enabled, detect, names_file, patterns, ttl_seconds")
    return v


def load(path: str | Path) -> Config:
    base = Path(path).resolve().parent
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ConfigError("top level must be a mapping")
    ups: dict[str, Upstream] = {}
    for name, u in (data.get("upstreams") or {}).items():
        if not NAME.fullmatch(str(name)) or "." in name or "__" in name:
            raise ConfigError(f"upstream name {name!r}: letters, digits, _ and - only")
        if not isinstance(u, dict) or bool(u.get("command")) == bool(u.get("url")):
            raise ConfigError(f"upstream {name}: exactly one of command or url")
        ups[name] = Upstream(name=name, command=u.get("command"), args=[str(a) for a in u.get("args", [])], env={str(k): str(v) for k, v in (u.get("env") or {}).items()},
                             url=u.get("url"), cwd=str(base / u["cwd"]) if u.get("cwd") else str(base))
    if not ups:
        raise ConfigError("at least one upstream is required")
    rules = data.get("rules") or {}
    dflt = {"read_only": "allow", "destructive": "confirm", "unknown": "confirm", "non_destructive_write": "confirm"}
    for k, v in (rules.get("default") or {}).items():
        if k not in dflt:
            raise ConfigError(f"rules.default: unknown key {k}")
        dflt[k] = _action(v, f"rules.default.{k}")
    tool_rules: dict[str, ToolRule] = {}
    for name, r in (rules.get("tools") or {}).items():
        if not isinstance(r, dict):
            raise ConfigError(f"rules.tools.{name}: mapping expected")
        rb = None
        if r.get("readback"):
            x = r["readback"]
            if not isinstance(x, dict) or not isinstance(x.get("tool"), str):
                raise ConfigError(f"rules.tools.{name}.readback: tool required")
            rb = Readback(tool=x["tool"], args=dict(x.get("args") or {}), expect=dict(x.get("expect") or {}))
        tool_rules[str(name)] = ToolRule(action=_action(r["action"], f"rules.tools.{name}") if "action" in r else None, summary=r.get("summary"), readback=rb)
    conf = data.get("confirm") or {}
    audit = data.get("audit") or {}
    http = data.get("http") or {}
    if not isinstance(http, dict) or set(http) - {"token_file"}:
        raise ConfigError("http: mapping with token_file")
    execution = data.get("execution", {})
    if not isinstance(execution, dict) or set(execution) - {"timeout_seconds"}:
        raise ConfigError("execution: mapping with timeout_seconds")
    timeout = execution.get("timeout_seconds", 60)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ConfigError("execution.timeout_seconds: finite positive number required")
    return Config(upstreams=ups, default_actions=dflt, tool_rules=tool_rules, timeout_seconds=float(conf.get("timeout_seconds", 120)),
                  elicitation=conf.get("elicitation", True) is not False, web=conf.get("web"), webhook=conf.get("webhook"),
                  audit_log=base / str(audit.get("log", "lookfirst-audit.jsonl")), audit_key=base / str(audit.get("key", "lookfirst-ed25519.key")),
                  redact_hook=(data.get("redact") or {}).get("hook"), server_name=str(data.get("name", "lookfirst")),
                  schleuse=_schleuse(data.get("schleuse")), base=base,
                  http_token_file=base / str(http["token_file"]) if http.get("token_file") else None,
                  upstream_timeout_seconds=float(timeout))
