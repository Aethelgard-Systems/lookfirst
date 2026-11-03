"""Synthetic execution failures, real in-memory MCP transport and signed audit log."""
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import anyio
import mcp.types as t
import yaml
from mcp.server.lowlevel import Server
from mcp.shared.exceptions import MCPError

from lookfirst import audit, config
from lookfirst.execution import ExecutionSafety
from lookfirst.proxy import Gate
from tests.helpers import GateHarness


def gate_of(result):
    return result.structured_content["lookfirst"]


def decisions(*answers):
    remaining = iter(answers)

    async def cb(ctx, params):
        return t.ElicitResult(action="accept", content={"approve": next(remaining)})
    return cb


def failing_bank(state, mode):
    async def tools(ctx, params):
        return t.ListToolsResult(tools=[
            t.Tool(name="write", inputSchema={"type": "object"}, annotations=t.ToolAnnotations(destructiveHint=True)),
            t.Tool(name="read", inputSchema={"type": "object"}, annotations=t.ToolAnnotations(readOnlyHint=True)),
        ])

    async def call(ctx, params):
        if params.name == "read":
            return t.CallToolResult(content=[], structuredContent={"count": state["effects"]})
        state["calls"] += 1
        if mode != "reject":
            state["effects"] += 1  # response lost AFTER the synthetic effect
        if mode == "timeout":
            await anyio.sleep_forever()
        return t.CallToolResult(content=[t.TextContent(type="text", text="synthetic failure")], isError=True)
    return Server("failing-bank", version="0", on_list_tools=tools, on_call_tool=call)


class ExecutionTest(unittest.TestCase):
    def setUp(self):
        self.h = GateHarness()
        self.addCleanup(self.h.close)
        self.state = {"calls": 0, "effects": 0}

    def entries(self):
        return [json.loads(line) for line in self.h.conf.audit_log.read_text(encoding="utf-8").splitlines()]

    def test_error_response_lost_after_effect_blocks_changed_arguments(self):
        async def go():
            async with self.h.client(decisions(True, False), {"bank": failing_bank(self.state, "error")}) as (cs, _):
                first = gate_of(await cs.call_tool("write", {"title": "one"}))
                self.assertEqual((first["status"], first["readback"], first["blocked"]), ("executed", "unklar", True))
                second = gate_of(await cs.call_tool("write", {"title": "different"}))
                self.assertEqual((second["status"], second["blocked"]), ("denied", True))
                self.assertEqual(gate_of(await cs.call_tool("read", {}))["status"], "allowed")
        anyio.run(go)
        self.assertEqual(self.state, {"calls": 1, "effects": 1})
        self.assertTrue(self.h.verify()[0])

    def test_timeout_exactly_one_dispatch_and_durable_block(self):
        self.h.conf.upstream_timeout_seconds = 0.03
        async def go():
            async with self.h.client(decisions(True, False), {"bank": failing_bank(self.state, "timeout")}) as (cs, _):
                result = gate_of(await cs.call_tool("write", {}))
                self.assertEqual(result["upstream_error"], "TimeoutError")
                self.assertEqual(result["readback"], "unklar")
                self.assertTrue(gate_of(await cs.call_tool("write", {}))["blocked"])
        anyio.run(go)
        self.assertEqual(self.state["calls"], 1)
        self.assertIn("write", ExecutionSafety(audit.AuditLog(self.h.conf.audit_log, self.h.log.key)).blocked)

    def test_clear_upstream_rejection_is_conservatively_blocked(self):
        async def go():
            async with self.h.client(decisions(True, False), {"bank": failing_bank(self.state, "reject")}) as (cs, _):
                self.assertTrue(gate_of(await cs.call_tool("write", {}))["blocked"])
                self.assertTrue(gate_of(await cs.call_tool("write", {}))["blocked"])
        anyio.run(go)
        self.assertEqual(self.state, {"calls": 1, "effects": 0})

    def test_transport_exception_blocks_followup(self):
        async def go():
            async with self.h.client(decisions(True, False)) as (cs, sessions):
                with patch.object(sessions["bank"], "call_tool", side_effect=ConnectionError("synthetic private detail")) as upstream:
                    first = gate_of(await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 1}))
                    self.assertEqual(first["upstream_error"], "ConnectionError")
                    self.assertTrue(gate_of(await cs.call_tool("ueberweisung", {}))["blocked"])
                    self.assertEqual(upstream.call_count, 1)
        anyio.run(go)
        self.assertNotIn("synthetic private detail", self.h.conf.audit_log.read_text())

    def test_human_unlock_does_not_execute_and_next_call_needs_new_approval(self):
        async def go():
            async with self.h.client(decisions(True, True, False, True), {"bank": failing_bank(self.state, "error")}) as (cs, _):
                await cs.call_tool("write", {})
                unlocked = gate_of(await cs.call_tool("write", {"new": "arguments"}))
                self.assertEqual((unlocked["status"], unlocked["blocked"]), ("unblocked", False))
                self.assertEqual(self.state["calls"], 1)
                self.assertEqual(gate_of(await cs.call_tool("write", {}))["status"], "denied")
                self.assertEqual(self.state["calls"], 1)
                await cs.call_tool("write", {})
                self.assertEqual(self.state["calls"], 2)
        anyio.run(go)
        unlocks = [e for e in self.entries() if e["event"] == "execution_unblocked"]
        self.assertEqual(len(unlocks), 1)
        self.assertTrue(unlocks[0]["by"].startswith("elicitation:"))
        self.assertTrue(self.h.verify()[0])

    def test_web_confirmation_channel_unlocks_without_changing_web_or_confirm(self):
        self.h.conf.elicitation = False
        self.h.confirmer.use_elicitation = False
        self.h.confirmer.web_enabled = True
        self.h.confirmer.timeout = 2
        async def go():
            async with self.h.client(None) as (cs, _):
                self.h.gate.execution.start("tw-interrupted", "ueberweisung", "0" * 64)
                async def approve():
                    while not self.h.registry.list_open():
                        await anyio.sleep(0.01)
                    preview = self.h.registry.list_open()[0]
                    self.assertEqual(preview["arguments"]["operation"], "unlock")
                    self.h.registry.decide(preview["id"], True, "web", actor="synthetic-human")
                async with anyio.create_task_group() as tg:
                    tg.start_soon(approve)
                    result = gate_of(await cs.call_tool("ueberweisung", {}))
                self.assertFalse(result["blocked"])
                self.assertEqual(self.h.state["calls"], [])
        anyio.run(go)
        self.assertEqual(self.entries()[-1]["by"], "web:synthetic-human")

    def test_recreated_gate_remembers_uncertainty_and_policy_revocation(self):
        async def go():
            async with self.h.client(decisions(True), {"bank": failing_bank(self.state, "error")}) as (cs, _):
                await cs.call_tool("write", {})
                gate = self.h.gate
                recovered = Gate(self.h.conf, gate.up, audit.AuditLog(self.h.conf.audit_log, self.h.log.key), gate.confirmer, gate.redact)
                self.assertIn("write", recovered.execution.blocked)
                self.h.conf.tool_rules["write"] = config.ToolRule(action="deny")
                denied = await recovered.on_call_tool(None, t.CallToolRequestParams(name="write", arguments={}))
                self.assertEqual(gate_of(denied)["reason"], "rule:write")
                self.assertIn("write", recovered.execution.blocked)
        anyio.run(go)
        self.assertEqual(self.state["calls"], 1)

    def test_interruption_after_start_recovers_and_tampering_fails_closed(self):
        safety = ExecutionSafety(self.h.log)
        safety.start("tw-crash", "write", "0" * 64)
        self.assertEqual(ExecutionSafety(audit.AuditLog(self.h.conf.audit_log, self.h.log.key)).blocked, {"write": "tw-crash"})
        lines = self.h.conf.audit_log.read_text(encoding="utf-8").replace("execution_started", "execution_resolved")
        self.h.conf.audit_log.write_text(lines, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "verified audit"):
            ExecutionSafety(audit.AuditLog(self.h.conf.audit_log, self.h.log.key))

    def test_missing_signed_head_refuses_recovery(self):
        self.h.log.append("preview", "tw-1", "write")
        Path(str(self.h.conf.audit_log) + ".head").unlink()
        with self.assertRaises(ValueError):
            ExecutionSafety(self.h.log)

    def test_missing_log_with_existing_head_refuses_recovery(self):
        ExecutionSafety(self.h.log).start("tw-missing", "write", "0" * 64)
        self.h.conf.audit_log.unlink()
        with self.assertRaises(ValueError):
            ExecutionSafety(audit.AuditLog(self.h.conf.audit_log, self.h.log.key))

    def test_unblock_is_recovered_and_does_not_reuse_old_policy_approval(self):
        from lookfirst.confirm import Decision
        safety = ExecutionSafety(self.h.log)
        safety.start("tw-old", "write", "0" * 64)
        safety.unblock("tw-unlock", "write", Decision(True, "web", actor="synthetic-human"))
        self.assertEqual(ExecutionSafety(audit.AuditLog(self.h.conf.audit_log, self.h.log.key)).blocked, {})
        self.assertTrue(self.h.verify()[0])

    def test_allow_rule_does_not_bypass_interlock(self):
        self.h.conf.tool_rules["write"] = config.ToolRule(action="allow")
        async def go():
            async with self.h.client(decisions(False), {"bank": failing_bank(self.state, "error")}) as (cs, _):
                self.assertTrue(gate_of(await cs.call_tool("write", {}))["blocked"])
                self.assertTrue(gate_of(await cs.call_tool("write", {}))["blocked"])
        anyio.run(go)
        self.assertEqual(self.state["calls"], 1)

    def test_concurrent_call_cannot_slip_past_timeout(self):
        self.h.conf.upstream_timeout_seconds = 0.03
        async def go():
            async with self.h.client(decisions(True, False), {"bank": failing_bank(self.state, "timeout")}) as (cs, _):
                results = []
                async def call():
                    results.append(gate_of(await cs.call_tool("write", {})))
                async with anyio.create_task_group() as tg:
                    tg.start_soon(call)
                    tg.start_soon(call)
                self.assertCountEqual([r["status"] for r in results], ["executed", "denied"])
        anyio.run(go)
        self.assertEqual(self.state["calls"], 1)

    def test_audit_start_failure_prevents_dispatch(self):
        async def go():
            async with self.h.client(decisions(True)) as (cs, sessions):
                with patch.object(self.h.gate.execution, "start", side_effect=OSError("synthetic disk failure")), patch.object(sessions["bank"], "call_tool") as upstream:
                    with self.assertRaises(MCPError):
                        await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 1})
                    upstream.assert_not_called()
        anyio.run(go)

    def test_result_logging_failure_keeps_lock_in_memory_and_after_restart(self):
        append = self.h.log.append
        def fail_result(event, *args, **kw):
            if event == "result":
                raise OSError("synthetic disk failure after dispatch")
            return append(event, *args, **kw)
        async def go():
            async with self.h.client(decisions(True, False)) as (cs, _):
                with patch.object(self.h.log, "append", side_effect=fail_result):
                    with self.assertRaises(MCPError):
                        await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 1})
                self.assertTrue(gate_of(await cs.call_tool("ueberweisung", {}))["blocked"])
        anyio.run(go)
        self.assertEqual(len(self.h.state["calls"]), 1)
        self.assertIn("ueberweisung", ExecutionSafety(audit.AuditLog(self.h.conf.audit_log, self.h.log.key)).blocked)

    def test_new_process_recovers_unresolved_start(self):
        ExecutionSafety(self.h.log).start("tw-interrupted", "write", "0" * 64)
        code = ("import json,sys; from pathlib import Path; from lookfirst.audit import AuditLog,load_private; "
                "from lookfirst.execution import ExecutionSafety; "
                "print(json.dumps(ExecutionSafety(AuditLog(Path(sys.argv[1]),load_private(Path(sys.argv[2])))).blocked))")
        result = subprocess.run([sys.executable, "-B", "-c", code, str(self.h.conf.audit_log), str(self.h.conf.audit_key)],
                                capture_output=True, text=True, timeout=20, check=True)
        self.assertEqual(json.loads(result.stdout), {"write": "tw-interrupted"})

    def test_readback_revoked_policy_does_not_bypass_deny(self):
        self.h.conf.tool_rules["kontostand"] = config.ToolRule(action="deny")
        async def go():
            async with self.h.client(decisions(True)) as (cs, sessions):
                original = sessions["bank"].call_tool
                with patch.object(sessions["bank"], "call_tool", wraps=original) as upstream:
                    result = gate_of(await cs.call_tool("ueberweisung", {"an": "Demo", "betrag": 1}))
                    self.assertEqual((result["readback"], result["blocked"]), ("unklar", True))
                    self.assertEqual(upstream.call_count, 1)  # write only; forbidden reader not called
        anyio.run(go)

    def test_cancellation_during_dispatch_leaves_recoverable_lock(self):
        from lookfirst.confirm import Decision
        async def go():
            async with self.h.client(None, {"bank": failing_bank(self.state, "timeout")}) as (_, _sessions):
                with patch.object(self.h.confirmer, "ask", return_value=Decision(True, "web", actor="synthetic-human")):
                    with anyio.move_on_after(0.03) as cancel:
                        await self.h.gate.on_call_tool(None, t.CallToolRequestParams(name="write", arguments={}))
                    self.assertTrue(cancel.cancel_called)
                self.assertIn("write", self.h.gate.execution.blocked)
        anyio.run(go)
        self.assertEqual(self.state["calls"], 1)
        self.assertIn("write", ExecutionSafety(audit.AuditLog(self.h.conf.audit_log, self.h.log.key)).blocked)


class ExecutionConfigTest(unittest.TestCase):
    def test_timeout_default_override_and_invalid_values(self):
        h = GateHarness()
        self.addCleanup(h.close)
        self.assertEqual(h.conf.upstream_timeout_seconds, 60)
        path = h.dir / "lookfirst.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        data["execution"] = {"timeout_seconds": 1.25}
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        self.assertEqual(config.load(path).upstream_timeout_seconds, 1.25)
        for bad in [0, -1, True, "60", None, float("nan"), float("inf")]:
            with self.subTest(bad=bad):
                data["execution"]["timeout_seconds"] = bad
                path.write_text(yaml.safe_dump(data), encoding="utf-8")
                with self.assertRaises(config.ConfigError):
                    config.load(path)
