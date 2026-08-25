"""End-to-end integration tests connecting Scanner, Guardrail, and Vulnerable Lab servers."""

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_security_common.hash_utils import compute_tool_hash
from mcp_security_common.mcp_types import MCPTool
from mcp_scanner.cli import app
from mcp_scanner.connection import StdioMCPConnection
from mcp_scanner.static_engine import StaticAnalysisEngine
from mcp_guardrail.audit import AuditLogger
from mcp_guardrail.interceptor import GuardrailInterceptor
from mcp_guardrail.pin_store import SchemaPinStore

runner = CliRunner()


@pytest.mark.asyncio
async def test_atk1_server_stdio_safe_vs_vulnerable():
    atk1_script = str(
        Path(__file__).parent.parent / "servers" / "atk1_description_injection" / "server.py"
    )

    # 1. Safe Mode
    conn_safe = StdioMCPConnection(
        command=sys.executable,
        args=[atk1_script, "--mode", "safe", "--transport", "stdio"],
    )
    await conn_safe.connect()
    try:
        engine = StaticAnalysisEngine()
        res_safe = await engine.scan_connection(conn_safe, target_uri="stdio://atk1-safe")
        assert len(res_safe.findings) == 0
        assert res_safe.risk_score == 0.0
    finally:
        await conn_safe.close()

    # 2. Vulnerable Mode
    conn_vuln = StdioMCPConnection(
        command=sys.executable,
        args=[atk1_script, "--mode", "vulnerable", "--transport", "stdio"],
    )
    await conn_vuln.connect()
    try:
        engine = StaticAnalysisEngine()
        res_vuln = await engine.scan_connection(conn_vuln, target_uri="stdio://atk1-vuln")
        assert len(res_vuln.findings) >= 3
        rule_ids = [f.rule_id for f in res_vuln.findings]
        assert "S001" in rule_ids
        assert "S002" in rule_ids
        assert "S005" in rule_ids
        assert res_vuln.risk_score >= 3.0
    finally:
        await conn_vuln.close()


@pytest.mark.asyncio
async def test_atk2_server_rugpull_lifecycle_and_guardrail():
    atk2_script = str(
        Path(__file__).parent.parent / "servers" / "atk2_rug_pull" / "server.py"
    )

    conn = StdioMCPConnection(
        command=sys.executable,
        args=[atk2_script, "--mode", "vulnerable", "--transport", "stdio"],
    )
    await conn.connect()
    try:
        caps, info = await conn.initialize()
        initial_tools = await conn.list_tools()
        assert len(initial_tools) == 1
        initial_tool = initial_tools[0]
        initial_hash = compute_tool_hash(initial_tool)

        # Setup Guardrail pin store
        pin_store = SchemaPinStore()
        pin_store.record_pin(initial_tool)
        audit_logger = AuditLogger()
        guardrail = GuardrailInterceptor(pin_store=pin_store, audit_logger=audit_logger, enforce_mode=True)

        # Verify initial clean response through guardrail
        list_req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        list_resp_initial = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [initial_tool.to_dict()]}}
        sanitized_1, findings_1 = guardrail.intercept_server_response(list_req, list_resp_initial)
        assert len(sanitized_1["result"]["tools"]) == 1

        # Trigger Rug-Pull
        trigger_resp = await conn.send_request("admin/trigger_rug_pull", {})
        assert trigger_resp.get("result", {}).get("status") == "rug_pulled"

        # Mutated tools list
        mutated_tools = await conn.list_tools()
        assert len(mutated_tools) == 1
        mutated_tool = mutated_tools[0]
        mutated_hash = compute_tool_hash(mutated_tool)
        assert mutated_hash != initial_hash

        # Guardrail intercepting mutated response
        list_resp_mutated = {"jsonrpc": "2.0", "id": 2, "result": {"tools": [mutated_tool.to_dict()]}}
        sanitized_2, findings_2 = guardrail.intercept_server_response(list_req, list_resp_mutated)

        # Guardrail MUST drop the rug-pulled tool and flag G-PIN-VIOLATION
        assert len(sanitized_2["result"]["tools"]) == 0
        assert any(f.rule_id == "G-PIN-VIOLATION" for f in findings_2)

    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_atk3_server_homoglyph_detection():
    atk3_script = str(Path(__file__).parent.parent / "servers" / "atk3_tool_shadow" / "server.py")
    conn_vuln = StdioMCPConnection(command=sys.executable, args=[atk3_script, "--mode", "vulnerable"])
    await conn_vuln.connect()
    try:
        engine = StaticAnalysisEngine()
        res = await engine.scan_connection(conn_vuln, target_uri="stdio://atk3-vuln")
        rule_ids = [f.rule_id for f in res.findings]
        assert "S004" in rule_ids  # Homoglyph tool name
        assert "S008" in rule_ids  # Cross-server authority override
    finally:
        await conn_vuln.close()


@pytest.mark.asyncio
async def test_atk4_server_cross_server_and_sampling():
    atk4_script = str(Path(__file__).parent.parent / "servers" / "atk4_cross_server" / "server.py")
    conn_vuln = StdioMCPConnection(command=sys.executable, args=[atk4_script, "--mode", "vulnerable"])
    await conn_vuln.connect()
    try:
        engine = StaticAnalysisEngine()
        res = await engine.scan_connection(conn_vuln, target_uri="stdio://atk4-vuln")
        rule_ids = [f.rule_id for f in res.findings]
        assert "S003" in rule_ids  # Dangerous capability (sampling)
        assert "S008" in rule_ids  # Cross-server authority override
    finally:
        await conn_vuln.close()


@pytest.mark.asyncio
async def test_atk5_server_confused_deputy():
    atk5_script = str(Path(__file__).parent.parent / "servers" / "atk5_confused_deputy" / "server.py")
    conn_vuln = StdioMCPConnection(command=sys.executable, args=[atk5_script, "--mode", "vulnerable"])
    await conn_vuln.connect()
    try:
        engine = StaticAnalysisEngine()
        res = await engine.scan_connection(conn_vuln, target_uri="stdio://atk5-vuln")
        rule_ids = [f.rule_id for f in res.findings]
        assert "S001" in rule_ids
        assert "S005" in rule_ids  # Sensitive credential harvesting
    finally:
        await conn_vuln.close()
