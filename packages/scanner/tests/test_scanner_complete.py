"""Targeted unit tests to reach >95% coverage on Scanner connection and scoring subsystems."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mcp_scanner.connection import HttpMCPConnection
from mcp_scanner.scoring import format_cli_table
from mcp_security_common.mcp_types import Finding, FindingSeverity, MCPTool, ScanResult


@pytest.mark.asyncio
async def test_http_connection_complete_lifecycle():
    conn = HttpMCPConnection(endpoint_url="http://mock-server:8000/")

    # 1. Test connect
    await conn.connect()

    # 2. Mock initialize response
    mock_init = httpx.Response(
        status_code=200,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"capabilities": {"tools": {"listChanged": True}}, "serverInfo": {"name": "test-http"}},
        },
        request=httpx.Request("POST", "http://mock-server:8000/"),
    )
    # 3. Mock list_tools response
    mock_list = httpx.Response(
        status_code=200,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": [{"name": "tool1", "description": "Desc 1", "inputSchema": {}}]},
        },
        request=httpx.Request("POST", "http://mock-server:8000/"),
    )
    # 4. Mock call_tool response
    mock_call = httpx.Response(
        status_code=200,
        json={"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "result"}]}},
        request=httpx.Request("POST", "http://mock-server:8000/"),
    )
    notif_mock = httpx.Response(200, json={}, request=httpx.Request("POST", "http://mock-server:8000/"))

    with patch.object(conn.client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.side_effect = [mock_init, notif_mock, mock_list, mock_call, notif_mock]

        caps, info = await conn.initialize()
        assert caps.tools_list_changed is True

        tools = await conn.list_tools()
        assert len(tools) == 1

        call_res = await conn.call_tool("tool1", {"arg": "val"})
        assert "result" in call_res
        assert "content" in call_res["result"]

        await conn.send_notification("notifications/test", {})

    await conn.close()


def test_scoring_all_severities_and_table_colors():
    findings = [
        Finding(
            rule_id="C01",
            rule_name="Critical",
            severity=FindingSeverity.CRITICAL,
            category=FindingSeverity.CRITICAL,
            description="Crit",
            target_tool="t1",
            target_field="f1",
        ),  # type: ignore
        Finding(
            rule_id="H01",
            rule_name="High",
            severity=FindingSeverity.HIGH,
            category=FindingSeverity.HIGH,
            description="High",
            target_tool="t2",
            target_field="f2",
        ),  # type: ignore
        Finding(
            rule_id="M01",
            rule_name="Med",
            severity=FindingSeverity.MEDIUM,
            category=FindingSeverity.MEDIUM,
            description="Med",
            target_tool="t3",
            target_field="f3",
        ),  # type: ignore
        Finding(
            rule_id="L01",
            rule_name="Low",
            severity=FindingSeverity.LOW,
            category=FindingSeverity.LOW,
            description="Low",
            target_tool="t4",
            target_field="f4",
        ),  # type: ignore
        Finding(
            rule_id="I01",
            rule_name="Info",
            severity=FindingSeverity.INFO,
            category=FindingSeverity.INFO,
            description="Info",
            target_tool="t5",
            target_field="f5",
        ),  # type: ignore
    ]

    res = ScanResult(
        target_uri="http://test",
        server_name="test-server",
        tools_scanned=[MCPTool(name=f"t{i}") for i in range(1, 6)],
        findings=findings,
        pins_recorded={"t1": "hash"},
    )
    rendered = format_cli_table(res)
    assert "CRITICAL" in rendered
    assert "HIGH" in rendered
    assert "MEDIUM" in rendered
    assert "LOW" in rendered
    assert "INFO" in rendered


def test_cli_table_file_and_pin_failure(tmp_path):
    import sys

    from typer.testing import CliRunner

    from mcp_scanner.cli import app

    runner = CliRunner()

    server_path = Path(__file__).parent.parent.parent / "lab" / "servers" / "atk1_description_injection" / "server.py"

    # 1. Scan with table format saving to output file
    table_file = tmp_path / "table_output.txt"
    res_table = runner.invoke(
        app,
        [
            "scan",
            f'"{sys.executable}" "{server_path}" --mode safe',
            "--format",
            "table",
            "--output",
            str(table_file),
            "--static-only",
        ],
    )
    assert res_table.exit_code == 0
    assert table_file.exists()

    # 2. Pin invalid target
    res_pin_fail = runner.invoke(app, ["pin", "invalid_nonexistent_command_12345"])
    assert res_pin_fail.exit_code == 1
