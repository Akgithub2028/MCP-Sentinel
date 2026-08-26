"""Targeted test cases to boost coverage on connection.py and scoring.py beyond 96%."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mcp_scanner.connection import HttpMCPConnection, MCPConnection, MCPConnectionError, StdioMCPConnection
from mcp_scanner.scoring import format_cli_table
from mcp_security_common.mcp_types import MCPTool


@pytest.mark.asyncio
async def test_base_mcp_connection_abstract_methods():
    conn = MCPConnection()
    with pytest.raises(NotImplementedError):
        await conn.connect()
    with pytest.raises(NotImplementedError):
        await conn.close()
    with pytest.raises(NotImplementedError):
        await conn.send_request("test")
    with pytest.raises(NotImplementedError):
        await conn.send_notification("test")


@pytest.mark.asyncio
async def test_connection_unconnected_errors():
    # 1. Stdio unconnected errors
    stdio = StdioMCPConnection(command="python")
    with pytest.raises(MCPConnectionError):
        await stdio.send_request("tools/list")
    with pytest.raises(MCPConnectionError):
        await stdio.send_notification("notifications/test")
    # Closing unconnected should be safe no-op
    await stdio.close()

    # 2. HTTP unconnected errors
    http_conn = HttpMCPConnection(endpoint_url="http://localhost:9999")
    with pytest.raises(MCPConnectionError):
        await http_conn.send_request("tools/list")
    with pytest.raises(MCPConnectionError):
        await http_conn.send_notification("notifications/test")

    # 3. HTTP status error and connection exception
    await http_conn.connect()
    with patch.object(http_conn.client, "post", new_callable=AsyncMock) as mock_post:
        # Non-200 HTTP response
        mock_post.return_value = httpx.Response(
            500, text="Internal Error", request=httpx.Request("POST", "http://localhost:9999")
        )
        with pytest.raises(MCPConnectionError):
            await http_conn.send_request("tools/list")

        # Network exception
        mock_post.side_effect = httpx.ConnectError("Connection failed")
        with pytest.raises(MCPConnectionError):
            await http_conn.send_request("tools/list")

        # Error response in initialize and list_tools
        mock_post.side_effect = [
            httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "Init fail"}},
                request=httpx.Request("POST", "http://localhost:9999"),
            ),
            httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "List fail"}},
                request=httpx.Request("POST", "http://localhost:9999"),
            ),
        ]
        with pytest.raises(MCPConnectionError):
            await http_conn.initialize()
        with pytest.raises(MCPConnectionError):
            await http_conn.list_tools()

        # Notification exception (should not raise)
        mock_post.side_effect = httpx.ConnectError("Connection failed")
        await http_conn.send_notification("notifications/test")

    await http_conn.close()


def test_scoring_plain_text_fallback():
    from mcp_security_common.mcp_types import Finding, FindingSeverity, ScanResult

    res = ScanResult(
        target_uri="http://fallback",
        server_name="fallback-server",
        tools_scanned=[MCPTool(name="t1")],
        findings=[
            Finding(
                rule_id="S001",
                rule_name="Test",
                severity=FindingSeverity.HIGH,
                category=FindingSeverity.HIGH,
                description="Plain desc",
                target_tool="t1",
                target_field="desc",
                evidence="ev",
            )  # type: ignore
        ],
    )

    with patch("rich.console.Console", side_effect=Exception("Rich failed")):
        plain_out = format_cli_table(res)
        assert "MCP Security Audit Summary: fallback-server" in plain_out
        assert "[HIGH] S001" in plain_out
