"""MCP Connection Manager supporting stdio and HTTP transports."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from typing import Any

import httpx

from mcp_security_common.mcp_types import MCPServerCapabilities, MCPTool


class MCPConnectionError(Exception):
    pass


class MCPConnection:
    def __init__(self, protocol_version: str = "2025-03-26"):
        self.protocol_version: str = protocol_version
        self.server_protocol_version: str | None = None
        self.server_capabilities: MCPServerCapabilities | None = None
        self.server_info: dict[str, Any] = {}
        self._request_counter: int = 0

    def _next_id(self) -> int:
        self._request_counter += 1
        return self._request_counter

    async def connect(self) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        raise NotImplementedError

    async def initialize(self) -> tuple[MCPServerCapabilities, dict[str, Any]]:
        """Executes mandatory MCP initialization handshake."""
        resp = await self.send_request(
            "initialize",
            {
                "protocolVersion": self.protocol_version,
                "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                "clientInfo": {"name": "mcp-scanner-auditor", "version": "0.1.0"},
            },
        )

        if "error" in resp:
            raise MCPConnectionError(f"Initialize failed: {resp['error']}")

        result = resp.get("result", {})
        self.server_protocol_version = result.get("protocolVersion")
        raw_caps = result.get("capabilities", {})
        self.server_capabilities = MCPServerCapabilities.from_dict(raw_caps)
        self.server_info = result.get("serverInfo", {})

        # Send notifications/initialized
        await self.send_notification("notifications/initialized", {})
        return self.server_capabilities, self.server_info

    async def list_tools(self) -> list[MCPTool]:
        """Queries tools/list from the server."""
        resp = await self.send_request("tools/list", {})
        if "error" in resp:
            raise MCPConnectionError(f"tools/list failed: {resp['error']}")

        result = resp.get("result", {})
        tools_data = result.get("tools", [])
        tools: list[MCPTool] = []
        for t in tools_data:
            tools.append(
                MCPTool(
                    name=t.get("name", "unnamed"),
                    description=t.get("description", ""),
                    inputSchema=t.get("inputSchema", {"type": "object", "properties": {}}),
                    annotations=t.get("annotations"),
                )
            )
        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Executes tools/call on the server."""
        resp = await self.send_request("tools/call", {"name": name, "arguments": arguments})
        return resp


class StdioMCPConnection(MCPConnection):
    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        protocol_version: str = "2025-03-26",
    ):
        super().__init__(protocol_version=protocol_version)
        self.command = command
        self.args = args or []
        self.env = env or os.environ.copy()
        self.process: asyncio.subprocess.Process | None = None
        self._notifications: list[dict[str, Any]] = []


    async def connect(self) -> None:
        cmd = [self.command] + self.args
        self.process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
        )

    async def close(self) -> None:
        if self.process:
            try:
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=3.0)
            except Exception:
                self.process.kill()

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise MCPConnectionError("Process is not connected")

        req_id = self._next_id()
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}
        data = json.dumps(payload) + "\n"
        self.process.stdin.write(data.encode("utf-8"))
        await self.process.stdin.drain()

        # Read lines until we find the response matching req_id
        while True:
            line = await self.process.stdout.readline()
            if not line:
                raise MCPConnectionError("Subprocess closed output stream prematurely")
            try:
                msg = json.loads(line.decode("utf-8").strip())
            except Exception:
                continue

            # Check if notification
            if "id" not in msg and "method" in msg:
                self._notifications.append(msg)
                continue

            if msg.get("id") == req_id:
                return msg

    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        if not self.process or not self.process.stdin:
            raise MCPConnectionError("Process is not connected")

        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        data = json.dumps(payload) + "\n"
        self.process.stdin.write(data.encode("utf-8"))
        await self.process.stdin.drain()

    def get_received_notifications(self) -> list[dict[str, Any]]:
        return list(self._notifications)


from mcp_scanner.auth import AuthProvider, MCPAuthConfig


class HttpMCPConnection(MCPConnection):
    def __init__(
        self,
        endpoint_url: str,
        timeout: float = 15.0,
        protocol_version: str = "2025-03-26",
        auth_config: MCPAuthConfig | None = None,
    ):
        super().__init__(protocol_version=protocol_version)
        self.endpoint_url = endpoint_url
        self.timeout = timeout
        self.auth_config = auth_config or MCPAuthConfig(auth_type="none")
        self.auth_provider = AuthProvider(self.auth_config)
        self.client: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        self.client = httpx.AsyncClient(timeout=self.timeout)

    async def close(self) -> None:
        if self.client:
            await self.client.aclose()

    async def send_request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.client:
            raise MCPConnectionError("HTTP Client not connected")

        req_id = self._next_id()
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}
        headers = await self.auth_provider.get_auth_headers()
        try:
            resp = await self.client.post(self.endpoint_url, json=payload, headers=headers)
            if resp.status_code != 200:
                raise MCPConnectionError(f"HTTP {resp.status_code}: {resp.text}")
            return resp.json()
        except Exception as e:
            raise MCPConnectionError(f"HTTP request failed: {e}") from e

    async def send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        if not self.client:
            raise MCPConnectionError("HTTP Client not connected")

        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        headers = await self.auth_provider.get_auth_headers()
        try:
            await self.client.post(self.endpoint_url, json=payload, headers=headers)
        except Exception:
            pass


async def create_connection(
    target: str,
    protocol_version: str = "2025-03-26",
    auth_config: MCPAuthConfig | None = None,
) -> MCPConnection:
    """Factory helper creating stdio or HTTP connection based on target string."""
    if target.startswith("http://") or target.startswith("https://"):
        conn = HttpMCPConnection(target, protocol_version=protocol_version, auth_config=auth_config)
        await conn.connect()
        return conn
    else:
        # Split command and args using shlex to respect quoted strings/paths with spaces
        parts = shlex.split(target)
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        conn = StdioMCPConnection(command=cmd, args=args, protocol_version=protocol_version)
        await conn.connect()
        return conn
