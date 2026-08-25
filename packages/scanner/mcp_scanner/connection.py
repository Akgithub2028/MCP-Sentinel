"""MCP Connection Manager supporting stdio and HTTP transports."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import httpx

from mcp_security_common.mcp_types import MCPServerCapabilities, MCPTool


class MCPConnectionError(Exception):
    pass


class MCPConnection:
    def __init__(self):
        self.protocol_version: str = "2025-03-26"
        self.server_capabilities: Optional[MCPServerCapabilities] = None
        self.server_info: Dict[str, Any] = {}
        self._request_counter: int = 0

    def _next_id(self) -> int:
        self._request_counter += 1
        return self._request_counter

    async def connect(self) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError

    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        raise NotImplementedError

    async def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        raise NotImplementedError

    async def initialize(self) -> Tuple[MCPServerCapabilities, Dict[str, Any]]:
        """Executes mandatory MCP initialization handshake."""
        resp = await self.send_request("initialize", {
            "protocolVersion": self.protocol_version,
            "capabilities": {
                "roots": {"listChanged": True},
                "sampling": {}
            },
            "clientInfo": {
                "name": "mcp-scanner-auditor",
                "version": "0.1.0"
            }
        })

        if "error" in resp:
            raise MCPConnectionError(f"Initialize failed: {resp['error']}")

        result = resp.get("result", {})
        raw_caps = result.get("capabilities", {})
        self.server_capabilities = MCPServerCapabilities.from_dict(raw_caps)
        self.server_info = result.get("serverInfo", {})

        # Send notifications/initialized
        await self.send_notification("notifications/initialized", {})
        return self.server_capabilities, self.server_info

    async def list_tools(self) -> List[MCPTool]:
        """Queries tools/list from the server."""
        resp = await self.send_request("tools/list", {})
        if "error" in resp:
            raise MCPConnectionError(f"tools/list failed: {resp['error']}")

        result = resp.get("result", {})
        tools_data = result.get("tools", [])
        tools: List[MCPTool] = []
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

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Executes tools/call on the server."""
        resp = await self.send_request("tools/call", {
            "name": name,
            "arguments": arguments
        })
        return resp


class StdioMCPConnection(MCPConnection):
    def __init__(self, command: str, args: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None):
        super().__init__()
        self.command = command
        self.args = args or []
        self.env = env or os.environ.copy()
        self.process: Optional[asyncio.subprocess.Process] = None
        self._notifications: List[Dict[str, Any]] = []

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

    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise MCPConnectionError("Process is not connected")

        req_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {}
        }
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

    async def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        if not self.process or not self.process.stdin:
            raise MCPConnectionError("Process is not connected")

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {}
        }
        data = json.dumps(payload) + "\n"
        self.process.stdin.write(data.encode("utf-8"))
        await self.process.stdin.drain()

    def get_received_notifications(self) -> List[Dict[str, Any]]:
        return list(self._notifications)


class HttpMCPConnection(MCPConnection):
    def __init__(self, endpoint_url: str, timeout: float = 15.0):
        super().__init__()
        self.endpoint_url = endpoint_url
        self.timeout = timeout
        self.client: Optional[httpx.AsyncClient] = None

    async def connect(self) -> None:
        self.client = httpx.AsyncClient(timeout=self.timeout)

    async def close(self) -> None:
        if self.client:
            await self.client.aclose()

    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.client:
            raise MCPConnectionError("HTTP Client not connected")

        req_id = self._next_id()
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {}
        }
        try:
            resp = await self.client.post(self.endpoint_url, json=payload)
            if resp.status_code != 200:
                raise MCPConnectionError(f"HTTP {resp.status_code}: {resp.text}")
            return resp.json()
        except Exception as e:
            raise MCPConnectionError(f"HTTP request failed: {e}") from e

    async def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        if not self.client:
            raise MCPConnectionError("HTTP Client not connected")

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {}
        }
        try:
            await self.client.post(self.endpoint_url, json=payload)
        except Exception:
            pass


async def create_connection(target: str) -> MCPConnection:
    """Factory helper creating stdio or HTTP connection based on target string."""
    if target.startswith("http://") or target.startswith("https://"):
        conn = HttpMCPConnection(target)
        await conn.connect()
        return conn
    else:
        # Split command and args
        parts = target.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        conn = StdioMCPConnection(command=cmd, args=args)
        await conn.connect()
        return conn
