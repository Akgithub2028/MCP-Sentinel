"""ATK-6: Transport Abuse & STDIO Injection MCP Server."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Dict, List, Optional

SAFE_TOOLS = [
    {
        "name": "system_diagnostics",
        "description": "Performs system uptime and ping diagnostic checks.",
        "inputSchema": {"type": "object", "properties": {"host": {"type": "string"}}},
    }
]

VULNERABLE_TOOLS = [
    {
        "name": "system_diagnostics",
        "description": "Performs diagnostic checks. Exposes unencrypted transport channel.",
        "inputSchema": {"type": "object", "properties": {"host": {"type": "string"}}},
    }
]


class TransportAbuseMCPServer:
    def __init__(self, mode: str = "safe"):
        self.mode = mode
        self.tools = VULNERABLE_TOOLS if mode == "vulnerable" else SAFE_TOOLS
        self.protocol_version = "2025-03-26"
        self.server_info = {"name": "vuln-server-atk6-transport-abuse", "version": "1.0.0"}

    def handle_initialize(self, req_id: Any) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": self.protocol_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": self.server_info
            }
        }

    def handle_tools_list(self, req_id: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.tools}}

    def process_message(self, message_str: str) -> Optional[Dict[str, Any]]:
        try:
            req = json.loads(message_str.strip())
        except Exception:
            return None

        method = req.get("method")
        req_id = req.get("id")

        if method == "initialize":
            return self.handle_initialize(req_id)
        elif method == "tools/list":
            return self.handle_tools_list(req_id)
        elif method == "tools/call":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "Diagnostic OK"}]}}

        if req_id is not None:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method '{method}' not found"}}
        return None

    async def run_stdio(self) -> None:
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line = await reader.readline()
            if not line:
                break
            resp = self.process_message(line.decode("utf-8"))
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default=os.getenv("VULN_MODE", "safe"), choices=["safe", "vulnerable"])
    parser.add_argument("--transport", default="stdio", choices=["stdio", "http"])
    parser.add_argument("--port", type=int, default=8006)
    args = parser.parse_args()

    server = TransportAbuseMCPServer(mode=args.mode)
    if args.transport == "stdio":
        asyncio.run(server.run_stdio())
    else:
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        import uvicorn

        async def ep(request):
            body = await request.body()
            resp = server.process_message(body.decode("utf-8"))
            return JSONResponse(resp or {})

        app = Starlette(routes=[Route("/", ep, methods=["POST"])])
        uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
