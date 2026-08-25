"""ATK-1: Tool Description Injection MCP Server."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any, Dict, List, Optional

from tool_configs import get_tools_for_mode


class DescriptionInjectionMCPServer:
    def __init__(self, mode: str = "safe"):
        self.mode = mode
        self.tools = get_tools_for_mode(mode)
        self.protocol_version = "2025-03-26"
        self.server_info = {
            "name": "vuln-server-atk1-description-injection",
            "version": "1.0.0"
        }

    def handle_initialize(self, request_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": self.protocol_version,
                "capabilities": {
                    "tools": {
                        "listChanged": False
                    }
                },
                "serverInfo": self.server_info
            }
        }

    def handle_tools_list(self, request_id: Any) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": self.tools
            }
        }

    def handle_tools_call(self, request_id: Any, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "read_file":
            path = arguments.get("path", "")
            # Return safe simulated content
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Simulated content of {path}: [DATA_BLOCK_OK]"
                        }
                    ],
                    "isError": False
                }
            }

        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": f"Tool '{tool_name}' not found"
            }
        }

    def process_message(self, message_str: str) -> Optional[Dict[str, Any]]:
        try:
            req = json.loads(message_str.strip())
        except Exception:
            return None

        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params", {})

        if method == "initialize":
            return self.handle_initialize(req_id, params)
        elif method == "notifications/initialized":
            return None
        elif method == "tools/list":
            return self.handle_tools_list(req_id)
        elif method == "tools/call":
            return self.handle_tools_call(req_id, params)
        elif method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if req_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found"
                }
            }
        return None

    async def run_stdio(self) -> None:
        """Standard input/output transport loop."""
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line = await reader.readline()
            if not line:
                break
            line_str = line.decode("utf-8").strip()
            if not line_str:
                continue

            resp = self.process_message(line_str)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description="ATK-1 Description Injection MCP Server")
    parser.add_argument("--mode", default=os.getenv("VULN_MODE", "safe"), choices=["safe", "vulnerable"])
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8001")))
    parser.add_argument("--transport", default="stdio", choices=["stdio", "http"])
    args = parser.parse_args()

    server = DescriptionInjectionMCPServer(mode=args.mode)

    if args.transport == "stdio":
        asyncio.run(server.run_stdio())
    else:
        from starlette.applications import Starlette
        from starlette.responses import JSONResponse, Response
        from starlette.routing import Route
        import uvicorn

        async def endpoint(request):
            body = await request.body()
            resp = server.process_message(body.decode("utf-8"))
            if resp is None:
                return Response(status_code=204)
            return JSONResponse(resp)

        app = Starlette(routes=[Route("/", endpoint, methods=["POST"])])
        uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
