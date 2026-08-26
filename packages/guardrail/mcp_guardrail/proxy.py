"""ASGI MITM Proxy server sitting between MCP client and upstream MCP server."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from mcp_guardrail.audit import AuditLogger
from mcp_guardrail.interceptor import GuardrailInterceptor
from mcp_guardrail.pin_store import SchemaPinStore
from mcp_security_common.dashboard import generate_html_dashboard


def create_guardrail_app(
    upstream_url: str,
    pin_file: Path | str | None = None,
    audit_file: Path | str | None = None,
    enforce_mode: bool = True,
    rules_dir: Path | str | None = None,
) -> Starlette:
    pin_store = SchemaPinStore(pin_file)
    audit_logger = AuditLogger(audit_file)
    interceptor = GuardrailInterceptor(
        pin_store=pin_store,
        audit_logger=audit_logger,
        rules_dir=rules_dir,
        enforce_mode=enforce_mode,
    )
    http_client = httpx.AsyncClient(timeout=30.0)

    async def proxy_handler(request: Request) -> Response:
        start_time = time.perf_counter()
        try:
            body = await request.body()
            req_data = request.json() if hasattr(request, "_json") else None
            if not req_data:
                req_data = json.loads(body.decode("utf-8"))
        except Exception:
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}}, status_code=400
            )

        # 1. Intercept client request
        should_forward, error_resp, finding = interceptor.intercept_client_request(req_data)
        if not should_forward:
            return JSONResponse(error_resp, status_code=200)

        # 2. Forward to upstream MCP server
        try:
            upstream_resp = await http_client.post(upstream_url, json=req_data)
            if upstream_resp.status_code != 200:
                return Response(content=upstream_resp.content, status_code=upstream_resp.status_code)
            resp_data = upstream_resp.json()
        except Exception as e:
            audit_logger.log_event(
                method=req_data.get("method", "unknown"),
                action="ERROR",
                details={"error": f"Upstream connect failed: {e}"},
                request_id=req_data.get("id"),
            )
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": req_data.get("id"),
                    "error": {"code": -32001, "message": f"Upstream connect failure: {e}"},
                },
                status_code=502,
            )

        # 3. Intercept upstream response
        sanitized_resp, findings = interceptor.intercept_server_response(req_data, resp_data)
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        audit_logger.log_event(
            method=req_data.get("method", "unknown"),
            action="PASS" if not findings else "AUDIT_FINDING",
            details={"findings_count": len(findings)},
            duration_ms=duration_ms,
            request_id=req_data.get("id"),
        )
        return JSONResponse(sanitized_resp)

    async def health_handler(request: Request) -> Response:
        return JSONResponse(
            {
                "status": "healthy",
                "upstream_url": upstream_url,
                "enforce_mode": enforce_mode,
                "pinned_tools_count": len(pin_store.pins),
            }
        )

    async def pins_handler(request: Request) -> Response:
        return JSONResponse(
            {
                "server_name": pin_store.server_name,
                "pins": pin_store.pins,
            }
        )

    async def update_pins_handler(request: Request) -> Response:
        """Learns hashes from request body or by querying upstream tools/list, and writes pin file."""
        try:
            body = {}
            try:
                body = await request.json()
            except Exception:
                pass

            if body and "pins" in body:
                pin_store.server_name = body.get("server_name", pin_store.server_name)
                for tool_name, hash_val in body["pins"].items():
                    pin_store.pins[tool_name] = hash_val
                pin_store.save()
                return JSONResponse({"status": "pins_updated", "pinned_tools": list(pin_store.pins.keys())})

            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "pin-learner", "version": "1.0"},
                },
            }
            await http_client.post(upstream_url, json=init_req)
            list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            resp = await http_client.post(upstream_url, json=list_req)
            tools_data = resp.json().get("result", {}).get("tools", [])

            from mcp_security_common.mcp_types import MCPTool

            for t in tools_data:
                tool = MCPTool(
                    name=t.get("name", ""), description=t.get("description", ""), inputSchema=t.get("inputSchema", {})
                )
                pin_store.record_pin(tool)

            pin_store.save()
            return JSONResponse({"status": "pins_updated", "pinned_tools": list(pin_store.pins.keys())})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    async def audit_logs_handler(request: Request) -> Response:
        limit = int(request.query_params.get("limit", "50"))
        return JSONResponse({"recent_events": audit_logger.get_recent_events(limit)})

    async def stats_handler(request: Request) -> Response:
        return JSONResponse(audit_logger.get_stats())

    async def dashboard_handler(request: Request) -> Response:
        html = generate_html_dashboard()
        return HTMLResponse(content=html)

    async def ws_events_handler(websocket: WebSocket) -> None:
        await websocket.accept()
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        audit_logger.subscribe(q)
        try:
            # Send initial state snapshot with recent events & aggregated stats
            recent = audit_logger.get_recent_events(limit=50)
            stats = audit_logger.get_stats()
            await websocket.send_json({"type": "init", "recent_events": recent, "stats": stats})

            # Stream new events as they happen
            while True:
                event = await q.get()
                stats = audit_logger.get_stats()
                await websocket.send_json({"type": "event", "event": event, "stats": stats})
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            audit_logger.unsubscribe(q)

    routes = [
        Route("/", proxy_handler, methods=["POST"]),
        Route("/health", health_handler, methods=["GET"]),
        Route("/pins", pins_handler, methods=["GET"]),
        Route("/pins/update", update_pins_handler, methods=["POST"]),
        Route("/audit-logs", audit_logs_handler, methods=["GET"]),
        Route("/api/stats", stats_handler, methods=["GET"]),
        Route("/dashboard", dashboard_handler, methods=["GET"]),
        WebSocketRoute("/ws/events", ws_events_handler),
    ]

    return Starlette(routes=routes)


def main():
    parser = argparse.ArgumentParser(description="MCP Runtime Guardrail Proxy")
    parser.add_argument(
        "--upstream", default=os.getenv("UPSTREAM_URL", "http://localhost:8001"), help="Upstream MCP server URL"
    )
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")), help="Proxy listen port")
    parser.add_argument(
        "--pin-file", default=os.getenv("PIN_FILE", ".guardrail-pins.json"), help="Path to schema pins file"
    )
    parser.add_argument(
        "--audit-file", default=os.getenv("AUDIT_FILE", "guardrail_audit.ndjson"), help="Path to audit log file"
    )
    parser.add_argument("--enforce", action="store_true", default=True, help="Enable enforce mode (block violations)")
    parser.add_argument(
        "--audit-only", action="store_false", dest="enforce", help="Run in audit-only mode (warn without blocking)"
    )
    args = parser.parse_args()

    app = create_guardrail_app(
        upstream_url=args.upstream,
        pin_file=args.pin_file,
        audit_file=args.audit_file,
        enforce_mode=args.enforce,
    )
    print(
        f"🛡️  Starting MCP Runtime Guardrail on port {args.port} -> Upstream: {args.upstream} (Enforce: {args.enforce})"
    )
    print(f"📊 Live Security Dashboard available at: http://localhost:{args.port}/dashboard")
    print(f"⚡ Live WebSocket Stream endpoint: ws://localhost:{args.port}/ws/events")
    uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
