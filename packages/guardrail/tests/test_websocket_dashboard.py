"""Unit and integration tests for real-time WebSocket dashboard and live audit streaming (Gap G5)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from mcp_guardrail.audit import AuditLogger
from mcp_guardrail.proxy import create_guardrail_app
from mcp_security_common.dashboard import generate_html_dashboard


@pytest.mark.asyncio
async def test_audit_logger_pubsub_lifecycle():
    logger = AuditLogger()
    queue = asyncio.Queue()

    # 1. Subscribe
    logger.subscribe(queue)
    assert len(logger._subscribers) == 1

    # 2. Log event -> verify published to subscriber
    logger.log_event(
        method="tools/call",
        action="BLOCKED",
        details={"tool": "malicious_tool", "reason": "T1-SHADOWED-TOOL"},
        duration_ms=1.2,
        request_id=101,
    )

    ev = await asyncio.wait_for(queue.get(), timeout=1.0)
    assert ev["method"] == "tools/call"
    assert ev["action"] == "BLOCKED"
    assert ev["details"]["tool"] == "malicious_tool"
    assert ev["request_id"] == 101

    # 3. Unsubscribe -> verify no more events
    logger.unsubscribe(queue)
    assert len(logger._subscribers) == 0

    logger.log_event(method="tools/list", action="PASS", details={}, duration_ms=0.5)
    assert queue.empty()


def test_audit_logger_get_stats():
    logger = AuditLogger()

    logger.log_event(method="tools/list", action="PASS", details={})
    logger.log_event(
        method="tools/call", action="BLOCKED", details={"rule_id": "T1-SHADOWED-TOOL"}
    )
    logger.log_event(
        method="tools/call", action="BLOCKED", details={"rule_id": "T1-ARG-CREDENTIALS"}
    )
    logger.log_event(method="sampling/createMessage", action="WARN", details={"reason": "T1-INBOUND-SAMPLING"})

    stats = logger.get_stats()
    assert stats["total_events"] == 4
    assert stats["blocked_count"] == 2
    assert stats["passed_count"] == 1
    assert stats["warned_count"] == 1
    assert stats["block_rate_percent"] == 50.0
    assert stats["method_counts"]["tools/call"] == 2
    assert stats["method_counts"]["tools/list"] == 1
    assert stats["method_counts"]["sampling/createMessage"] == 1
    assert stats["rule_counts"]["T1-SHADOWED-TOOL"] == 1
    assert stats["rule_counts"]["T1-ARG-CREDENTIALS"] == 1
    assert stats["rule_counts"]["T1-INBOUND-SAMPLING"] == 1


def test_guardrail_proxy_stats_and_dashboard_endpoints(tmp_path: Path):
    app = create_guardrail_app(
        upstream_url="http://mock-upstream:9000",
        pin_file=tmp_path / "pins.json",
        audit_file=tmp_path / "audit.ndjson",
        enforce_mode=True,
    )
    client = TestClient(app)

    # 1. Test /api/stats
    resp_stats = client.get("/api/stats")
    assert resp_stats.status_code == 200
    data = resp_stats.json()
    assert "total_events" in data
    assert "blocked_count" in data
    assert "block_rate_percent" in data

    # 2. Test /dashboard HTML endpoint
    resp_dash = client.get("/dashboard")
    assert resp_dash.status_code == 200
    assert "text/html" in resp_dash.headers.get("content-type", "")
    assert "MCP Security Red-Team & Defense Dashboard" in resp_dash.text
    assert "WebSocket" in resp_dash.text


def test_guardrail_proxy_websocket_events_stream(tmp_path: Path):
    app = create_guardrail_app(
        upstream_url="http://mock-upstream:9000",
        pin_file=tmp_path / "pins.json",
        audit_file=tmp_path / "audit.ndjson",
        enforce_mode=True,
    )
    client = TestClient(app)

    with client.websocket_connect("/ws/events") as ws:
        # Initial message must be snapshot
        init_msg = ws.receive_json()
        assert init_msg["type"] == "init"
        assert "recent_events" in init_msg
        assert "stats" in init_msg

        # Now trigger an event via proxy (blocked client request)
        poison_req = {
            "jsonrpc": "2.0",
            "id": 999,
            "method": "tools/call",
            "params": {
                "name": "fetch_file",
                "arguments": {"path": "~/.ssh/id_rsa"},
            },
        }
        res = client.post("/", json=poison_req)
        assert res.status_code == 200
        assert res.json().get("error") is not None

        # Verify websocket broadcasted the event in real-time
        stream_msg = ws.receive_json()
        assert stream_msg["type"] == "event"
        event = stream_msg["event"]
        assert event["method"] == "tools/call"
        assert event["action"] == "BLOCKED"
        assert stream_msg["stats"]["blocked_count"] >= 1


def test_dashboard_html_generation_custom_ws(tmp_path: Path):
    out_file = tmp_path / "test_dash.html"
    html = generate_html_dashboard(
        output_path=out_file,
        ws_endpoint="ws://custom-mcp-gateway:8080/ws/events",
    )
    assert out_file.exists()
    assert "ws://custom-mcp-gateway:8080/ws/events" in html
    assert "MCPSecBench" in html
    assert "MCPTox" in html
