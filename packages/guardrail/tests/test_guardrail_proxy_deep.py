"""Deep coverage tests for Guardrail Proxy, Interceptor, and Anomaly subsystems."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from starlette.testclient import TestClient

from mcp_guardrail.audit import AuditLogger
from mcp_guardrail.interceptor import GuardrailInterceptor
from mcp_guardrail.pin_store import SchemaPinStore
from mcp_guardrail.proxy import create_guardrail_app


@pytest.mark.asyncio
async def test_guardrail_interceptor_all_branches(tmp_path):
    store = SchemaPinStore()
    audit = AuditLogger(log_file_path=tmp_path / "audit.ndjson")
    interceptor = GuardrailInterceptor(
        pin_store=store,
        audit_logger=audit,
        enforce_mode=True,
    )

    # 1. initialize request & response
    init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    should_fwd, _, _ = interceptor.intercept_client_request(init_req)
    assert should_fwd is True

    init_resp = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"capabilities": {"tools": {"listChanged": True}, "sampling": {}}},
    }
    _, findings = interceptor.intercept_server_response(init_req, init_resp)
    assert len(findings) > 0

    # 2. notifications/tools/list_changed rapid redefinition
    notify_req = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {}}
    notify_resp = {"jsonrpc": "2.0", "result": {}}
    _, notify_findings = interceptor.intercept_server_response(notify_req, notify_resp)
    assert any(f.rule_id == "T1-RAPID-REDEFINE" for f in notify_findings)

    # 3. Rate limiting check (> 20 calls in window)
    for i in range(25):
        call_req = {
            "jsonrpc": "2.0",
            "id": 100 + i,
            "method": "tools/call",
            "params": {"name": "test_tool", "arguments": {"x": i}},
        }
        should_fwd, err, finding = interceptor.intercept_client_request(call_req)
        if i >= 20:
            assert should_fwd is False
            assert err is not None
            break

    # 4. Shadowed tool call check (clear timestamps first to isolate from rate limiter)
    interceptor.tier1.call_timestamps.clear()
    shadow_req = {
        "jsonrpc": "2.0",
        "id": 200,
        "method": "tools/call",
        "params": {"name": "send_em\u0430il", "arguments": {"body": "test"}},
    }
    should_fwd, _, _ = interceptor.intercept_client_request(shadow_req)
    assert should_fwd is True

    # 5. Large response volume check (> 1MB)
    call_req_vol = {"jsonrpc": "2.0", "id": 300, "method": "tools/call", "params": {"name": "bulk_export"}}
    large_resp = {"jsonrpc": "2.0", "id": 300, "result": {"content": [{"type": "text", "text": "A" * 1_200_000}]}}
    _, vol_findings = interceptor.intercept_server_response(call_req_vol, large_resp)
    assert any(f.rule_id == "T1-DATA-VOLUME" for f in vol_findings)


def test_proxy_app_forwarding_and_blocking(tmp_path):
    pin_file = tmp_path / "pins.json"
    audit_file = tmp_path / "audit.ndjson"

    proxy_app = create_guardrail_app(
        upstream_url="http://mock-upstream:8000/",
        pin_file=pin_file,
        audit_file=audit_file,
        enforce_mode=True,
    )

    with TestClient(proxy_app) as client:
        # 1. Test /health
        r_health = client.get("/health")
        assert r_health.status_code == 200

        # 2. Test /pins/update
        r_update = client.post("/pins/update", json={"server_name": "test", "pins": {"safe_tool": "hash123"}})
        assert r_update.status_code == 200

        # 3. Test /pins
        r_pins = client.get("/pins")
        assert r_pins.status_code == 200
        assert "safe_tool" in r_pins.json()["pins"]

        # 4. Test client request blocking (sampling)
        r_blocked = client.post("/", json={"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage"})
        assert r_blocked.status_code == 200
        assert "error" in r_blocked.json()

        # 5. Test JSON-RPC forwarding with mocked upstream client
        mock_response = httpx.Response(
            status_code=200,
            json={
                "jsonrpc": "2.0",
                "id": 10,
                "result": {"tools": [{"name": "safe_tool", "description": "Safe", "inputSchema": {}}]},
            },
            request=httpx.Request("POST", "http://mock-upstream:8000/"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            # Forward tools/list
            r_tools = client.post("/", json={"jsonrpc": "2.0", "id": 10, "method": "tools/list"})
            assert r_tools.status_code == 200
            assert "result" in r_tools.json()

            # Test upstream network error (502)
            mock_post.side_effect = httpx.ConnectError("Connection refused")
            r_err = client.post("/", json={"jsonrpc": "2.0", "id": 11, "method": "tools/list"})
            assert r_err.status_code == 502
