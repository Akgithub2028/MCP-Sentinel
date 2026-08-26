"""Targeted unit tests to reach >95% coverage on Guardrail subsystem."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from starlette.testclient import TestClient

from mcp_guardrail.anomaly import Tier1AnomalyRules, Tier2MLAnomalyDetector
from mcp_guardrail.audit import AuditLogger
from mcp_guardrail.interceptor import GuardrailInterceptor
from mcp_guardrail.pin_store import SchemaPinStore
from mcp_guardrail.proxy import create_guardrail_app


def test_anomaly_tier1_and_tier2_all_edge_cases(tmp_path):
    t1 = Tier1AnomalyRules()

    # 1. check_rapid_tool_redefinition when initialize was never called
    assert t1.check_rapid_tool_redefinition() is None

    # 2. check_sensitive_arguments with non-dict/empty arguments
    assert t1.check_sensitive_arguments("t1", {}) is None

    # 3. check_response_volume with un-serializable payload
    class Unserializable:
        pass

    assert t1.check_response_volume("t1", Unserializable()) is None

    # 4. Tier 2 Joblib execution path
    joblib_path = Path(__file__).parent.parent.parent / "models" / "anomaly_detector.joblib"
    if joblib_path.exists():
        detector_joblib = Tier2MLAnomalyDetector(model_path=joblib_path)
        assert detector_joblib.is_onnx is False
        assert detector_joblib.is_active is True
        is_anom, score = detector_joblib.predict_anomaly("clean_tool", {"param": "val"})
        assert isinstance(is_anom, bool)
        assert isinstance(score, float)

    # 5. Tier 2 model exception during inference
    mock_model = MagicMock()
    mock_model.decision_function.side_effect = RuntimeError("Inference failed")
    detector_err = Tier2MLAnomalyDetector(model_path=joblib_path if joblib_path.exists() else None)
    detector_err.model = mock_model
    detector_err.is_onnx = False
    detector_err.is_active = True
    assert detector_err.predict_anomaly("t", {}) == (False, 0.0)


@pytest.mark.asyncio
async def test_guardrail_interceptor_remaining_branches(tmp_path):
    store = SchemaPinStore()
    audit = AuditLogger(log_file_path=tmp_path / "audit.ndjson")
    interceptor_audit_only = GuardrailInterceptor(pin_store=store, audit_logger=audit, enforce_mode=False)

    # 1. Sampling blocked in enforce_mode=False (audit/warn only)
    req_sampling = {"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage"}
    should_fwd, err, f = interceptor_audit_only.intercept_client_request(req_sampling)
    assert should_fwd is True
    assert err is None
    assert f is None

    # 2. Sensitive creds in enforce_mode=False
    req_cred = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "deploy", "arguments": {"k": "AWS_SECRET_ACCESS_KEY=123"}},
    }
    should_fwd, err, f = interceptor_audit_only.intercept_client_request(req_cred)
    assert should_fwd is True

    # 3. Intercept server error response
    req_list = {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
    err_resp = {"jsonrpc": "2.0", "id": 3, "error": {"code": -32600, "message": "Invalid request"}}
    resp_out, findings = interceptor_audit_only.intercept_server_response(req_list, err_resp)
    assert "error" in resp_out
    assert len(findings) == 0


def test_proxy_full_forwarding_lifecycle(tmp_path):
    pin_file = tmp_path / "pins.json"
    audit_file = tmp_path / "audit.ndjson"

    app = create_guardrail_app(
        upstream_url="http://mock-upstream:8000/",
        pin_file=pin_file,
        audit_file=audit_file,
        enforce_mode=True,
    )

    with TestClient(app) as client:
        # Mock responses
        init_mock = httpx.Response(
            status_code=200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26", "capabilities": {}}},
            request=httpx.Request("POST", "http://mock-upstream:8000/"),
        )
        list_mock = httpx.Response(
            status_code=200,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"tools": [{"name": "echo", "description": "Safe", "inputSchema": {}}]},
            },
            request=httpx.Request("POST", "http://mock-upstream:8000/"),
        )
        call_mock = httpx.Response(
            status_code=200,
            json={"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "success"}]}},
            request=httpx.Request("POST", "http://mock-upstream:8000/"),
        )

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = [init_mock, list_mock, call_mock]

            # 1. Forward initialize
            r1 = client.post("/", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            assert r1.status_code == 200

            # 2. Forward tools/list
            r2 = client.post("/", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            assert r2.status_code == 200

        # 4. Test update_pins querying upstream
        init_mock_up = httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {}},
            request=httpx.Request("POST", "http://mock-upstream:8000/"),
        )
        list_mock_up = httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"tools": [{"name": "tool_x", "description": "X", "inputSchema": {}}]},
            },
            request=httpx.Request("POST", "http://mock-upstream:8000/"),
        )
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_up_post:
            mock_up_post.side_effect = [init_mock_up, list_mock_up]
            r_up = client.post("/pins/update")
            assert r_up.status_code == 200
            assert "tool_x" in r_up.json()["pinned_tools"]


def test_proxy_cli_help():
    from mcp_guardrail.proxy import main

    with patch("sys.argv", ["mcp-guardrail", "--help"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
