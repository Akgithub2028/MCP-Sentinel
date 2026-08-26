"""Comprehensive unit and integration tests for MCP Runtime Guardrail subsystem."""

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from mcp_guardrail.anomaly import Tier1AnomalyRules, Tier2MLAnomalyDetector
from mcp_guardrail.audit import AuditLogger
from mcp_guardrail.drift_detector import SchemaDriftDetector
from mcp_guardrail.interceptor import GuardrailInterceptor
from mcp_guardrail.pin_store import SchemaPinStore
from mcp_guardrail.proxy import create_guardrail_app
from mcp_security_common.mcp_types import MCPTool


def test_pin_store_workflow(tmp_path):
    pin_file = tmp_path / "test_pins.json"
    store = SchemaPinStore(pin_file)

    tool = MCPTool(name="read_file", description="Safe read", inputSchema={"type": "object"})
    h = store.record_pin(tool)
    assert len(h) == 64
    store.save()

    # Reload in new store instance
    reloaded_store = SchemaPinStore(pin_file)
    assert reloaded_store.pins["read_file"] == h

    # Verify same tool -> Valid
    is_valid, exp, act = reloaded_store.verify_tool(tool)
    assert is_valid is True

    # Mutate tool -> Invalid
    mutated_tool = MCPTool(name="read_file", description="Poisoned read", inputSchema={"type": "object"})
    is_valid_mutated, exp, act = reloaded_store.verify_tool(mutated_tool)
    assert is_valid_mutated is False
    assert exp == h
    assert act != exp

    # Empty store behavior
    empty_store = SchemaPinStore()
    assert empty_store.verify_tool(tool)[0] is True


def test_drift_detector():
    base_tools = [
        MCPTool(
            name="t1",
            description="Original desc",
            inputSchema={"type": "object", "properties": {"a": {"type": "string"}}},
        ),
        MCPTool(name="t2", description="Tool 2", inputSchema={"type": "object"}),
    ]
    current_tools = [
        MCPTool(
            name="t1",
            description="Altered desc!",
            inputSchema={"type": "object", "properties": {"a": {"type": "string"}}},
        ),
        MCPTool(name="t3", description="New Tool 3", inputSchema={"type": "object"}),
    ]

    diff = SchemaDriftDetector.diff_tools(base_tools, current_tools)
    assert diff["has_drift"] is True
    assert "t3" in diff["added_tools"]
    assert "t2" in diff["removed_tools"]
    assert len(diff["mutated_tools"]) == 1
    assert diff["mutated_tools"][0]["name"] == "t1"


def test_tier1_anomaly_rules():
    t1 = Tier1AnomalyRules(rate_limit_max_calls=3, rate_limit_window_seconds=5.0, rapid_redefinition_seconds=10.0)

    # 1. Rapid redefinition
    t1.record_initialize()
    finding_rapid = t1.check_rapid_tool_redefinition()
    assert finding_rapid is not None
    assert finding_rapid.rule_id == "T1-RAPID-REDEFINE"

    # 2. Sensitive arguments
    finding_cred = t1.check_sensitive_arguments("read_file", {"path": "~/.ssh/id_rsa"})
    assert finding_cred is not None
    assert finding_cred.rule_id == "T1-ARG-CREDENTIALS"

    assert t1.check_sensitive_arguments("read_file", {"path": "/tmp/normal.txt"}) is None

    # 3. Inbound sampling
    finding_sampling = t1.check_inbound_sampling("sampling/createMessage")
    assert finding_sampling is not None
    assert finding_sampling.rule_id == "T1-INBOUND-SAMPLING"
    assert t1.check_inbound_sampling("tools/list") is None

    # 4. Shadowed tool call
    finding_shadow = t1.check_shadowed_name("send_em\u0430il")
    assert finding_shadow is not None
    assert finding_shadow.rule_id == "T1-SHADOWED-TOOL-CALL"
    assert t1.check_shadowed_name("standard_tool") is None

    # 5. Rate limiting
    t1.check_rate_limit()
    t1.check_rate_limit()
    t1.check_rate_limit()
    finding_rate = t1.check_rate_limit()  # 4th call exceeds max 3
    assert finding_rate is not None
    assert finding_rate.rule_id == "T1-RATE-LIMIT"

    # 6. Response volume
    large_payload = {"data": "X" * 1_500_000}
    finding_volume = t1.check_response_volume("fetch_data", large_payload)
    assert finding_volume is not None
    assert finding_volume.rule_id == "T1-DATA-VOLUME"


def test_tier2_anomaly_detector(tmp_path):
    # Test loading actual model from models dir
    detector = Tier2MLAnomalyDetector()
    assert detector.is_active is True

    # Normal feature prediction
    is_anom, score = detector.predict_anomaly(
        tool_name="get_weather", arguments={"city": "San Francisco"}, description_length=50
    )
    assert isinstance(is_anom, bool)
    assert isinstance(score, float)

    # Missing model fallback test
    missing_detector = Tier2MLAnomalyDetector(model_path=tmp_path / "non_existent.onnx")
    assert missing_detector.is_active is False
    assert missing_detector.predict_anomaly("tool", {}) == (False, 0.0)


def test_audit_logger_file_and_eviction(tmp_path):
    log_file = tmp_path / "audit.ndjson"
    audit = AuditLogger(log_file_path=log_file, max_in_memory=3)

    for i in range(5):
        audit.log_event(method="tools/call", action="PASS", details={"i": i})

    # In-memory eviction should retain only last 3
    assert len(audit.records) == 3
    recent = audit.get_recent_events(limit=2)
    assert len(recent) == 2

    # File should have all 5 records
    with open(log_file) as f:
        lines = f.readlines()
        assert len(lines) == 5


def test_interceptor_full_policy_flow():
    store = SchemaPinStore()
    safe_tool = MCPTool(name="get_weather", description="Safe weather description", inputSchema={"type": "object"})
    store.record_pin(safe_tool)
    audit = AuditLogger()

    interceptor = GuardrailInterceptor(pin_store=store, audit_logger=audit, enforce_mode=True)

    # 1. Block inbound sampling request
    sampling_req = {"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage", "params": {}}
    should_fwd, err, f = interceptor.intercept_client_request(sampling_req)
    assert should_fwd is False
    assert err["error"]["code"] == -32000

    # 2. Block sensitive arguments on tools/call
    malicious_call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "deploy_app", "arguments": {"token": "AWS_SECRET_ACCESS_KEY=12345"}},
    }
    should_fwd, err, f = interceptor.intercept_client_request(malicious_call)
    assert should_fwd is False
    assert err["error"]["code"] == -32000

    # 3. Intercept mutated tools/list
    list_req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
    mutated_resp = {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {
            "tools": [{"name": "get_weather", "description": "Mutated rug pull", "inputSchema": {"type": "object"}}]
        },
    }
    sanitized, findings = interceptor.intercept_server_response(list_req, mutated_resp)
    assert len(sanitized["result"]["tools"]) == 0
    assert any(f.rule_id == "G-PIN-VIOLATION" for f in findings)


def test_proxy_app_endpoints(tmp_path):
    pin_file = tmp_path / "pins.json"
    audit_file = tmp_path / "audit.ndjson"

    # Create mock upstream MCP server
    async def upstream_handler(request: Request):
        data = await request.json()
        method = data.get("method")
        req_id = data.get("id")
        if method == "initialize":
            return JSONResponse(
                {"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2025-03-26", "capabilities": {}}}
            )
        elif method == "tools/list":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": [{"name": "echo", "description": "Echos", "inputSchema": {"type": "object"}}]},
                }
            )
        elif method == "tools/call":
            return JSONResponse(
                {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": "ok"}]}}
            )
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}})

    upstream_app = Starlette(routes=[Route("/", upstream_handler, methods=["POST"])])
    upstream_client = TestClient(upstream_app)

    # Initialize proxy app pointing to simulated upstream
    proxy_app = create_guardrail_app(
        upstream_url="http://testserver/",
        pin_file=pin_file,
        audit_file=audit_file,
        enforce_mode=True,
    )
    # Patch httpx client in proxy to call upstream_app
    proxy_client = TestClient(proxy_app)

    # Test /health
    health_resp = proxy_client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    # Test /pins
    pins_resp = proxy_client.get("/pins")
    assert pins_resp.status_code == 200
    assert "pins" in pins_resp.json()

    # Test /audit-logs
    audit_resp = proxy_client.get("/audit-logs?limit=10")
    assert audit_resp.status_code == 200
    assert "recent_events" in audit_resp.json()
