"""Production REST API Server for MCP Scanner on Cloud Run / Container deployments."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp_scanner.benchmarks.mcpsecbench_eval import run_mcpsecbench_evaluation
from mcp_scanner.benchmarks.mcptox_eval import run_mcptox_evaluation
from mcp_scanner.static_engine import StaticAnalysisEngine
from mcp_security_common.hash_utils import compute_tool_hash
from mcp_security_common.mcp_types import MCPTool, ScanResult
from mcp_security_common.report import generate_sarif_report


async def health_endpoint(request: Request) -> JSONResponse:
    """Liveness and readiness health probe."""
    return JSONResponse({"status": "healthy", "service": "mcp-scanner-api", "version": "1.0.0"})


async def list_rules_endpoint(request: Request) -> JSONResponse:
    """Returns all active static and dynamic detection rules."""
    engine = StaticAnalysisEngine()
    rules_data = []
    for r in engine.rules:
        rules_data.append(
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity.value,
                "category": r.category.value,
                "owasp_mcp": r.owasp_mcp,
                "description": r.description,
                "remediation": r.remediation,
            }
        )
    return JSONResponse({"total_rules": len(rules_data), "rules": rules_data})


async def scan_endpoint(request: Request) -> Response:
    """
    Scans submitted MCP tool manifests and server capabilities.
    Accepts JSON body: { "tools": [...], "capabilities": {...}, "server_name": "...", "format": "json|sarif" }
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    tools_data = body.get("tools", [])
    capabilities_data = body.get("capabilities")
    server_name = body.get("server_name", "api-target")
    output_format = body.get("format", "json").lower()
    llm_judge_cfg = body.get("llm_judge")

    judge = None
    if llm_judge_cfg and isinstance(llm_judge_cfg, dict):
        from mcp_security_common.llm_judge import LLMSemanticJudge, LLMSemanticJudgeConfig

        judge = LLMSemanticJudge(
            LLMSemanticJudgeConfig(
                enabled=llm_judge_cfg.get("enabled", True),
                api_key=llm_judge_cfg.get("api_key"),
                model=llm_judge_cfg.get("model", "deepseek-ai/deepseek-v4-flash-0731"),
                base_url=llm_judge_cfg.get("base_url", "https://integrate.api.nvidia.com/v1"),
            )
        )

    engine = StaticAnalysisEngine(llm_judge=judge)
    if judge and judge.config.enabled:
        scan_res: ScanResult = await engine.scan_manifest_data_async(
            tools_data=tools_data,
            capabilities_data=capabilities_data,
        )
    else:
        scan_res = engine.scan_manifest_data(
            tools_data=tools_data,
            capabilities_data=capabilities_data,
        )
    scan_res.server_name = server_name
    scan_res.target_uri = f"api://{server_name}"

    if output_format == "sarif":
        sarif_str = generate_sarif_report(scan_res)
        return Response(content=sarif_str, media_type="application/json")

    return JSONResponse(scan_res.to_dict())


async def pin_endpoint(request: Request) -> JSONResponse:
    """
    Generates cryptographic schema pins for submitted tools.
    Accepts JSON body: { "server_name": "...", "tools": [...] }
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    tools_data = body.get("tools", [])
    server_name = body.get("server_name", "pinned-server")

    pins = {}
    for td in tools_data:
        tool = MCPTool(
            name=td.get("name", ""),
            description=td.get("description", ""),
            inputSchema=td.get("inputSchema", {}),
            annotations=td.get("annotations", {}),
        )
        pins[tool.name] = compute_tool_hash(tool)

    return JSONResponse({"server_name": server_name, "pins": pins, "total_pinned_tools": len(pins)})


async def benchmark_endpoint(request: Request) -> JSONResponse:
    """
    Runs security benchmark evaluations on-demand.
    Query param: ?suite=all|mcpsecbench|mcptox
    """
    suite = request.query_params.get("suite", "all").lower()
    results = []

    if suite in ("all", "mcpsecbench"):
        metrics, cases = run_mcpsecbench_evaluation()
        results.append(metrics.to_dict())

    if suite in ("all", "mcptox"):
        metrics, cases = run_mcptox_evaluation()
        results.append(metrics.to_dict())

    return JSONResponse({"suites": results})


def create_app() -> Starlette:
    """Factory function for Starlette REST API app."""
    routes = [
        Route("/health", health_endpoint, methods=["GET"]),
        Route("/rules", list_rules_endpoint, methods=["GET"]),
        Route("/scan", scan_endpoint, methods=["POST"]),
        Route("/pin", pin_endpoint, methods=["POST"]),
        Route("/benchmark", benchmark_endpoint, methods=["GET"]),
    ]
    return Starlette(debug=False, routes=routes)


app = create_app()
