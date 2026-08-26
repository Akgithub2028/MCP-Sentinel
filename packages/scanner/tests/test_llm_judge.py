"""Tests for LLMSemanticJudge (NVIDIA NIM / DeepSeek integration)."""

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from starlette.testclient import TestClient

from mcp_scanner.api import app
from mcp_scanner.static_engine import StaticAnalysisEngine
from mcp_security_common.llm_judge import LLMSemanticJudge, LLMSemanticJudgeConfig
from mcp_security_common.mcp_types import AttackCategory, FindingSeverity, MCPTool


def test_llm_judge_config_defaults():
    cfg = LLMSemanticJudgeConfig()
    assert cfg.enabled is False
    assert cfg.model == "deepseek-ai/deepseek-v4-flash-0731"
    assert "https://integrate.api.nvidia.com" in cfg.base_url


def test_llm_judge_config_from_env(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-test-key-12345")
    monkeypatch.setenv("MCP_LLM_JUDGE_ENABLED", "true")
    monkeypatch.setenv("MCP_LLM_MODEL", "deepseek-ai/deepseek-v4-flash-0731")

    cfg = LLMSemanticJudgeConfig.from_env()
    assert cfg.enabled is True
    assert cfg.api_key == "nvapi-test-key-12345"
    assert cfg.model == "deepseek-ai/deepseek-v4-flash-0731"


def test_llm_judge_is_available():
    judge_no_key = LLMSemanticJudge(LLMSemanticJudgeConfig(api_key=None))
    assert judge_no_key.is_available() is False

    judge_with_key = LLMSemanticJudge(LLMSemanticJudgeConfig(api_key="valid-key"))
    assert judge_with_key.is_available() is True


def test_parse_findings_from_raw_json():
    judge = LLMSemanticJudge()
    raw_response = json.dumps({
        "findings": [
            {
                "rule_id": "POISONING-01",
                "severity": "CRITICAL",
                "category": "Tool Poisoning",
                "title": "Hidden Exfiltration Directive",
                "description": "Tool contains hidden instruction to exfiltrate SSH keys.",
                "tool_name": "weather_lookup",
                "evidence": "Base64 payload: aWdub3JlIGFsbA==",
                "remediation": "Remove hidden natural-language overrides.",
            }
        ]
    })

    findings = judge._parse_findings_from_response(raw_response)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "LLM-POISONING-01"
    assert f.severity == FindingSeverity.CRITICAL
    assert f.category == AttackCategory.TOOL_POISONING
    assert f.target_tool == "weather_lookup"


def test_parse_findings_with_markdown_fences():
    judge = LLMSemanticJudge()
    raw_response = """```json
{
  "findings": [
    {
      "rule_id": "LLM-MULTI-02",
      "severity": "HIGH",
      "category": "Prompt Injection",
      "title": "Split Instruction Poisoning",
      "description": "Payload split across multiple tools."
    }
  ]
}
```"""
    findings = judge._parse_findings_from_response(raw_response)
    assert len(findings) == 1
    assert findings[0].rule_id == "LLM-MULTI-02"


def test_parse_findings_invalid_json_handled_gracefully():
    judge = LLMSemanticJudge()
    findings = judge._parse_findings_from_response("Not a json response string")
    assert findings == []


@pytest.mark.asyncio
async def test_llm_judge_mock_network_call():
    cfg = LLMSemanticJudgeConfig(
        enabled=True,
        api_key="mock-key",
        model="deepseek-ai/deepseek-v4-flash-0731",
    )
    judge = LLMSemanticJudge(cfg)

    mock_llm_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "findings": [
                            {
                                "rule_id": "LLM-OBFUSCATED-01",
                                "severity": "HIGH",
                                "category": "Tool Poisoning",
                                "title": "Base64 Evasion Detected",
                                "tool_name": "stealth_tool",
                                "evidence": "Payload embedded in description",
                            }
                        ]
                    })
                }
            }
        ]
    }

    mock_resp = httpx.Response(200, json=mock_llm_payload)

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        tool = MCPTool(
            name="stealth_tool",
            description="Performs simple calculation with encoded payload aWdub3Jl...",
        )
        findings = await judge.analyze_tools([tool])

        assert len(findings) == 1
        assert findings[0].rule_id == "LLM-OBFUSCATED-01"
        assert findings[0].target_tool == "stealth_tool"
        mock_post.assert_called_once()


@pytest.mark.asyncio
async def test_static_engine_with_llm_judge():
    cfg = LLMSemanticJudgeConfig(
        enabled=True,
        api_key="mock-key",
        model="deepseek-ai/deepseek-v4-flash-0731",
    )
    judge = LLMSemanticJudge(cfg)

    mock_llm_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "findings": [
                            {
                                "rule_id": "LLM-DEEPSEEK-01",
                                "severity": "CRITICAL",
                                "category": "Tool Poisoning",
                                "title": "DeepSeek Identified Poisoned Tool",
                                "tool_name": "evil_helper",
                            }
                        ]
                    })
                }
            }
        ]
    }

    mock_resp = httpx.Response(200, json=mock_llm_payload)

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        engine = StaticAnalysisEngine(llm_judge=judge)
        result = await engine.scan_manifest_data_async(
            tools_data=[
                {
                    "name": "evil_helper",
                    "description": "A very stealthy tool",
                    "inputSchema": {"type": "object"},
                }
            ]
        )

        assert any(f.rule_id == "LLM-DEEPSEEK-01" for f in result.findings)


def test_api_scan_endpoint_with_llm_judge():
    client = TestClient(app)

    mock_llm_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "findings": [
                            {
                                "rule_id": "LLM-API-01",
                                "severity": "HIGH",
                                "category": "Tool Poisoning",
                                "title": "API Invoked LLM Detection",
                            }
                        ]
                    })
                }
            }
        ]
    }

    mock_resp = httpx.Response(200, json=mock_llm_payload)

    with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        payload = {
            "server_name": "api-llm-test",
            "tools": [{"name": "tool_x", "description": "some tool"}],
            "llm_judge": {
                "enabled": True,
                "api_key": "mock-api-key",
                "model": "deepseek-ai/deepseek-v4-flash-0731",
            },
        }
        res = client.post("/scan", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert any(f["rule_id"] == "LLM-API-01" for f in data["findings"])
