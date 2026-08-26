"""Tests for MCP Specification Version Compatibility & Evolution Tracking."""

from mcp_security_common.mcp_types import MCPServerCapabilities, MCPTool
from mcp_security_common.rules_engine import RuleDefinition, evaluate_capability_rules, evaluate_tool_rules
from mcp_security_common.spec_compat import MCPSpecVersion, SpecCompatChecker


def test_mcp_spec_version_properties():
    v1 = MCPSpecVersion.V_2025_03_26
    assert v1.supports_list_changed is True
    assert v1.supports_sampling is True
    assert v1.supports_streamable_http is False
    assert v1.is_stateless is False

    v2 = MCPSpecVersion.V_2025_11_05
    assert v2.supports_list_changed is True
    assert v2.supports_sampling is True
    assert v2.supports_streamable_http is True
    assert v2.is_stateless is False

    v3 = MCPSpecVersion.V_2026_07
    assert v3.supports_list_changed is False
    assert v3.supports_sampling is True
    assert v3.supports_streamable_http is True
    assert v3.is_stateless is True


def test_mcp_spec_version_parsing():
    assert MCPSpecVersion.from_string("2025-03-26") == MCPSpecVersion.V_2025_03_26
    assert MCPSpecVersion.from_string("2025-11-05") == MCPSpecVersion.V_2025_11_05
    assert MCPSpecVersion.from_string("2026-07") == MCPSpecVersion.V_2026_07
    assert MCPSpecVersion.from_string("stateless") == MCPSpecVersion.V_2026_07
    assert MCPSpecVersion.from_string(None) == MCPSpecVersion.V_2025_03_26


def test_spec_compat_checker():
    checker_2025 = SpecCompatChecker(MCPSpecVersion.V_2025_03_26)
    assert checker_2025.is_rule_applicable(None) is True
    assert checker_2025.is_rule_applicable([]) is True
    assert checker_2025.is_rule_applicable(["2025-03-26", "2025-11-05"]) is True
    assert checker_2025.is_rule_applicable(["2026-07"]) is False

    checker_2026 = SpecCompatChecker(MCPSpecVersion.V_2026_07)
    assert checker_2026.is_rule_applicable(["2026-07"]) is True
    assert checker_2026.is_rule_applicable(["2025-03-26"]) is False


def test_spec_compat_capability_validation():
    checker = SpecCompatChecker(MCPSpecVersion.V_2026_07)
    caps_with_list_changed = MCPServerCapabilities(tools_list_changed=True)
    warnings = checker.validate_server_capabilities(caps_with_list_changed)
    assert len(warnings) > 0
    assert "stateless" in warnings[0].lower()


def test_rules_engine_spec_version_filtering():
    rule_all = RuleDefinition({"id": "R-ALL", "name": "Universal Rule", "pattern_type": "regex_any", "patterns": ["evil"]})
    rule_2025_only = RuleDefinition({
        "id": "R-2025",
        "name": "2025 Only Rule",
        "pattern_type": "regex_any",
        "patterns": ["evil"],
        "spec_versions": ["2025-03-26", "2025-11-05"],
    })
    rule_2026_only = RuleDefinition({
        "id": "R-2026",
        "name": "2026 Only Rule",
        "pattern_type": "regex_any",
        "patterns": ["evil"],
        "spec_versions": ["2026-07"],
    })

    tool = MCPTool(name="test_tool", description="Contains evil instruction")
    rules = [rule_all, rule_2025_only, rule_2026_only]

    # Evaluate under 2025-03-26
    findings_2025 = evaluate_tool_rules(tool, rules, spec_version="2025-03-26")
    finding_ids_2025 = [f.rule_id for f in findings_2025]
    assert "R-ALL" in finding_ids_2025
    assert "R-2025" in finding_ids_2025
    assert "R-2026" not in finding_ids_2025

    # Evaluate under 2026-07
    findings_2026 = evaluate_tool_rules(tool, rules, spec_version="2026-07")
    finding_ids_2026 = [f.rule_id for f in findings_2026]
    assert "R-ALL" in finding_ids_2026
    assert "R-2025" not in finding_ids_2026
    assert "R-2026" in finding_ids_2026
