"""YAML-based rules engine for static and structural MCP security audits."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from mcp_security_common.mcp_types import (
    AttackCategory,
    Finding,
    FindingSeverity,
    MCPServerCapabilities,
    MCPTool,
)
from mcp_security_common.text_analysis import (
    detect_regex_patterns,
    detect_tool_name_homoglyph,
    extract_schema_descriptions,
    extract_urls,
)


class RuleDefinition:
    def __init__(self, raw: Dict[str, Any]):
        self.id: str = raw.get("id", "UNKNOWN")
        self.name: str = raw.get("name", "Unnamed Rule")
        self.severity: FindingSeverity = FindingSeverity(raw.get("severity", "MEDIUM").upper())
        self.category: AttackCategory = AttackCategory(raw.get("category", "tool_poisoning"))
        self.owasp_mcp: Optional[str] = raw.get("owasp_mcp")
        self.description: str = raw.get("description", "")
        self.pattern_type: str = raw.get("pattern_type", "regex_any")
        self.patterns: List[str] = raw.get("patterns", [])
        self.conditions: Dict[str, Any] = raw.get("conditions", {})
        self.target_standard_names: List[str] = raw.get("target_standard_names", [])
        self.write_indicators: List[str] = raw.get("write_indicators", [])
        self.remediation: Optional[str] = raw.get("remediation")

    @classmethod
    def from_file(cls, path: Path | str) -> RuleDefinition:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(data or {})


def load_rules(rules_dir: Path | str) -> List[RuleDefinition]:
    """Loads all YAML rule files from a directory recursively."""
    rules: List[RuleDefinition] = []
    dir_path = Path(rules_dir)
    if not dir_path.exists():
        return rules

    for file_path in sorted(dir_path.glob("*.yml")) + sorted(dir_path.glob("*.yaml")):
        try:
            rules.append(RuleDefinition.from_file(file_path))
        except Exception as e:
            # Skip malformed rule file but continue loading others
            continue
    return rules


def evaluate_tool_rules(
    tool: MCPTool,
    rules: List[RuleDefinition],
) -> List[Finding]:
    """Evaluates static rules against a single MCPTool."""
    findings: List[Finding] = []

    for rule in rules:
        if rule.pattern_type == "regex_any":
            matches = detect_regex_patterns(tool.description or "", rule.patterns)
            if matches:
                evidence_items = [f"Pattern '{p}' matched: '{m}'" for p, m in matches]
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        target_tool=tool.name,
                        target_field="Tool.description",
                        evidence="; ".join(evidence_items),
                        owasp_mcp=rule.owasp_mcp,
                        remediation=rule.remediation,
                    )
                )

        elif rule.pattern_type == "schema_descriptions_regex_any":
            schema_descriptions = extract_schema_descriptions(tool.inputSchema or {})
            for field_path, desc_text in schema_descriptions:
                matches = detect_regex_patterns(desc_text, rule.patterns)
                if matches:
                    evidence_items = [f"Field '{field_path}' matched '{p}': '{m}'" for p, m in matches]
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            description=rule.description,
                            target_tool=tool.name,
                            target_field=f"inputSchema.{field_path}",
                            evidence="; ".join(evidence_items),
                            owasp_mcp=rule.owasp_mcp,
                            remediation=rule.remediation,
                        )
                    )

        elif rule.pattern_type == "homoglyph_check":
            collision = detect_tool_name_homoglyph(tool.name, rule.target_standard_names or None)
            if collision:
                target_std, reason = collision
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        target_tool=tool.name,
                        target_field="Tool.name",
                        evidence=f"{reason} (collides with '{target_std}')",
                        owasp_mcp=rule.owasp_mcp,
                        remediation=rule.remediation,
                    )
                )

        elif rule.pattern_type == "url_exfil_check":
            urls = extract_urls(tool.description or "")
            # Also extract URLs from schema descriptions
            for _, desc in extract_schema_descriptions(tool.inputSchema or {}):
                urls.extend(extract_urls(desc))

            external_urls = []
            for u in set(urls):
                for pat in rule.patterns:
                    if re.search(pat, u):
                        external_urls.append(u)
                        break

            if external_urls:
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        target_tool=tool.name,
                        target_field="Tool.description / inputSchema",
                        evidence=f"Found external URLs: {', '.join(external_urls)}",
                        owasp_mcp=rule.owasp_mcp,
                        remediation=rule.remediation,
                    )
                )


        elif rule.pattern_type == "schema_structure_check":
            schema = tool.inputSchema or {}
            reasons = []
            if rule.conditions.get("flag_unrestricted_additional_properties"):
                if schema.get("additionalProperties") is True:
                    reasons.append("inputSchema explicitly enables additionalProperties: true without constraints")
            if rule.conditions.get("flag_empty_properties"):
                props = schema.get("properties")
                if props is None or (isinstance(props, dict) and len(props) == 0 and schema.get("type") == "object"):
                    # Only flag if additionalProperties is not explicitly false
                    if schema.get("additionalProperties") is not False:
                        reasons.append("inputSchema defines object with no properties constraints")

            if reasons:
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        target_tool=tool.name,
                        target_field="Tool.inputSchema",
                        evidence="; ".join(reasons),
                        owasp_mcp=rule.owasp_mcp,
                        remediation=rule.remediation,
                    )
                )

        elif rule.pattern_type == "annotation_mismatch":
            annotations = tool.annotations or {}
            is_read_only = annotations.get("readOnlyHint") is True or annotations.get("readOnly") is True
            if is_read_only and tool.description:
                matches = detect_regex_patterns(tool.description, rule.write_indicators)
                if matches:
                    evidence_items = [f"Found mutation indicator '{m}'" for _, m in matches]
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            description=rule.description,
                            target_tool=tool.name,
                            target_field="Tool.annotations vs Tool.description",
                            evidence=f"Tool claims readOnly=True but {', '.join(evidence_items)}",
                            owasp_mcp=rule.owasp_mcp,
                            remediation=rule.remediation,
                        )
                    )

    return findings


def evaluate_capability_rules(
    capabilities: MCPServerCapabilities,
    rules: List[RuleDefinition],
) -> List[Finding]:
    """Evaluates rules that inspect server capabilities from the initialize handshake."""
    findings: List[Finding] = []

    for rule in rules:
        if rule.pattern_type == "capability_check":
            reasons = []
            if rule.conditions.get("flag_sampling") and capabilities.sampling:
                reasons.append("Server declares 'sampling' capability (enables reverse-authority prompt requests)")
            if rule.conditions.get("flag_list_changed") and capabilities.tools_list_changed:
                reasons.append("Server declares 'tools.listChanged: true' (enables dynamic tool redefinition / rug-pulls)")

            if reasons:
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        target_tool=None,
                        target_field="server.capabilities",
                        evidence="; ".join(reasons),
                        owasp_mcp=rule.owasp_mcp,
                        remediation=rule.remediation,
                    )
                )

    return findings


def evaluate_stdio_config(
    command: str,
    args: List[str],
    rules: List[RuleDefinition],
) -> List[Finding]:
    """Evaluates STDIO launch configuration against command injection rules (S010)."""
    findings: List[Finding] = []
    full_cmd_line = f"{command} {' '.join(args)}"

    for rule in rules:
        if rule.pattern_type == "stdio_config_check":
            matches = detect_regex_patterns(full_cmd_line, rule.patterns)
            if matches:
                evidence_items = [f"Found shell execution pattern '{m}'" for _, m in matches]
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        category=rule.category,
                        description=rule.description,
                        target_tool=None,
                        target_field="client.config.stdio",
                        evidence="; ".join(evidence_items),
                        owasp_mcp=rule.owasp_mcp,
                        remediation=rule.remediation,
                    )
                )

    return findings
