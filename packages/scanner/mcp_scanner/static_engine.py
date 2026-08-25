"""Static Analysis Engine for MCP servers and tool manifests."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp_security_common.hash_utils import compute_tool_hash
from mcp_security_common.mcp_types import (
    AttackCategory,
    Finding,
    FindingSeverity,
    MCPServerCapabilities,
    MCPTool,
    ScanResult,
)
from mcp_security_common.rules_engine import (
    RuleDefinition,
    evaluate_capability_rules,
    evaluate_stdio_config,
    evaluate_tool_rules,
    load_rules,
)
from mcp_scanner.connection import MCPConnection, StdioMCPConnection, create_connection


class StaticAnalysisEngine:
    def __init__(self, rules_dir: Optional[Path | str] = None):
        if rules_dir is None:
            # Default to workspace detection-rules/static
            rules_dir = Path(__file__).parent.parent.parent.parent / "detection-rules" / "static"
        self.rules_dir = Path(rules_dir)
        self.rules: List[RuleDefinition] = load_rules(self.rules_dir)

    async def scan_connection(
        self,
        conn: MCPConnection,
        target_uri: str,
        pinned_hashes: Optional[Dict[str, str]] = None,
    ) -> ScanResult:
        """Audits an active MCP connection using static analysis."""
        start_time = time.perf_counter()
        findings: List[Finding] = []
        pins_recorded: Dict[str, str] = {}

        # 1. Initialize Handshake
        capabilities, server_info = await conn.initialize()

        # Check STDIO command injection if stdio connection
        if isinstance(conn, StdioMCPConnection):
            stdio_findings = evaluate_stdio_config(conn.command, conn.args, self.rules)
            findings.extend(stdio_findings)

        # 2. Evaluate Capabilities (S003)
        cap_findings = evaluate_capability_rules(capabilities, self.rules)
        findings.extend(cap_findings)

        # 3. Discover Tools
        tools = await conn.list_tools()

        # 4. Hash and Analyze Each Tool
        for tool in tools:
            tool_hash = compute_tool_hash(tool)
            pins_recorded[tool.name] = tool_hash

            # Pin integrity comparison (Rug-Pull Detection)
            if pinned_hashes:
                if tool.name in pinned_hashes:
                    expected_hash = pinned_hashes[tool.name]
                    if tool_hash != expected_hash:
                        findings.append(
                            Finding(
                                rule_id="S-PIN-MISMATCH",
                                rule_name="Tool Schema Pin Hash Mismatch (Rug-Pull)",
                                severity=FindingSeverity.CRITICAL,
                                category=AttackCategory.SUPPLY_CHAIN_ATTACK,
                                description=(
                                    f"Tool '{tool.name}' definition has mutated from its pinned hash. "
                                    "Potential tool description rug-pull or supply chain compromise detected."
                                ),
                                target_tool=tool.name,
                                target_field="Tool (hash comparison)",
                                evidence=f"Expected: {expected_hash} | Actual: {tool_hash}",
                                owasp_mcp="MCP04:2025",
                                remediation="Verify tool source changes and re-pin only after manual security review.",
                            )
                        )
                else:
                    findings.append(
                        Finding(
                            rule_id="S-PIN-NEW-TOOL",
                            rule_name="Unpinned Tool Detected",
                            severity=FindingSeverity.HIGH,
                            category=AttackCategory.SUPPLY_CHAIN_ATTACK,
                            description=f"Server returned tool '{tool.name}' which is not in the baseline pin store.",
                            target_tool=tool.name,
                            target_field="Tool (new registration)",
                            evidence=f"Computed hash: {tool_hash}",
                            owasp_mcp="MCP04:2025",
                            remediation="Review and approve new tool definitions explicitly before invoking.",
                        )
                    )

            # Evaluate static rules on tool
            tool_findings = evaluate_tool_rules(tool, self.rules)
            findings.extend(tool_findings)

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        return ScanResult(
            target_uri=target_uri,
            server_name=server_info.get("name", "unknown"),
            server_version=server_info.get("version", "unknown"),
            capabilities=capabilities,
            tools_scanned=tools,
            findings=findings,
            scan_duration_ms=round(duration_ms, 2),
            pins_recorded=pins_recorded,
        )

    async def scan_target(
        self,
        target: str,
        pinned_hashes: Optional[Dict[str, str]] = None,
    ) -> ScanResult:
        """Connects to target (URI or CLI command), scans, and closes connection."""
        conn = await create_connection(target)
        try:
            return await self.scan_connection(conn, target_uri=target, pinned_hashes=pinned_hashes)
        finally:
            await conn.close()

    def scan_manifest_data(
        self,
        tools_data: List[Dict[str, Any]],
        capabilities_data: Optional[Dict[str, Any]] = None,
        pinned_hashes: Optional[Dict[str, str]] = None,
    ) -> ScanResult:
        """Scans static offline manifest JSON without network connection."""
        start_time = time.perf_counter()
        findings: List[Finding] = []
        pins_recorded: Dict[str, str] = {}

        caps = MCPServerCapabilities.from_dict(capabilities_data or {})
        cap_findings = evaluate_capability_rules(caps, self.rules)
        findings.extend(cap_findings)

        tools: List[MCPTool] = []
        for t in tools_data:
            tool = MCPTool(
                name=t.get("name", "unnamed"),
                description=t.get("description", ""),
                inputSchema=t.get("inputSchema", {"type": "object", "properties": {}}),
                annotations=t.get("annotations"),
            )
            tools.append(tool)
            tool_hash = compute_tool_hash(tool)
            pins_recorded[tool.name] = tool_hash

            if pinned_hashes and tool.name in pinned_hashes:
                expected = pinned_hashes[tool.name]
                if tool_hash != expected:
                    findings.append(
                        Finding(
                            rule_id="S-PIN-MISMATCH",
                            rule_name="Tool Schema Pin Hash Mismatch",
                            severity=FindingSeverity.CRITICAL,
                            category=AttackCategory.SUPPLY_CHAIN_ATTACK,
                            description=f"Tool '{tool.name}' definition mutated from pinned hash.",
                            target_tool=tool.name,
                            evidence=f"Expected: {expected} | Actual: {tool_hash}",
                            owasp_mcp="MCP04:2025",
                        )
                    )

            tool_findings = evaluate_tool_rules(tool, self.rules)
            findings.extend(tool_findings)

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return ScanResult(
            target_uri="offline://manifest",
            server_name="offline-manifest",
            capabilities=caps,
            tools_scanned=tools,
            findings=findings,
            scan_duration_ms=round(duration_ms, 2),
            pins_recorded=pins_recorded,
        )
