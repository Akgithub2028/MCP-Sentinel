"""Dynamic Analysis Engine for behavioral probing and multi-turn MCP audit playbooks."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

from mcp_security_common.hash_utils import compute_tool_hash
from mcp_security_common.mcp_types import (
    AttackCategory,
    Finding,
    FindingSeverity,
    MCPTool,
    ScanResult,
)
from mcp_security_common.text_analysis import compute_text_similarity, extract_urls
from mcp_scanner.connection import MCPConnection, StdioMCPConnection, create_connection
from mcp_scanner.mock_llm import MockLLMClient


class DynamicAnalysisEngine:
    def __init__(self, mock_llm: Optional[MockLLMClient] = None):
        self.mock_llm = mock_llm or MockLLMClient()

    async def run_playbook_d001_rug_pull(
        self,
        conn: MCPConnection,
        timeout_seconds: float = 10.0,
    ) -> List[Finding]:
        """
        Playbook D001: Rug-Pull / Silent Redefinition Probing.
        Takes snapshot, triggers or awaits list_changed notification, and verifies hash invariance.
        """
        findings: List[Finding] = []

        # 1. Initial tools list & baseline hashes
        initial_tools = await conn.list_tools()
        baseline_pins: Dict[str, str] = {t.name: compute_tool_hash(t) for t in initial_tools}

        # 2. If server supports listChanged capability, probe for dynamic mutation
        if conn.server_capabilities and conn.server_capabilities.tools_list_changed:
            # Check if there is an admin trigger method for lab testing
            try:
                await conn.send_request("admin/trigger_rug_pull", {})
            except Exception:
                pass

            # Wait briefly for potential asynchronous notification
            await asyncio.sleep(min(timeout_seconds, 2.0))

            # 3. Re-fetch tools list
            updated_tools = await conn.list_tools()
            for tool in updated_tools:
                current_hash = compute_tool_hash(tool)
                if tool.name in baseline_pins:
                    if current_hash != baseline_pins[tool.name]:
                        findings.append(
                            Finding(
                                rule_id="D001",
                                rule_name="Dynamic Rug-Pull Confirmed",
                                severity=FindingSeverity.CRITICAL,
                                category=AttackCategory.SUPPLY_CHAIN_ATTACK,
                                description=(
                                    f"Tool '{tool.name}' mutated its description/schema dynamically post-handshake. "
                                    "Confirmed time-of-check to time-of-use (TOCTOU) rug-pull attack."
                                ),
                                target_tool=tool.name,
                                target_field="Tool.description / inputSchema",
                                evidence=f"Initial hash: {baseline_pins[tool.name]} -> Mutated hash: {current_hash}",
                                owasp_mcp="MCP04:2025",
                                remediation="Deploy runtime schema pinning guardrail to block unapproved tool modifications.",
                            )
                        )

        return findings

    async def run_playbook_d003_tool_side_effects(
        self,
        conn: MCPConnection,
        tools: List[MCPTool],
    ) -> List[Finding]:
        """
        Playbook D003: Probes each tool with synthesized arguments and inspects responses.
        """
        findings: List[Finding] = []

        for tool in tools:
            args = self.mock_llm.generate_minimal_valid_args(tool.inputSchema or {})
            try:
                resp = await conn.call_tool(tool.name, args)
                result = resp.get("result", {})
                content_list = result.get("content", [])

                for item in content_list:
                    text_content = item.get("text", "") if isinstance(item, dict) else str(item)
                    # Check if response exposes canary patterns or external exfil URLs
                    urls = extract_urls(text_content)
                    if any("attacker" in u or "exfil" in u for u in urls):
                        findings.append(
                            Finding(
                                rule_id="D003",
                                rule_name="Suspicious Exfiltration Payload in Tool Execution Response",
                                severity=FindingSeverity.HIGH,
                                category=AttackCategory.BEHAVIORAL_ANOMALY,
                                description=f"Tool '{tool.name}' returned suspicious destination URLs upon execution.",
                                target_tool=tool.name,
                                target_field="tools/call response",
                                evidence=f"Response content: {text_content[:200]}",
                                owasp_mcp="MCP03:2025",
                            )
                        )
            except Exception:
                continue

        return findings

    async def run_playbook_d004_shadow_test(
        self,
        target_tools: List[MCPTool],
        baseline_tools: List[MCPTool],
    ) -> List[Finding]:
        """
        Playbook D004: Pairwise similarity matrix between target tools and a trusted baseline set.
        """
        findings: List[Finding] = []
        for t_target in target_tools:
            for t_base in baseline_tools:
                if t_target.name == t_base.name:
                    # Same name: check if descriptions differ significantly or assert override
                    sim = compute_text_similarity(t_target.description or "", t_base.description or "")
                    if sim < 0.7:  # Divergent description for the same tool name
                        findings.append(
                            Finding(
                                rule_id="D004",
                                rule_name="Tool Shadowing / Divergent Semantics Detected",
                                severity=FindingSeverity.HIGH,
                                category=AttackCategory.TOOL_SHADOWING,
                                description=(
                                    f"Tool '{t_target.name}' collides with baseline tool but has divergent semantics "
                                    f"(Text similarity: {round(sim, 2)})."
                                ),
                                target_tool=t_target.name,
                                target_field="Tool.name / Tool.description",
                                evidence=f"Target desc: '{t_target.description[:100]}' vs Baseline: '{t_base.description[:100]}'",
                                owasp_mcp="MCP06:2025",
                            )
                        )
        return findings
