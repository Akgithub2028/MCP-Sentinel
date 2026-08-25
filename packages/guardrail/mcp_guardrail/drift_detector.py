"""Structural diff and drift detector for tool definitions and schemas."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from mcp_security_common.hash_utils import canonical_json, compute_tool_hash
from mcp_security_common.mcp_types import MCPTool


class SchemaDriftDetector:
    @staticmethod
    def diff_tools(
        baseline_tools: List[MCPTool],
        current_tools: List[MCPTool],
    ) -> Dict[str, Any]:
        """Computes structural diff between baseline and current tool lists."""
        base_map = {t.name: t for t in baseline_tools}
        curr_map = {t.name: t for t in current_tools}

        added_tools = [t.name for t in current_tools if t.name not in base_map]
        removed_tools = [t.name for t in baseline_tools if t.name not in curr_map]
        mutated_tools = []

        for name in curr_map:
            if name in base_map:
                t_curr = curr_map[name]
                t_base = base_map[name]

                diffs: List[str] = []
                if t_curr.description != t_base.description:
                    diffs.append(
                        f"Description altered (length {len(t_base.description)} -> {len(t_curr.description)})"
                    )

                if canonical_json(t_curr.inputSchema) != canonical_json(t_base.inputSchema):
                    diffs.append("inputSchema structure altered")

                if diffs:
                    mutated_tools.append({
                        "name": name,
                        "base_hash": compute_tool_hash(t_base),
                        "current_hash": compute_tool_hash(t_curr),
                        "alterations": diffs
                    })

        has_drift = bool(added_tools or removed_tools or mutated_tools)
        return {
            "has_drift": has_drift,
            "added_tools": added_tools,
            "removed_tools": removed_tools,
            "mutated_tools": mutated_tools,
        }
