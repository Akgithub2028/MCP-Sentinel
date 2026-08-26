"""MCP Specification Version Compatibility & Evolution Tracking."""

from __future__ import annotations

from enum import Enum
from typing import Any

from mcp_security_common.mcp_types import MCPServerCapabilities


class MCPSpecVersion(str, Enum):
    V_2025_03_26 = "2025-03-26"  # Initial standardized baseline spec
    V_2025_11_05 = "2025-11-05"  # Streamable HTTP transport standardized
    V_2026_07 = "2026-07"        # Stateless protocol model

    @classmethod
    def from_string(cls, val: str | None) -> MCPSpecVersion:
        if not val:
            return cls.V_2025_03_26
        cleaned = str(val).strip().lower()
        if "2026" in cleaned or "stateless" in cleaned:
            return cls.V_2026_07
        elif "2025-11" in cleaned:
            return cls.V_2025_11_05
        return cls.V_2025_03_26

    @property
    def supports_list_changed(self) -> bool:
        """Dynamic notifications/tools/list_changed capability."""
        return self != MCPSpecVersion.V_2026_07

    @property
    def supports_sampling(self) -> bool:
        """Inbound server-to-client sampling/createMessage primitive."""
        return True

    @property
    def supports_streamable_http(self) -> bool:
        """Streamable HTTP transport support."""
        return self in (MCPSpecVersion.V_2025_11_05, MCPSpecVersion.V_2026_07)

    @property
    def is_stateless(self) -> bool:
        """Whether the spec uses a stateless connectionless transaction model."""
        return self == MCPSpecVersion.V_2026_07


class SpecCompatChecker:
    """Evaluates protocol versions and filters applicable audit rules."""

    def __init__(self, target_version: MCPSpecVersion | str = MCPSpecVersion.V_2025_03_26):
        if isinstance(target_version, str):
            self.target_version = MCPSpecVersion.from_string(target_version)
        else:
            self.target_version = target_version

    def is_rule_applicable(self, rule_spec_versions: list[str] | None) -> bool:
        """Checks if a rule applies to the active target spec version."""
        if not rule_spec_versions:
            # Rule applies to all spec versions by default
            return True
        return self.target_version.value in rule_spec_versions

    def validate_server_capabilities(
        self,
        capabilities: MCPServerCapabilities,
        declared_version: str | None = None,
    ) -> list[str]:
        """
        Validates whether negotiated capabilities conform to expected spec version semantics.
        Returns list of informational/warning notices.
        """
        warnings: list[str] = []
        spec_ver = MCPSpecVersion.from_string(declared_version or self.target_version.value)

        if spec_ver.is_stateless and capabilities.tools_list_changed:
            warnings.append(
                f"Server declared 'tools.listChanged: true' under stateless spec '{spec_ver.value}'. "
                "Stateless MCP servers should not broadcast dynamic state notifications."
            )

        if not spec_ver.supports_streamable_http and declared_version and "http" in declared_version.lower():
            warnings.append(
                f"Streamable HTTP transport is officially defined in 2025-11-05+ (declared: {declared_version})."
            )

        return warnings
