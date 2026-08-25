"""Typed protocol definitions and domain models for MCP Security Red-Team & Defense Toolkit."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> float:
        mapping = {
            FindingSeverity.CRITICAL: 4.0,
            FindingSeverity.HIGH: 3.0,
            FindingSeverity.MEDIUM: 2.0,
            FindingSeverity.LOW: 1.0,
            FindingSeverity.INFO: 0.0,
        }
        return mapping[self]


class AttackCategory(str, Enum):
    TOOL_POISONING = "tool_poisoning"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    TOOL_SHADOWING = "tool_shadowing"
    CONFUSED_DEPUTY = "confused_deputy"
    INTENT_FLOW_SUBVERSION = "intent_flow_subversion"
    CAPABILITY_ABUSE = "capability_abuse"
    COMMAND_INJECTION = "command_injection"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    EXCESSIVE_AGENCY = "excessive_agency"


@dataclass
class MCPTool:
    name: str
    description: str = ""
    inputSchema: Dict[str, Any] = field(default_factory=lambda: {"type": "object", "properties": {}})
    annotations: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.inputSchema,
        }
        if self.annotations is not None:
            data["annotations"] = self.annotations
        return data


@dataclass
class MCPServerCapabilities:
    tools_list_changed: bool = False
    sampling: bool = False
    resources: bool = False
    prompts: bool = False
    logging: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MCPServerCapabilities:
        tools_cap = data.get("tools", {})
        list_changed = isinstance(tools_cap, dict) and tools_cap.get("listChanged", False)
        sampling_cap = "sampling" in data
        resources_cap = "resources" in data
        prompts_cap = "prompts" in data
        logging_cap = "logging" in data
        return cls(
            tools_list_changed=bool(list_changed),
            sampling=bool(sampling_cap),
            resources=bool(resources_cap),
            prompts=bool(prompts_cap),
            logging=bool(logging_cap),
            raw=data,
        )


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: FindingSeverity
    category: AttackCategory
    description: str
    target_tool: Optional[str] = None
    target_field: Optional[str] = None
    evidence: Optional[str] = None
    owasp_mcp: Optional[str] = None
    remediation: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "target_tool": self.target_tool,
            "target_field": self.target_field,
            "evidence": self.evidence,
            "owasp_mcp": self.owasp_mcp,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }


@dataclass
class ToolPin:
    name: str
    hash: str
    description_length: int
    schema_property_count: int
    pinned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "hash": self.hash,
            "description_length": self.description_length,
            "schema_property_count": self.schema_property_count,
            "pinned_at": self.pinned_at,
        }


@dataclass
class ServerPinStore:
    server_id: str
    version: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    pins: Dict[str, ToolPin] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_id": self.server_id,
            "version": self.version,
            "pins": {k: v.to_dict() for k, v in self.pins.items()},
        }


@dataclass
class ScanResult:
    target_uri: str
    server_name: str = "unknown"
    server_version: str = "unknown"
    protocol_version: str = "2025-03-26"
    capabilities: Optional[MCPServerCapabilities] = None
    tools_scanned: List[MCPTool] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_duration_ms: float = 0.0
    pins_recorded: Dict[str, str] = field(default_factory=dict)

    @property
    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        max_severity = max(f.severity.score for f in self.findings)
        return round(max_severity + (0.1 * len(self.findings)), 2)

    @property
    def summary_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_uri": self.target_uri,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "protocol_version": self.protocol_version,
            "capabilities": self.capabilities.raw if self.capabilities else {},
            "tools_count": len(self.tools_scanned),
            "findings_count": len(self.findings),
            "risk_score": self.risk_score,
            "summary_counts": self.summary_counts,
            "findings": [f.to_dict() for f in self.findings],
            "pins": self.pins_recorded,
            "scan_timestamp": self.scan_timestamp,
            "scan_duration_ms": self.scan_duration_ms,
        }
