"""MCP Security Common Package."""

from mcp_security_common.hash_utils import (
    canonical_json,
    compute_schema_hash,
    compute_sha256,
    compute_tool_hash,
    create_tool_pin,
)
from mcp_security_common.mcp_types import (
    AttackCategory,
    Finding,
    FindingSeverity,
    MCPServerCapabilities,
    MCPTool,
    ScanResult,
    ServerPinStore,
    ToolPin,
)
from mcp_security_common.report import (
    generate_html_report,
    generate_json_report,
    generate_sarif_report,
)
from mcp_security_common.rules_engine import (
    RuleDefinition,
    evaluate_capability_rules,
    evaluate_stdio_config,
    evaluate_tool_rules,
    load_rules,
)
from mcp_security_common.text_analysis import (
    compute_text_similarity,
    detect_regex_patterns,
    detect_tool_name_homoglyph,
    extract_schema_descriptions,
    extract_urls,
    is_homoglyph_collision,
    normalize_homoglyphs,
)

__all__ = [
    "AttackCategory",
    "Finding",
    "FindingSeverity",
    "MCPServerCapabilities",
    "MCPTool",
    "RuleDefinition",
    "ScanResult",
    "ServerPinStore",
    "ToolPin",
    "canonical_json",
    "compute_schema_hash",
    "compute_sha256",
    "compute_text_similarity",
    "compute_tool_hash",
    "create_tool_pin",
    "detect_regex_patterns",
    "detect_tool_name_homoglyph",
    "evaluate_capability_rules",
    "evaluate_stdio_config",
    "evaluate_tool_rules",
    "extract_schema_descriptions",
    "extract_urls",
    "generate_html_report",
    "generate_json_report",
    "generate_sarif_report",
    "is_homoglyph_collision",
    "load_rules",
    "normalize_homoglyphs",
]
