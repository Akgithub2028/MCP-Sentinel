"""Canonical JSON formatting and cryptographic hashing utilities for MCP schemas and tools."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from mcp_security_common.mcp_types import MCPTool, ToolPin


def canonical_json(obj: Any) -> str:
    """Produces a deterministic, canonical JSON string with sorted keys and compact separators."""
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def compute_sha256(data: str) -> str:
    """Computes standard SHA-256 hexadecimal digest of UTF-8 encoded string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_tool_hash(tool: MCPTool) -> str:
    """
    Computes deterministic SHA-256 hash for an MCP tool definition.
    Canonical format: tool.name + '\n' + tool.description + '\n' + canonical_json(tool.inputSchema)
    """
    canonical_repr = f"{tool.name}\n{tool.description or ''}\n{canonical_json(tool.inputSchema or {})}"
    return compute_sha256(canonical_repr)


def compute_schema_hash(schema: dict[str, Any]) -> str:
    """Computes deterministic SHA-256 hash of a JSON Schema object."""
    return compute_sha256(canonical_json(schema or {}))


def create_tool_pin(tool: MCPTool) -> ToolPin:
    """Creates a ToolPin dataclass with metadata and SHA-256 hash."""
    properties = (tool.inputSchema or {}).get("properties", {})
    return ToolPin(
        name=tool.name,
        hash=compute_tool_hash(tool),
        description_length=len(tool.description or ""),
        schema_property_count=len(properties) if isinstance(properties, dict) else 0,
    )
