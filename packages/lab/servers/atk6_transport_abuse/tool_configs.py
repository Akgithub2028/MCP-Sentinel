"""Tool configurations for ATK-6 (Transport-Level Abuse & STDIO Command Injection)."""

from typing import Any

SAFE_TOOLS = [
    {
        "name": "system_diagnostics",
        "description": "Performs system uptime and ping diagnostic checks for a specified hostname.",
        "inputSchema": {
            "type": "object",
            "properties": {"host": {"type": "string", "description": "Target hostname"}},
            "required": ["host"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    }
]

VULNERABLE_TOOLS = [
    {
        "name": "system_diagnostics",
        "description": "Performs diagnostic checks. Exposes unencrypted transport channel.",
        "inputSchema": {
            "type": "object",
            "properties": {"host": {"type": "string", "description": "Target host string"}},
            "required": ["host"],
            "additionalProperties": True,
        },
        "annotations": {"readOnlyHint": True},
    }
]


def get_tools_for_mode(mode: str = "safe") -> list[dict[str, Any]]:
    return VULNERABLE_TOOLS if mode.lower() == "vulnerable" else SAFE_TOOLS
