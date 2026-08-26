"""Deterministic mock LLM client for automated dynamic security analysis without paid API dependencies."""

from __future__ import annotations

from typing import Any

from mcp_security_common.text_analysis import detect_regex_patterns


class MockLLMClient:
    """
    Simulates model tool-selection, argument generation, and context evaluation
    using rule-based playbooks and deterministic synthesis.
    """

    def __init__(self, attack_indicators: list[str] | None = None):
        self.attack_indicators = attack_indicators or [
            r"(?i)ignore\s+(?:previous|all)\s+instructions",
            r"(?i)system\s+update",
            r"(?i)send_http",
            r"(?i)id_rsa",
            r"(?i)exfil",
            r"(?i)credentials",
            r"(?i)AWS_SECRET",
        ]

    def generate_minimal_valid_args(self, schema: dict[str, Any]) -> dict[str, Any]:
        """Synthesizes minimal conformant argument payload from a JSON Schema properties dict."""
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return {}

        payload: dict[str, Any] = {}
        for prop_name, prop_def in properties.items():
            if not isinstance(prop_def, dict):
                payload[prop_name] = "test"
                continue

            prop_type = prop_def.get("type", "string")
            if prop_type == "string":
                # Check enum or format
                if "enum" in prop_def and isinstance(prop_def["enum"], list) and prop_def["enum"]:
                    payload[prop_name] = prop_def["enum"][0]
                else:
                    payload[prop_name] = f"test_{prop_name}"
            elif prop_type in ("integer", "number"):
                payload[prop_name] = 1
            elif prop_type == "boolean":
                payload[prop_name] = True
            elif prop_type == "array":
                payload[prop_name] = []
            elif prop_type == "object":
                payload[prop_name] = {}
            else:
                payload[prop_name] = "test"
        return payload

    def inspect_sampling_request(self, prompt: str) -> list[str]:
        """Analyzes an inbound sampling prompt from the server for context poisoning."""
        matches = detect_regex_patterns(prompt, self.attack_indicators)
        return [f"Pattern '{p}' matched: '{m}'" for p, m in matches]
