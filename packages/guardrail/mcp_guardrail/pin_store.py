"""Schema Pin Store for enforcing cryptographic tool integrity at runtime."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_security_common.hash_utils import compute_tool_hash
from mcp_security_common.mcp_types import MCPTool


class SchemaPinStore:
    def __init__(self, pin_file_path: Path | str | None = None):
        self.pin_file_path = Path(pin_file_path) if pin_file_path else None
        self.pins: dict[str, str] = {}  # tool_name -> sha256_hash
        self.server_name: str = "default-server"
        if self.pin_file_path and self.pin_file_path.exists():
            self.load()

    def load(self) -> None:
        if not self.pin_file_path or not self.pin_file_path.exists():
            return
        with open(self.pin_file_path, encoding="utf-8") as f:
            data = json.load(f)
            self.server_name = data.get("server_name", "default-server")
            raw_pins = data.get("pins", {})
            for k, v in raw_pins.items():
                if isinstance(v, str):
                    self.pins[k] = v
                elif isinstance(v, dict):
                    self.pins[k] = v.get("hash", "")

    def save(self, output_path: Path | str | None = None) -> None:
        target = Path(output_path) if output_path else self.pin_file_path
        if not target:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        data = {"server_name": self.server_name, "pins": self.pins}
        with open(target, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def record_pin(self, tool: MCPTool) -> str:
        h = compute_tool_hash(tool)
        self.pins[tool.name] = h
        return h

    def verify_tool(self, tool: MCPTool) -> tuple[bool, str | None, str | None]:
        """
        Verifies if tool matches pinned hash.
        Returns (is_valid, expected_hash, actual_hash).
        """
        actual_hash = compute_tool_hash(tool)
        if not self.pins:
            # Learn mode / no pins configured
            return True, None, actual_hash

        if tool.name not in self.pins:
            return False, None, actual_hash

        expected_hash = self.pins[tool.name]
        is_valid = actual_hash == expected_hash
        return is_valid, expected_hash, actual_hash


# Alias for clean naming
PinStore = SchemaPinStore
