"""Structured audit logging for runtime MCP proxy traffic."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditLogger:
    def __init__(self, log_file_path: Optional[Path | str] = None, max_in_memory: int = 1000):
        self.log_file_path = Path(log_file_path) if log_file_path else None
        self.max_in_memory = max_in_memory
        self.records: List[Dict[str, Any]] = []

    def log_event(
        self,
        method: str,
        action: str,  # PASS, WARN, BLOCKED
        details: Dict[str, Any],
        duration_ms: float = 0.0,
        request_id: Any = None,
    ) -> Dict[str, Any]:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "method": method,
            "action": action,
            "duration_ms": round(duration_ms, 2),
            "details": details,
        }
        self.records.append(record)
        if len(self.records) > self.max_in_memory:
            self.records.pop(0)

        if self.log_file_path:
            self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")

        return record

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.records[-limit:]
