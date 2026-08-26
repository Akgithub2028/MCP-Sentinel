"""Structured audit logging for runtime MCP proxy traffic with WebSocket live streaming."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, log_file_path: Path | str | None = None, max_in_memory: int = 1000):
        self.log_file_path = Path(log_file_path) if log_file_path else None
        self.max_in_memory = max_in_memory
        self.records: list[dict[str, Any]] = []
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self, queue: asyncio.Queue) -> None:
        """Registers a queue for real-time audit event updates."""
        self._subscribers.add(queue)

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Unregisters a subscriber queue."""
        self._subscribers.discard(queue)

    def log_event(
        self,
        method: str,
        action: str,  # PASS, WARN, BLOCKED
        details: dict[str, Any],
        duration_ms: float = 0.0,
        request_id: Any = None,
    ) -> dict[str, Any]:
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
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

        # Broadcast to real-time subscribers
        for q in list(self._subscribers):
            try:
                q.put_nowait(record)
            except (asyncio.QueueFull, Exception):
                pass

        return record

    def get_recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.records[-limit:]

    def get_stats(self) -> dict[str, Any]:
        """Calculates aggregated metrics for live security dashboard."""
        total = len(self.records)
        blocked = 0
        passed = 0
        warned = 0
        method_counts: dict[str, int] = {}
        rule_counts: dict[str, int] = {}

        for r in self.records:
            act = r.get("action", "").upper()
            if act == "BLOCKED":
                blocked += 1
            elif act == "WARN":
                warned += 1
            else:
                passed += 1

            m = r.get("method", "unknown")
            method_counts[m] = method_counts.get(m, 0) + 1

            details = r.get("details", {})
            rule_id = details.get("rule_id") or details.get("reason")
            if rule_id:
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1

        block_rate = round((blocked / total * 100.0), 1) if total > 0 else 0.0

        return {
            "total_events": total,
            "blocked_count": blocked,
            "passed_count": passed,
            "warned_count": warned,
            "block_rate_percent": block_rate,
            "method_counts": method_counts,
            "rule_counts": rule_counts,
            "active_subscribers": len(self._subscribers),
        }
