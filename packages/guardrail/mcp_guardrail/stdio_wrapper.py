"""Stdio Transport Guardrail Wrapper for local subprocess MCP servers."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import sys
from pathlib import Path
from typing import Any

from mcp_guardrail.audit import AuditLogger
from mcp_guardrail.interceptor import GuardrailInterceptor
from mcp_guardrail.pin_store import SchemaPinStore

logger = logging.getLogger(__name__)


class StdioGuardrailWrapper:
    """Interposes GuardrailInterceptor between client stdio and child MCP server process."""

    def __init__(
        self,
        command: str | list[str],
        pin_store: SchemaPinStore | None = None,
        audit_logger: AuditLogger | None = None,
        rules_dir: Path | str | None = None,
        enforce_mode: bool = True,
        tier1_config_path: Path | str | None = None,
        cwd: str | Path | None = None,
        env: dict[str, str] | None = None,
    ):
        self.command = command if isinstance(command, list) else shlex.split(command)
        self.pin_store = pin_store or SchemaPinStore()
        self.audit_logger = audit_logger or AuditLogger()
        self.enforce_mode = enforce_mode
        self.cwd = str(cwd) if cwd else None
        self.env = env or dict(os.environ)

        self.interceptor = GuardrailInterceptor(
            pin_store=self.pin_store,
            audit_logger=self.audit_logger,
            rules_dir=rules_dir,
            enforce_mode=self.enforce_mode,
            tier1_config_path=tier1_config_path,
        )
        self.process: asyncio.subprocess.Process | None = None
        self._running = False
        self._pending_requests: dict[Any, dict[str, Any]] = {}

    async def start(self) -> None:
        """Spawns the child MCP server process."""
        if not self.command:
            raise ValueError("Command cannot be empty")

        self.process = await asyncio.create_subprocess_exec(
            self.command[0],
            *self.command[1:],
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.cwd,
            env=self.env,
        )
        self._running = True
        logger.info("Spawned stdio child process: %s (PID: %d)", " ".join(self.command), self.process.pid)

    async def stop(self) -> None:
        """Stops the child MCP server process cleanly."""
        self._running = False
        if self.process:
            if self.process.returncode is None:
                try:
                    self.process.terminate()
                    await asyncio.wait_for(self.process.wait(), timeout=3.0)
                except (asyncio.TimeoutError, ProcessLookupError):
                    try:
                        self.process.kill()
                    except ProcessLookupError:
                        pass
            self.process = None

    async def process_inbound_line(self, line: str) -> tuple[str | None, str | None]:
        """Processes a single line from client stdin.

        Returns (forward_to_child_line, direct_reply_to_client_line).
        If forward_to_child_line is None, the request was blocked.
        """
        line_clean = line.strip()
        if not line_clean:
            return None, None

        try:
            req_json = json.loads(line_clean)
        except Exception:
            # Pass unparseable line directly through
            return line, None

        req_id = req_json.get("id")

        # Record pending request for matching response inspection
        if req_id is not None:
            self._pending_requests[req_id] = req_json

        should_forward, err_resp, finding = self.interceptor.intercept_client_request(req_json)

        if not should_forward:
            if req_id is not None:
                self._pending_requests.pop(req_id, None)
            return None, json.dumps(err_resp or {}) + "\n"

        return json.dumps(req_json) + "\n", None

    async def process_outbound_line(self, line: str) -> tuple[str | None, str | None]:
        """Processes a single line from child server stdout.

        Returns (response_to_client_line, None).
        If modified/blocked, returns the sanitized or blocked response.
        """
        line_clean = line.strip()
        if not line_clean:
            return None, None

        try:
            resp_json = json.loads(line_clean)
        except Exception:
            return line, None

        resp_id = resp_json.get("id")
        orig_req = self._pending_requests.pop(resp_id, {}) if resp_id is not None else {}

        target_resp, findings = self.interceptor.intercept_server_response(orig_req, resp_json)

        return json.dumps(target_resp) + "\n", None

    async def run_stdio_bridge(
        self,
        reader: asyncio.StreamReader | None = None,
        writer: asyncio.StreamWriter | None = None,
    ) -> None:
        """Bridges standard I/O (or custom streams) with guardrail interception."""
        if not self.process:
            await self.start()

        assert self.process is not None
        assert self.process.stdin is not None
        assert self.process.stdout is not None

        loop = asyncio.get_running_loop()
        client_reader = reader
        if client_reader is None:
            client_reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(client_reader)
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        async def _client_to_child():
            try:
                while self._running:
                    line_bytes = await client_reader.readline()
                    if not line_bytes:
                        break
                    line_str = line_bytes.decode("utf-8", errors="replace")
                    forward_line, direct_reply = await self.process_inbound_line(line_str)

                    if direct_reply:
                        if writer:
                            writer.write(direct_reply.encode("utf-8"))
                            await writer.drain()
                        else:
                            sys.stdout.write(direct_reply)
                            sys.stdout.flush()

                    if forward_line and self.process and self.process.stdin:
                        self.process.stdin.write(forward_line.encode("utf-8"))
                        await self.process.stdin.drain()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error("Error in client_to_child bridge: %s", e)

        async def _child_to_client():
            try:
                assert self.process is not None
                assert self.process.stdout is not None
                while self._running:
                    line_bytes = await self.process.stdout.readline()
                    if not line_bytes:
                        break
                    line_str = line_bytes.decode("utf-8", errors="replace")
                    client_line, _ = await self.process_outbound_line(line_str)

                    if client_line:
                        if writer:
                            writer.write(client_line.encode("utf-8"))
                            await writer.drain()
                        else:
                            sys.stdout.write(client_line)
                            sys.stdout.flush()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error("Error in child_to_client bridge: %s", e)

        async def _log_child_stderr():
            try:
                assert self.process is not None
                assert self.process.stderr is not None
                while self._running:
                    line_bytes = await self.process.stderr.readline()
                    if not line_bytes:
                        break
                    sys.stderr.write(line_bytes.decode("utf-8", errors="replace"))
                    sys.stderr.flush()
            except (asyncio.CancelledError, Exception):
                pass

        tasks = [
            asyncio.create_task(_client_to_child()),
            asyncio.create_task(_child_to_client()),
            asyncio.create_task(_log_child_stderr()),
        ]

        try:
            await asyncio.gather(*tasks)
        finally:
            for t in tasks:
                t.cancel()
            await self.stop()
