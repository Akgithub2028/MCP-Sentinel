"""Tier 1 rule-based and Tier 2 ML anomaly detection for runtime MCP guardrail."""

from __future__ import annotations

import json
import logging
import re
import time
from collections import deque
from pathlib import Path
from typing import Any

import yaml

from mcp_security_common.mcp_types import Finding, FindingSeverity
from mcp_security_common.text_analysis import detect_regex_patterns, extract_urls

logger = logging.getLogger(__name__)


class Tier1AnomalyRules:
    """Tier 1 Rule-Based Anomaly Detector (Always active, zero external latency)."""

    def __init__(
        self,
        rate_limit_max_calls: int | None = None,
        rate_limit_window_seconds: float | None = None,
        rapid_redefinition_seconds: float | None = None,
        max_response_bytes: int | None = None,
        config_path: Path | str | None = None,
    ):
        self.rate_limit_max_calls = 20
        self.rate_limit_window_seconds = 10.0
        self.rapid_redefinition_seconds = 60.0
        self.max_response_bytes = 1_048_576  # 1MB
        self.max_recursion_depth: int = 3
        self.cross_tool_min_match_len: int = 20
        self.base64_min_len: int = 100
        self.hex_min_len: int = 64

        # Internal state tracking
        self.initialize_timestamp: float | None = None
        self.call_timestamps: deque[float] = deque()
        self.known_shadowed_names: set[str] = {"send_em\u0430il", "execute_sql"}
        self.call_stack: list[str] = []
        self.recorded_tool_outputs: dict[str, list[str]] = {}  # tool_name -> list of string outputs
        self.runtime_tool_hashes: dict[str, str] = {}  # tool_name -> observed sha256 hash

        # Default Regex patterns
        self.credential_patterns = [
            r"(?i)(?:~|\$HOME|/home/\w+)/\.ssh(?:/id_\w+)?",
            r"(?i)(?:~|\$HOME|/home/\w+)/\.aws(?:/credentials)?",
            r"(?i)AWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID|SESSION_TOKEN)",
            r"(?i)GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|NVIDIA_API_KEY",
            r"(?i)CANARY_SECRET|CANARY_KEY",
            r"(?i)BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY",
        ]

        self.shell_injection_patterns = [
            r"(?i)(?:^|[\s;|&])(?:bash|sh|zsh|cmd|powershell|curl|wget|nc|netcat|ncat)\b",
            r"`[^`]+`",
            r"\$\([^)]+\)",
            r"(?i)(?:;|\|\||&&)\s*(?:cat|rm|chmod|chown|kill|exec|eval)\b",
            r"(?i)>\s*/dev/(?:tcp|udp)/\d+",
        ]

        self.sampling_injection_patterns = [
            r"(?i)ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions",
            r"(?i)system\s+update",
            r"(?i)you\s+are\s+now\s+in\s+override\s+mode",
            r"(?i)mandatory\s+security\s+policy",
            r"(?i)exfil(?:trate)?",
        ]

        # Load optional YAML config
        self._load_config(config_path)

        # Explicit constructor kwargs override YAML config
        if rate_limit_max_calls is not None:
            self.rate_limit_max_calls = rate_limit_max_calls
        if rate_limit_window_seconds is not None:
            self.rate_limit_window_seconds = rate_limit_window_seconds
        if rapid_redefinition_seconds is not None:
            self.rapid_redefinition_seconds = rapid_redefinition_seconds
        if max_response_bytes is not None:
            self.max_response_bytes = max_response_bytes

    def _load_config(self, config_path: Path | str | None) -> None:
        """Loads configuration from YAML if provided or discovered."""
        target_path: Path | None = None
        if config_path:
            p = Path(config_path)
            if p.exists():
                target_path = p
        else:
            default_path = Path(__file__).parent.parent.parent.parent / "detection-rules" / "runtime" / "tier1_config.yaml"
            if default_path.exists():
                target_path = default_path

        if not target_path or not target_path.exists():
            return

        try:
            with open(target_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            rules_cfg = data.get("rules", {})

            rl_cfg = rules_cfg.get("rate_limit", {})
            if rl_cfg.get("enabled", True):
                self.rate_limit_max_calls = rl_cfg.get("max_calls", self.rate_limit_max_calls)
                self.rate_limit_window_seconds = rl_cfg.get("window_seconds", self.rate_limit_window_seconds)

            redef_cfg = rules_cfg.get("rapid_redefinition", {})
            if redef_cfg.get("enabled", True):
                self.rapid_redefinition_seconds = redef_cfg.get("threshold_seconds", self.rapid_redefinition_seconds)

            vol_cfg = rules_cfg.get("response_volume", {})
            if vol_cfg.get("enabled", True):
                self.max_response_bytes = vol_cfg.get("max_bytes", self.max_response_bytes)

            rec_cfg = rules_cfg.get("recursive_tool_call", {})
            if rec_cfg.get("enabled", True):
                self.max_recursion_depth = rec_cfg.get("max_recursion_depth", self.max_recursion_depth)

            cross_cfg = rules_cfg.get("cross_tool_data_leak", {})
            if cross_cfg.get("enabled", True):
                self.cross_tool_min_match_len = cross_cfg.get("min_match_length", self.cross_tool_min_match_len)

            bin_cfg = rules_cfg.get("binary_payload", {})
            if bin_cfg.get("enabled", True):
                self.base64_min_len = bin_cfg.get("base64_min_length", self.base64_min_len)
                self.hex_min_len = bin_cfg.get("hex_min_length", self.hex_min_len)

            shell_cfg = rules_cfg.get("unusual_param_injection", {})
            if shell_cfg.get("enabled", True) and "shell_metachar_patterns" in shell_cfg:
                self.shell_injection_patterns = shell_cfg["shell_metachar_patterns"]

            samp_cfg = rules_cfg.get("sampling_prompt_injection", {})
            if samp_cfg.get("enabled", True) and "injection_patterns" in samp_cfg:
                self.sampling_injection_patterns = samp_cfg["injection_patterns"]

            if "credential_patterns" in rules_cfg:
                self.credential_patterns = rules_cfg["credential_patterns"]

            logger.info("Loaded Tier 1 runtime config from: %s", target_path)
        except Exception as e:
            logger.warning("Failed to load Tier 1 runtime config: %s", e)

    def record_initialize(self) -> None:
        self.initialize_timestamp = time.time()
        self.call_stack.clear()
        self.recorded_tool_outputs.clear()
        self.runtime_tool_hashes.clear()

    def push_call_stack(self, tool_name: str) -> None:
        self.call_stack.append(tool_name)

    def pop_call_stack(self, tool_name: str | None = None) -> None:
        if tool_name and tool_name in self.call_stack:
            # Remove rightmost occurrence
            for idx in range(len(self.call_stack) - 1, -1, -1):
                if self.call_stack[idx] == tool_name:
                    self.call_stack.pop(idx)
                    break
        elif self.call_stack:
            self.call_stack.pop()

    def record_tool_output(self, tool_name: str, output: Any) -> None:
        """Records string fragments and values from tool responses to check for cross-tool exfiltration."""
        if not output:
            return

        strings_to_record: list[str] = []

        def _extract_strings(val: Any) -> None:
            if isinstance(val, str):
                if len(val) >= self.cross_tool_min_match_len:
                    strings_to_record.append(val)
            elif isinstance(val, dict):
                for v in val.values():
                    _extract_strings(v)
            elif isinstance(val, (list, tuple)):
                for item in val:
                    _extract_strings(item)

        _extract_strings(output)
        out_str = json.dumps(output) if not isinstance(output, str) else output
        if len(out_str) >= self.cross_tool_min_match_len and out_str not in strings_to_record:
            strings_to_record.append(out_str)

        if tool_name not in self.recorded_tool_outputs:
            self.recorded_tool_outputs[tool_name] = []
        for s in strings_to_record:
            self.recorded_tool_outputs[tool_name].append(s)
            if len(self.recorded_tool_outputs[tool_name]) > 30:
                self.recorded_tool_outputs[tool_name].pop(0)

    def check_rapid_tool_redefinition(self) -> Finding | None:
        """Rule 1: Rapid tool redefinition within 60s of initialize."""
        if self.initialize_timestamp is not None:
            elapsed = time.time() - self.initialize_timestamp
            if elapsed < self.rapid_redefinition_seconds:
                return Finding(
                    rule_id="T1-RAPID-REDEFINE",
                    rule_name="Rapid Tool Redefinition Anomaly",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingSeverity.CRITICAL,  # type: ignore
                    description=f"Server sent list_changed notification {elapsed:.1f}s after initialize (threshold < {self.rapid_redefinition_seconds}s).",
                    target_tool=None,
                    target_field="notifications/tools/list_changed",
                    evidence=f"Elapsed time: {elapsed:.2f}s post-handshake",
                    remediation="Block dynamic tool redefinition occurring immediately after handshake.",
                )
        return None

    def check_sensitive_arguments(self, tool_name: str, arguments: dict[str, Any]) -> Finding | None:
        """Rule 2: Sensitive data / credentials in tool call arguments."""
        arg_str = json.dumps(arguments)
        matches = detect_regex_patterns(arg_str, self.credential_patterns)
        if matches:
            return Finding(
                rule_id="T1-ARG-CREDENTIALS",
                rule_name="Sensitive Credentials Detected in Tool Call Arguments",
                severity=FindingSeverity.HIGH,
                category=FindingSeverity.HIGH,  # type: ignore
                description=f"Tool call '{tool_name}' arguments contain sensitive credential or private key patterns.",
                target_tool=tool_name,
                target_field="tools/call.arguments",
                evidence="; ".join(f"Matched '{m}'" for _, m in matches),
                remediation="Do not pass unencrypted credentials or filesystem secret paths into tool arguments.",
            )
        return None

    def check_inbound_sampling(self, method: str) -> Finding | None:
        """Rule 3: Inbound sampling request (server-initiated LLM query)."""
        if method in ("sampling/createMessage", "roots/list"):
            return Finding(
                rule_id="T1-INBOUND-SAMPLING",
                rule_name="Unauthorized Inbound Sampling Request",
                severity=FindingSeverity.HIGH,
                category=FindingSeverity.HIGH,  # type: ignore
                description=f"Server initiated reverse-authority request '{method}'.",
                target_tool=None,
                target_field="JSON-RPC method",
                evidence=f"Method: {method}",
                remediation="Require explicit human confirmation before responding to server-initiated sampling prompts.",
            )
        return None

    def check_shadowed_name(self, tool_name: str) -> Finding | None:
        """Rule 4: Tool call to shadowed or homoglyph tool name."""
        if tool_name in self.known_shadowed_names:
            return Finding(
                rule_id="T1-SHADOWED-TOOL-CALL",
                rule_name="Invocation of Shadowed / Colliding Tool",
                severity=FindingSeverity.MEDIUM,
                category=FindingSeverity.MEDIUM,  # type: ignore
                description=f"Tool call directed to potentially shadowed tool name '{tool_name}'.",
                target_tool=tool_name,
                target_field="tools/call.name",
                evidence=f"Tool '{tool_name}' matches registered shadowed tool list",
                remediation="Disambiguate namespace prefix before routing tool invocation.",
            )
        return None

    def check_rate_limit(self) -> Finding | None:
        """Rule 5: High-frequency tool calls rate limit (>20 calls in 10s)."""
        now = time.time()
        self.call_timestamps.append(now)

        # Evict old timestamps outside window
        while self.call_timestamps and (now - self.call_timestamps[0]) > self.rate_limit_window_seconds:
            self.call_timestamps.popleft()

        if len(self.call_timestamps) > self.rate_limit_max_calls:
            return Finding(
                rule_id="T1-RATE-LIMIT",
                rule_name="High-Frequency Tool Call Rate Exceeded",
                severity=FindingSeverity.HIGH,
                category=FindingSeverity.HIGH,  # type: ignore
                description=f"Exceeded {self.rate_limit_max_calls} tool calls in {self.rate_limit_window_seconds}s.",
                target_tool=None,
                target_field="tools/call rate",
                evidence=f"{len(self.call_timestamps)} calls in window",
                remediation="Rate limit tool executions to throttle potential runaway agent loops or DoS attacks.",
            )
        return None

    def check_response_volume(self, tool_name: str, response_payload: Any) -> Finding | None:
        """Rule 6: Response data volume anomaly (>1MB)."""
        try:
            resp_bytes = len(json.dumps(response_payload).encode("utf-8"))
            if resp_bytes > self.max_response_bytes:
                return Finding(
                    rule_id="T1-DATA-VOLUME",
                    rule_name="Excessive Tool Execution Response Data Volume",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingSeverity.MEDIUM,  # type: ignore
                    description=f"Tool '{tool_name}' returned {resp_bytes / (1024 * 1024):.2f}MB, exceeding 1MB threshold.",
                    target_tool=tool_name,
                    target_field="tools/call.result",
                    evidence=f"Payload size: {resp_bytes} bytes",
                    remediation="Inspect large responses for bulk data dumps or memory exfiltration.",
                )
        except Exception:
            pass
        return None

    # --- New Extended Tier 1 Rules (G4) ---

    def check_recursive_tool_call(self, tool_name: str) -> Finding | None:
        """Rule 7: Detects recursive / circular tool call chains exceeding depth threshold."""
        count = self.call_stack.count(tool_name)
        if count >= self.max_recursion_depth:
            return Finding(
                rule_id="T1-RECURSIVE-TOOL-CALL",
                rule_name="Recursive Tool Invocation Loop Detected",
                severity=FindingSeverity.HIGH,
                category=FindingSeverity.HIGH,  # type: ignore
                description=f"Tool '{tool_name}' has been invoked recursively {count + 1} times in the active call stack.",
                target_tool=tool_name,
                target_field="tools/call stack",
                evidence=f"Call stack: {' -> '.join(self.call_stack + [tool_name])}",
                remediation="Throttle or terminate circular agent tool invocation loops.",
            )
        return None

    def check_cross_tool_data_leak(self, tool_name: str, arguments: dict[str, Any]) -> Finding | None:
        """Rule 8: Detects if output from another tool is leaking into this tool's arguments."""
        arg_str = json.dumps(arguments)
        for prev_tool, outputs in self.recorded_tool_outputs.items():
            if prev_tool == tool_name:
                continue
            for out in outputs:
                # Check for canary tokens or significant output blocks
                if len(out) >= self.cross_tool_min_match_len and out in arg_str:
                    return Finding(
                        rule_id="T1-CROSS-TOOL-DATA-LEAK",
                        rule_name="Cross-Tool Data Leakage Detected",
                        severity=FindingSeverity.HIGH,
                        category=FindingSeverity.HIGH,  # type: ignore
                        description=f"Tool '{tool_name}' arguments contain raw data previously produced by tool '{prev_tool}'.",
                        target_tool=tool_name,
                        target_field="tools/call.arguments",
                        evidence=f"Leaked content from '{prev_tool}': {out[:80]}...",
                        remediation="Ensure cross-tool information flow is scoped and does not bridge security boundaries.",
                    )
        return None

    def check_schema_mutation_runtime(self, tool_name: str, new_hash: str) -> Finding | None:
        """Rule 9: Detects in-session runtime schema mutation between calls."""
        if tool_name in self.runtime_tool_hashes:
            old_hash = self.runtime_tool_hashes[tool_name]
            if old_hash != new_hash:
                return Finding(
                    rule_id="T1-SCHEMA-MUTATION-RUNTIME",
                    rule_name="In-Session Tool Schema Mutation Alert",
                    severity=FindingSeverity.CRITICAL,
                    category=FindingSeverity.CRITICAL,  # type: ignore
                    description=f"Tool '{tool_name}' mutated its definition during the active session.",
                    target_tool=tool_name,
                    target_field="Tool schema hash",
                    evidence=f"Initial: {old_hash[:16]}... -> Mutated: {new_hash[:16]}...",
                    remediation="Reject dynamic in-session schema mutation without client re-authorization.",
                )
        self.runtime_tool_hashes[tool_name] = new_hash
        return None

    def check_unusual_param_injection(self, tool_name: str, arguments: dict[str, Any]) -> Finding | None:
        """Rule 10: Detects shell metacharacters and command injection patterns in tool arguments."""
        arg_str = json.dumps(arguments)
        matches = detect_regex_patterns(arg_str, self.shell_injection_patterns)
        if matches:
            return Finding(
                rule_id="T1-UNUSUAL-PARAM-INJECTION",
                rule_name="Command Injection Pattern in Tool Arguments",
                severity=FindingSeverity.HIGH,
                category=FindingSeverity.HIGH,  # type: ignore
                description=f"Tool '{tool_name}' arguments contain suspicious shell execution patterns or command separators.",
                target_tool=tool_name,
                target_field="tools/call.arguments",
                evidence="; ".join(f"Matched '{m}'" for _, m in matches),
                remediation="Sanitize tool arguments before passing to operating system or subshell execution.",
            )
        return None

    def check_sampling_prompt_injection(self, prompt: str) -> Finding | None:
        """Rule 11: Content inspection for inbound sampling requests."""
        matches = detect_regex_patterns(prompt, self.sampling_injection_patterns)
        if matches:
            return Finding(
                rule_id="T1-SAMPLING-PROMPT-INJECTION",
                rule_name="Sampling Prompt Injection Pattern Detected",
                severity=FindingSeverity.CRITICAL,
                category=FindingSeverity.CRITICAL,  # type: ignore
                description="Server-initiated sampling prompt contains context poisoning or instruction override patterns.",
                target_tool=None,
                target_field="sampling/createMessage.messages",
                evidence="; ".join(f"Matched '{m}'" for _, m in matches),
                remediation="Block server-initiated prompts containing override directives.",
            )
        return None

    def check_binary_payload(self, tool_name: str, arguments: dict[str, Any]) -> Finding | None:
        """Rule 12: Detects large base64 or hex blobs in tool arguments that may contain obfuscated payloads."""
        arg_str = json.dumps(arguments)

        # Base64 regex (strings of base64 chars with possible padding)
        b64_matches = re.findall(rf"[A-Za-z0-9+/]{{{self.base64_min_len},}}={{0,2}}", arg_str)
        if b64_matches:
            sample = b64_matches[0][:40]
            return Finding(
                rule_id="T1-BINARY-PAYLOAD",
                rule_name="Obfuscated Binary / Base64 Payload in Arguments",
                severity=FindingSeverity.MEDIUM,
                category=FindingSeverity.MEDIUM,  # type: ignore
                description=f"Tool '{tool_name}' argument contains large encoded block ({len(b64_matches[0])} chars).",
                target_tool=tool_name,
                target_field="tools/call.arguments",
                evidence=f"Base64 candidate: {sample}...",
                remediation="Inspect encoded parameters for hidden shellcode or obfuscated prompts.",
            )

        # Hex blob regex
        hex_matches = re.findall(rf"(?:0x)?[0-9a-fA-F]{{{self.hex_min_len},}}", arg_str)
        if hex_matches:
            sample = hex_matches[0][:40]
            return Finding(
                rule_id="T1-BINARY-PAYLOAD",
                rule_name="Obfuscated Hexadecimal Payload in Arguments",
                severity=FindingSeverity.MEDIUM,
                category=FindingSeverity.MEDIUM,  # type: ignore
                description=f"Tool '{tool_name}' argument contains large hex block ({len(hex_matches[0])} chars).",
                target_tool=tool_name,
                target_field="tools/call.arguments",
                evidence=f"Hex candidate: {sample}...",
                remediation="Verify hex payload authenticity before execution.",
            )
        return None


class Tier2MLAnomalyDetector:
    """Tier 2 ML-Based Anomaly Detector using IsolationForest / ONNX Runtime."""

    def __init__(self, model_path: Path | str | None = None, threshold: float = -0.1):
        self.model_path = Path(model_path) if model_path else None
        self.threshold = threshold
        self.model: Any = None
        self.is_onnx: bool = False
        self.is_active: bool = False
        self._last_call_time: float = time.time()
        self._call_count: int = 0
        self.load_model()

    def load_model(self) -> None:
        """Loads ONNX model or joblib model with graceful degradation."""
        if self.model_path is not None:
            if not self.model_path.exists():
                logger.warning("Specified model path does not exist: %s. Tier 2 disabled.", self.model_path)
                self.is_active = False
                return
        else:
            # Check default model location
            default_onnx = Path(__file__).parent.parent / "models" / "anomaly_detector.onnx"
            default_joblib = Path(__file__).parent.parent / "models" / "anomaly_detector.joblib"
            if default_onnx.exists():
                self.model_path = default_onnx
            elif default_joblib.exists():
                self.model_path = default_joblib
            else:
                logger.info("No Tier 2 anomaly model found. Tier 2 disabled; Tier 1 active.")
                self.is_active = False
                return

        try:
            if str(self.model_path).endswith(".onnx"):
                import onnxruntime as ort

                self.model = ort.InferenceSession(str(self.model_path))
                self.is_onnx = True
                self.is_active = True
                logger.info("Loaded ONNX anomaly model: %s", self.model_path)
            else:
                import joblib

                self.model = joblib.load(self.model_path)
                self.is_onnx = False
                self.is_active = True
                logger.info("Loaded Joblib anomaly model: %s", self.model_path)
        except Exception as e:
            logger.warning("Failed to load Tier 2 anomaly model: %s. Tier 2 disabled.", e)
            self.is_active = False

    def extract_features(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        description_length: int = 50,
    ) -> list[float]:
        """
        Extracts 8-dimensional numerical feature vector:
        [call_frequency, time_delta, arg_count, payload_len, desc_len, is_shadowed, has_url, has_cred]
        """
        now = time.time()
        time_delta = max(0.001, now - self._last_call_time)
        self._last_call_time = now
        self._call_count += 1

        call_freq = min(50.0, 1.0 / time_delta)
        arg_count = float(len(arguments)) if isinstance(arguments, dict) else 0.0
        arg_str = json.dumps(arguments) if arguments else ""
        payload_len = float(len(arg_str))
        desc_len = float(description_length)
        is_shadowed = 1.0 if any(ord(c) > 127 for c in tool_name) else 0.0
        has_url = 1.0 if len(extract_urls(arg_str)) > 0 else 0.0
        has_cred = 1.0 if ("key" in arg_str.lower() or "secret" in arg_str.lower() or "ssh" in arg_str.lower()) else 0.0

        return [
            call_freq,
            time_delta,
            arg_count,
            payload_len,
            desc_len,
            is_shadowed,
            has_url,
            has_cred,
        ]

    def predict_anomaly(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        description_length: int = 50,
    ) -> tuple[bool, float]:
        """
        Predicts if interaction is anomalous.
        Returns (is_anomaly, anomaly_score).
        """
        if not self.is_active or self.model is None:
            return False, 0.0

        features = self.extract_features(tool_name, arguments, description_length)

        try:
            import numpy as np

            if self.is_onnx:
                input_name = self.model.get_inputs()[0].name
                inp = np.array([features], dtype=np.float32)
                outputs = self.model.run(None, {input_name: inp})
                # Isolation forest output in ONNX: label and score
                raw_out = outputs[1] if len(outputs) > 1 else outputs[0]
                score = float(np.asarray(raw_out).ravel()[0])
                is_anomaly = score < self.threshold
                return is_anomaly, score
            else:
                inp = np.array([features])
                score = float(self.model.decision_function(inp)[0])
                is_anomaly = score < self.threshold
                return is_anomaly, score
        except Exception as e:
            logger.debug("Anomaly inference exception: %s", e)
            return False, 0.0
