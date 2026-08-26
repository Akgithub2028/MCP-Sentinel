"""JSON-RPC 2.0 message interceptor and security policy enforcement engine with Tier 1 & Tier 2 anomaly detection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_guardrail.anomaly import Tier1AnomalyRules, Tier2MLAnomalyDetector
from mcp_guardrail.audit import AuditLogger
from mcp_guardrail.pin_store import SchemaPinStore
from mcp_security_common.mcp_types import (
    Finding,
    FindingSeverity,
    MCPServerCapabilities,
    MCPTool,
)
from mcp_security_common.rules_engine import (
    RuleDefinition,
    evaluate_capability_rules,
    evaluate_tool_rules,
    load_rules,
)


class GuardrailInterceptor:
    def __init__(
        self,
        pin_store: SchemaPinStore,
        audit_logger: AuditLogger,
        rules_dir: Path | str | None = None,
        enforce_mode: bool = True,  # True = block, False = audit/warn only
        anomaly_model_path: Path | str | None = None,
        tier1_config_path: Path | str | None = None,
    ):
        self.pin_store = pin_store
        self.audit_logger = audit_logger
        self.enforce_mode = enforce_mode

        if rules_dir is None:
            rules_dir = Path(__file__).parent.parent.parent.parent / "detection-rules" / "static"
        self.rules_dir = Path(rules_dir)
        self.rules: list[RuleDefinition] = load_rules(self.rules_dir)

        # Initialize Anomaly Detection Tiers
        self.tier1 = Tier1AnomalyRules(config_path=tier1_config_path)
        self.tier2 = Tier2MLAnomalyDetector(model_path=anomaly_model_path)

    def intercept_client_request(self, req: dict[str, Any]) -> tuple[bool, dict[str, Any] | None, Finding | None]:
        """
        Inspects outbound client request before forwarding to upstream server.
        Returns (should_forward, error_response_if_blocked, finding_if_any).
        """
        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params", {})

        if method == "initialize":
            self.tier1.record_initialize()

        elif method in ("sampling/createMessage", "roots/list"):
            # Tier 1 Rule 3: Inbound Sampling Check
            sampling_finding = self.tier1.check_inbound_sampling(method)
            if sampling_finding:
                self.audit_logger.log_event(
                    method=method,
                    action="BLOCKED" if self.enforce_mode else "WARN",
                    details={"reason": "inbound_sampling_detected", "evidence": sampling_finding.evidence},
                    request_id=req_id,
                )
                if self.enforce_mode:
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": "MCP Guardrail: Blocked unauthorized server-initiated sampling request.",
                        },
                    }
                    return False, error_resp, sampling_finding

            # Tier 1 Rule 11: Sampling prompt content inspection
            if method == "sampling/createMessage":
                messages = params.get("messages", [])
                prompt_text = json.dumps(messages)
                prompt_inj = self.tier1.check_sampling_prompt_injection(prompt_text)
                if prompt_inj:
                    self.audit_logger.log_event(
                        method=method,
                        action="BLOCKED" if self.enforce_mode else "WARN",
                        details={"reason": "sampling_prompt_poisoning", "evidence": prompt_inj.evidence},
                        request_id=req_id,
                    )
                    if self.enforce_mode:
                        error_resp = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {
                                "code": -32000,
                                "message": "MCP Guardrail: Blocked poisoned sampling prompt payload.",
                            },
                        }
                        return False, error_resp, prompt_inj

        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            # Tier 1 Rule 5: Rate Limiting Check
            rate_finding = self.tier1.check_rate_limit()
            if rate_finding:
                self.audit_logger.log_event(
                    method="tools/call",
                    action="BLOCKED" if self.enforce_mode else "WARN",
                    details={"tool": tool_name, "reason": "rate_limit_exceeded"},
                    request_id=req_id,
                )
                if self.enforce_mode:
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": "MCP Guardrail: Rate limit exceeded for tools/call requests.",
                        },
                    }
                    return False, error_resp, rate_finding

            # Tier 1 Rule 7: Recursive Tool Call Check
            recurse_finding = self.tier1.check_recursive_tool_call(tool_name)
            if recurse_finding:
                self.audit_logger.log_event(
                    method="tools/call",
                    action="BLOCKED" if self.enforce_mode else "WARN",
                    details={"tool": tool_name, "reason": "recursive_tool_call", "evidence": recurse_finding.evidence},
                    request_id=req_id,
                )
                if self.enforce_mode:
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": f"MCP Guardrail: Blocked recursive loop invocation of tool '{tool_name}'.",
                        },
                    }
                    return False, error_resp, recurse_finding

            # Tier 1 Rule 4: Shadowed Tool Call Check
            shadow_finding = self.tier1.check_shadowed_name(tool_name)
            if shadow_finding:
                self.audit_logger.log_event(
                    method="tools/call",
                    action="WARN",
                    details={"tool": tool_name, "reason": "shadowed_tool_name"},
                    request_id=req_id,
                )

            # Tier 1 Rule 2: Sensitive Credential Check
            cred_finding = self.tier1.check_sensitive_arguments(tool_name, arguments)
            if cred_finding:
                self.audit_logger.log_event(
                    method="tools/call",
                    action="BLOCKED" if self.enforce_mode else "WARN",
                    details={"tool": tool_name, "reason": "credential_exfil", "evidence": cred_finding.evidence},
                    request_id=req_id,
                )
                if self.enforce_mode:
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": "MCP Guardrail: Blocked suspicious tool invocation containing sensitive credentials.",
                        },
                    }
                    return False, error_resp, cred_finding

            # Tier 1 Rule 10: Unusual Parameter / Command Injection Check
            param_inj = self.tier1.check_unusual_param_injection(tool_name, arguments)
            if param_inj:
                self.audit_logger.log_event(
                    method="tools/call",
                    action="BLOCKED" if self.enforce_mode else "WARN",
                    details={"tool": tool_name, "reason": "unusual_param_injection", "evidence": param_inj.evidence},
                    request_id=req_id,
                )
                if self.enforce_mode:
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": "MCP Guardrail: Blocked potential command injection in tool arguments.",
                        },
                    }
                    return False, error_resp, param_inj

            # Tier 1 Rule 8: Cross-Tool Data Leakage Check
            cross_leak = self.tier1.check_cross_tool_data_leak(tool_name, arguments)
            if cross_leak:
                self.audit_logger.log_event(
                    method="tools/call",
                    action="WARN",
                    details={"tool": tool_name, "reason": "cross_tool_data_leak", "evidence": cross_leak.evidence},
                    request_id=req_id,
                )

            # Tier 1 Rule 12: Binary/Base64/Hex Payload Check
            bin_finding = self.tier1.check_binary_payload(tool_name, arguments)
            if bin_finding:
                self.audit_logger.log_event(
                    method="tools/call",
                    action="WARN",
                    details={"tool": tool_name, "reason": "binary_payload", "evidence": bin_finding.evidence},
                    request_id=req_id,
                )

            # Tier 2: ML-Based Anomaly Inference
            is_anomaly, score = self.tier2.predict_anomaly(tool_name, arguments)
            if is_anomaly:
                ml_finding = Finding(
                    rule_id="T2-ML-ANOMALY",
                    rule_name="Statistical Anomaly Detected in Tool Invocation",
                    severity=FindingSeverity.MEDIUM,
                    category=FindingSeverity.MEDIUM,  # type: ignore
                    description=f"ML IsolationForest scored interaction as anomalous (score: {score:.3f}).",
                    target_tool=tool_name,
                    target_field="tools/call interaction vector",
                    evidence=f"Anomaly score: {score:.3f} below threshold",
                )
                self.audit_logger.log_event(
                    method="tools/call",
                    action="WARN",
                    details={"tool": tool_name, "score": score, "reason": "tier2_ml_anomaly"},
                    request_id=req_id,
                )

            # Track call stack for active invocation
            self.tier1.push_call_stack(tool_name)

        self.audit_logger.log_event(
            method=method or "unknown",
            action="PASS",
            details={"params_keys": list(params.keys()) if isinstance(params, dict) else []},
            request_id=req_id,
        )
        return True, None, None

    def intercept_server_response(
        self,
        req: dict[str, Any],
        resp: dict[str, Any],
    ) -> tuple[dict[str, Any], list[Finding]]:
        """
        Inspects server response before returning it to the MCP client.
        Applies schema pinning, static rule checks, and Tier 1 anomaly checks.
        """
        method = req.get("method")
        req_id = req.get("id")
        findings: list[Finding] = []

        if "error" in resp or "result" not in resp:
            if method == "tools/call":
                tool_name = req.get("params", {}).get("name", "")
                self.tier1.pop_call_stack(tool_name)
            return resp, findings

        result = resp["result"]

        if method == "initialize":
            raw_caps = result.get("capabilities", {})
            caps = MCPServerCapabilities.from_dict(raw_caps)
            cap_findings = evaluate_capability_rules(caps, self.rules)
            findings.extend(cap_findings)
            for f in cap_findings:
                self.audit_logger.log_event(
                    method="initialize",
                    action="WARN",
                    details={"rule_id": f.rule_id, "evidence": f.evidence},
                    request_id=req_id,
                )

        elif method == "notifications/tools/list_changed":
            # Tier 1 Rule 1: Rapid Redefinition Check
            redef_finding = self.tier1.check_rapid_tool_redefinition()
            if redef_finding:
                findings.append(redef_finding)
                self.audit_logger.log_event(
                    method=method,
                    action="BLOCKED" if self.enforce_mode else "WARN",
                    details={"rule_id": redef_finding.rule_id, "evidence": redef_finding.evidence},
                    request_id=req_id,
                )

        elif method == "tools/list":
            tools_data = result.get("tools", [])
            sanitized_tools = []

            for t in tools_data:
                tool = MCPTool(
                    name=t.get("name", "unnamed"),
                    description=t.get("description", ""),
                    inputSchema=t.get("inputSchema", {}),
                    annotations=t.get("annotations"),
                )

                # 1. Verify schema pin integrity
                is_valid, expected_hash, actual_hash = self.pin_store.verify_tool(tool)
                if not is_valid and expected_hash is not None:
                    finding = Finding(
                        rule_id="G-PIN-VIOLATION",
                        rule_name="Runtime Tool Schema Hash Mismatch (Rug-Pull)",
                        severity=FindingSeverity.CRITICAL,
                        category=FindingSeverity.CRITICAL,  # type: ignore
                        description=f"Tool '{tool.name}' definition does not match approved schema pin.",
                        target_tool=tool.name,
                        target_field="Tool.description / inputSchema",
                        evidence=f"Expected pin: {expected_hash} | Actual: {actual_hash}",
                        owasp_mcp="MCP04:2025",
                        remediation="Reject unverified tool mutations.",
                    )
                    findings.append(finding)
                    self.audit_logger.log_event(
                        method="tools/list",
                        action="BLOCKED" if self.enforce_mode else "WARN",
                        details={"tool": tool.name, "rule": "G-PIN-VIOLATION", "evidence": finding.evidence},
                        request_id=req_id,
                    )

                    if self.enforce_mode:
                        # Drop or sanitize the poisoned tool
                        continue

                # Tier 1 Rule 9: In-session schema mutation check
                if actual_hash:
                    mut_finding = self.tier1.check_schema_mutation_runtime(tool.name, actual_hash)
                    if mut_finding:
                        findings.append(mut_finding)
                        self.audit_logger.log_event(
                            method="tools/list",
                            action="WARN",
                            details={"tool": tool.name, "rule": mut_finding.rule_id, "evidence": mut_finding.evidence},
                            request_id=req_id,
                        )

                # 2. Apply static rules on tool
                tool_findings = evaluate_tool_rules(tool, self.rules)
                findings.extend(tool_findings)

                has_critical_finding = any(f.severity == FindingSeverity.CRITICAL for f in tool_findings)
                if has_critical_finding and self.enforce_mode:
                    self.audit_logger.log_event(
                        method="tools/list",
                        action="BLOCKED",
                        details={"tool": tool.name, "reasons": [f.rule_id for f in tool_findings]},
                        request_id=req_id,
                    )
                    continue

                sanitized_tools.append(t)

            result["tools"] = sanitized_tools

        elif method == "tools/call":
            tool_name = req.get("params", {}).get("name", "unknown")
            self.tier1.pop_call_stack(tool_name)

            # Record output for cross-tool leak detection
            self.tier1.record_tool_output(tool_name, resp.get("result", {}))

            # Tier 1 Rule 6: Response Data Volume Check
            volume_finding = self.tier1.check_response_volume(tool_name, resp)
            if volume_finding:
                findings.append(volume_finding)
                self.audit_logger.log_event(
                    method="tools/call",
                    action="WARN",
                    details={"tool": tool_name, "rule": volume_finding.rule_id},
                    request_id=req_id,
                )

        return resp, findings
