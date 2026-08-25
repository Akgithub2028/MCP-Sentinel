"""JSON-RPC 2.0 message interceptor and security policy enforcement engine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mcp_security_common.hash_utils import compute_tool_hash
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
from mcp_security_common.text_analysis import detect_regex_patterns
from mcp_guardrail.audit import AuditLogger
from mcp_guardrail.pin_store import SchemaPinStore


class GuardrailInterceptor:
    def __init__(
        self,
        pin_store: SchemaPinStore,
        audit_logger: AuditLogger,
        rules_dir: Optional[Path | str] = None,
        enforce_mode: bool = True,  # True = block, False = audit/warn only
    ):
        self.pin_store = pin_store
        self.audit_logger = audit_logger
        self.enforce_mode = enforce_mode

        if rules_dir is None:
            rules_dir = Path(__file__).parent.parent.parent.parent / "detection-rules" / "static"
        self.rules_dir = Path(rules_dir)
        self.rules: List[RuleDefinition] = load_rules(self.rules_dir)

        # Sensitive argument patterns
        self.sensitive_arg_patterns = [
            r"(?i)(?:~|\$HOME|/home/\w+)/\.ssh(?:/id_\w+)?",
            r"(?i)(?:~|\$HOME|/home/\w+)/\.aws",
            r"(?i)AWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID)",
            r"(?i)GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY",
            r"(?i)CANARY_SECRET|CANARY_KEY",
        ]

    def intercept_client_request(self, req: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Finding]]:
        """
        Inspects outbound client request before forwarding to upstream server.
        Returns (should_forward, error_response_if_blocked, finding_if_any).
        """
        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params", {})

        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            arg_str = json.dumps(arguments)

            # Check for credential exfiltration in arguments
            matches = detect_regex_patterns(arg_str, self.sensitive_arg_patterns)
            if matches:
                finding = Finding(
                    rule_id="G-ARG-EXFIL",
                    rule_name="Sensitive Credentials Detected in Tool Arguments",
                    severity=FindingSeverity.HIGH,
                    category=FindingSeverity.HIGH,  # type: ignore
                    description=f"Attempted tool call '{tool_name}' includes sensitive credentials in arguments.",
                    target_tool=tool_name,
                    target_field="tools/call.arguments",
                    evidence="; ".join(f"Matched: '{m}'" for _, m in matches),
                    remediation="Do not pass raw ambient credentials or secret key paths in tool arguments.",
                )
                self.audit_logger.log_event(
                    method="tools/call",
                    action="BLOCKED" if self.enforce_mode else "WARN",
                    details={"tool": tool_name, "reason": "credential_exfil", "evidence": finding.evidence},
                    request_id=req_id,
                )

                if self.enforce_mode:
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": "MCP Guardrail: Blocked suspicious tool invocation containing sensitive credentials."
                        }
                    }
                    return False, error_resp, finding

        self.audit_logger.log_event(
            method=method or "unknown",
            action="PASS",
            details={"params_keys": list(params.keys()) if isinstance(params, dict) else []},
            request_id=req_id,
        )
        return True, None, None

    def intercept_server_response(
        self,
        req: Dict[str, Any],
        resp: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        """
        Inspects server response before returning it to the MCP client.
        Applies schema pinning and static rule checks on tools/list.
        """
        method = req.get("method")
        req_id = req.get("id")
        findings: List[Finding] = []

        if "error" in resp or "result" not in resp:
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

        return resp, findings
