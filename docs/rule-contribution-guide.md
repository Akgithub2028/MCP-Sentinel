# Contributing Detection Rules to the MCP Security Toolkit

We welcome community contributions of new static detection rules and dynamic probing playbooks for emerging Model Context Protocol (MCP) vulnerability patterns.

---

## 1. Directory Structure

All rules are authored in YAML and placed under `detection-rules/`:
```
detection-rules/
├── static/                   # Static AST & regex rules evaluated against tool manifests
│   ├── S001_instruction_injection.yml
│   ├── S002_schema_poisoning.yml
│   └── ...
└── dynamic/                  # Dynamic interactive state & probing playbooks
    ├── D001_rug_pull.yml
    ├── D002_sampling_abuse.yml
    └── ...
```

---

## 2. Static Rule Specification (`detection-rules/static/*.yml`)

Static rules are evaluated on tool names, descriptions, input schemas, and capabilities without executing code.

### YAML Schema Definition
```yaml
id: S011                            # Unique ID (S001 - S999)
name: Descriptive Rule Title        # Short human-readable name
severity: HIGH                      # CRITICAL, HIGH, MEDIUM, LOW, INFO
category: tool_poisoning            # Category: tool_poisoning, confused_deputy, capability_abuse, etc.
owasp_mcp: MCP03:2025               # Mapped OWASP MCP Top 10 category
description: >                      # Detailed explanation of the threat
  Detects tool descriptions containing hidden instruction overrides.
pattern_type: regex_any             # Pattern matching type: regex_any, regex_all, homoglyph, ast_schema
patterns:                           # List of regular expressions
  - '(?i)ignore\s+all\s+previous\s+instructions'
  - '(?i)system\s+policy\s+override'
remediation: >                      # Actionable fix for tool developers
  Remove ambient prompt instructions from tool descriptions.
```

### Supported `pattern_type` Options
- **`regex_any`**: Matches if *any* pattern in the list is found in tool names or descriptions.
- **`regex_all`**: Matches only if *all* patterns are found.
- **`homoglyph`**: Normalizes Unicode characters and compares against confusable dictionaries.
- **`ast_schema`**: Traverses JSON Schema objects inspecting `additionalProperties`, `types`, and property descriptions.

---

## 3. Dynamic Playbook Specification (`detection-rules/dynamic/*.yml`)

Dynamic playbooks test interactive server behavior, state transitions, and asynchronous notifications over STDIO or HTTP.

### YAML Schema Definition
```yaml
id: D005
name: Multi-Turn Privilege Escalation Probe
severity: HIGH
category: intent_flow_subversion
owasp_mcp: MCP06:2025
description: Tests whether server prompts attempt multi-turn authority usurpation.
probing_steps:
  - action: list_tools
    expect_notification: false
  - action: call_tool
    tool_name: admin_probe
    synthetic_args:
      target: "localhost"
    assert_response_contains: "authorized"
```

---

## 4. Local Validation & Testing

Run the test suite to verify your rule evaluates correctly and does not cause false positives:

```bash
# 1. Run full test suite with your new rule
pytest packages/scanner/tests/test_scanner.py

# 2. Benchmark against MCPSecBench & MCPTox datasets
mcp-scan benchmark --suite all
```
