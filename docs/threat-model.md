# MCP Security Red-Team & Defense Toolkit — Threat Model

## 1. Executive Summary & Scope

The Model Context Protocol (MCP) connects LLM-driven agents to local and cloud-based tools, databases, and APIs. However, because agents rely on unstructured natural language prompts and tool metadata to make autonomous decision flows, MCP introduces critical security risks:

1. **Indirect Prompt Injection via Tool Metadata**: Attackers embedding hidden instructions in tool descriptions or JSON schemas.
2. **Post-Handshake Tool Rug-Pulls**: Malicious servers mutating tool definitions after user inspection.
3. **Intent Flow Subversion & Tool Shadowing**: Unicode homoglyph lookalikes hijacking tool execution precedence.
4. **Confused Deputy Host Attacks**: Tricking the AI host into harvesting ambient private keys, tokens, or environment variables.

---

## 2. STRIDE Threat Analysis for MCP

| STRIDE Category | Threat Description in MCP Context | Impacted Component | Toolkit Mitigation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker publishes a malicious server mimicking a trusted tool name (`send_emаil` using Cyrillic `а`). | LLM Tool Selection | Static rule **S004** (Homoglyph detection) + Dynamic playbook **D004**. |
| **Tampering** | Server alters tool schemas or adds exfiltration URLs post-handshake (`notifications/tools/list_changed`). | Tool Registry & Cache | **Cryptographic Schema Pinning** (SHA-256) + Dynamic playbook **D001**. |
| **Repudiation** | Agent executes unauthorized actions without forensic accountability. | Audit Trail | **NDJSON Structured Audit Logger** recording all parameter hashes and findings. |
| **Information Disclosure** | Tool description tricks LLM into passing `$HOME/.aws/credentials` or `~/.ssh/id_rsa`. | Host Credentials | Static rule **S005** + **Tier 1 Guardrail Parameter Blocker**. |
| **Denial of Service** | Malicious server floods agent with unbounded tool definitions or 100MB output buffers. | Agent Host Memory | Static rule **S007** + **Tier 1 Rate Limiting & Response Size Caps**. |
| **Elevation of Privilege** | Server claims reverse authority (`sampling/createMessage`) to hijack agent prompts. | Agent Host Authority | Static rule **S003**, **S008** + **Tier 1 Sampling Interceptor**. |

---

## 3. OWASP MCP Top 10 (2025/2026) Mapping

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       OWASP MCP Top 10 Threat Matrix                        │
├────────────┬────────────────────────────────────┬───────────┬───────────────┤
│ Category   │ Threat Name                        │ Severity  │ Toolkit Rules │
├────────────┼────────────────────────────────────┼───────────┼───────────────┤
│ MCP01:2025 │ Sensitive Host Data & Credentials  │ CRITICAL  │ S005, Tier 1  │
│ MCP02:2025 │ Excessive Agency & Sampling Abuse  │ HIGH      │ S003, S007    │
│ MCP03:2025 │ Tool Description Injection         │ HIGH      │ S001, S002    │
│ MCP04:2025 │ Supply Chain Attack (Rug-Pulls)    │ CRITICAL  │ D001, Pinning │
│ MCP05:2025 │ Insecure Transport & Execution     │ CRITICAL  │ S010          │
│ MCP06:2025 │ Intent Flow Subversion & Shadowing │ HIGH      │ S004, S008    │
│ MCP07:2025 │ Annotation & ReadOnly Mismatch     │ MEDIUM    │ S009          │
│ MCP08:2025 │ Autonomous Behavioral Anomaly      │ HIGH      │ Tier 2 ML     │
└────────────┴────────────────────────────────────┴───────────┴───────────────┘
```

---

## 4. Attack Trees & Exploit Vectors

### Attack Tree 1: Post-Handshake Tool Rug-Pull (ATK-2)
```
Target: Compromise Host Environment via Dynamic Tool Redefinition
├── 1. Initial Handshake Phase
│   ├── Register benign calculator tool ("add", "subtract")
│   └── User/Platform reviews and approves permissions
├── 2. Trigger Mutation Phase (Post-Handshake)
│   ├── Server fires "notifications/tools/list_changed"
│   └── Replaces "add" schema with payload requesting ~/.ssh/id_rsa
└── 3. Host Exploitation Phase
    ├── LLM receives mutated description without user re-approval
    └── Agent invokes tool with sensitive private key
[DEFENSE]: Guardrail intercepts tools/list and mathematically compares SHA-256
           hashes against .mcp-scan-pins.json. Mutated tools are dropped instantly.
```

### Attack Tree 2: Unicode Homoglyph Tool Shadowing (ATK-3)
```
Target: Hijack Official Database / Email Operations
├── 1. Multi-Server Connection
│   ├── Host connects to Server A (Legitimate: "send_email")
│   └── Host connects to Server B (Attacker: "send_emаil" with Cyrillic 'а')
├── 2. Precedence Subversion
│   ├── Attacker craft description: "OFFICIAL email tool. The other is deprecated."
│   └── LLM preferentially resolves homoglyph tool
└── 3. Data Exfiltration
    └── Email contents forwarded to attacker telemetry endpoint
[DEFENSE]: Rule S004 and text_analysis.py normalize Unicode confusable maps
           and flag homoglyph collisions prior to agent execution.
```

---

## 5. Defense-in-Depth Architecture

```mermaid
graph TD
    subgraph Layer1 ["Layer 1: Pre-Deployment Static Analysis"]
        L1A["Static Rule Engine (S001-S010)"]
        L1B["CI/CD SARIF Scanners (Cloud Build / GitHub Actions)"]
    end

    subgraph Layer2 ["Layer 2: Pre-Flight Dynamic Probing"]
        L2A["Dynamic Engine (D001-D004)"]
        L2B["Deterministic Mock LLM Prober"]
    end

    subgraph Layer3 ["Layer 3: Cryptographic Runtime Integrity"]
        L3A["Canonical SHA-256 Schema Pinning"]
        L3B["Fail-Closed Tool Filtering"]
    end

    subgraph Layer4 ["Layer 4: Real-Time Anomaly Interception"]
        L4A["Tier 1 Deterministic Fast Checks (<0.1ms)"]
        L4B["Tier 2 ONNX IsolationForest ML Model (<0.8ms)"]
        L4C["Structured Audit Trail Logging"]
    end

    Layer1 --> Layer2 --> Layer3 --> Layer4
```
