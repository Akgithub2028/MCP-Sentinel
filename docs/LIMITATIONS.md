# MCP Security Architecture — Blueprint §14 Risks & Gap Resolutions

This document provides a comprehensive technical breakdown of the 7 risk and limitation categories outlined in §14 of the MCP Security Implementation Blueprint, detailing the defensive mitigations, architectural implementations, and operational guidelines implemented in this toolkit.

---

## Summary Matrix of Gap Resolutions

| Blueprint §14 Risk Category | Identified Limitation | Resolution & Implementation Status | Active Defense Engine |
|---|---|---|---|
| **G1: Semantic Injections** | Regex rules miss highly obfuscated or cross-tool multi-stage prompt injections. | **Resolved**: Integrated NVIDIA NIM LLM Semantic Judge using `deepseek-ai/deepseek-v4-flash-0731` for deep semantic schema evaluation and cross-tool split payload analysis. | `mcp_security_common.llm_judge` (`--llm-judge`) |
| **G2: Authenticated Servers** | Scanners cannot audit MCP servers behind OAuth 2.0 or token gateways. | **Resolved**: `AuthProvider` and `MCPAuthConfig` support Bearer tokens, environment injection, OAuth 2.0 client credentials grant with proactive token caching, and custom HTTP headers. | `mcp_scanner.auth` (`--auth-file`, `--auth-token`) |
| **G3: Stdio Subprocesses** | HTTP proxy cannot intercept local subprocess MCP servers communicating via `stdin`/`stdout`. | **Resolved**: `StdioGuardrailWrapper` acts as an in-line bidirectional stdio interceptor enforcing schema validation, Tier 1 anomaly checks, and audit logging. | `mcp_guardrail.stdio_wrapper` (`stdio-wrap`) |
| **G4: Tier 1 Rigidity** | Hardcoded rate limits and heuristic thresholds cause false positives in high-throughput workflows. | **Resolved**: Externalized configuration via `tier1_config.yaml` and expanded with 6 new runtime anomaly detectors. | `detection-rules/runtime/tier1_config.yaml` |
| **G5: Static Dashboard** | HTML dashboards only capture point-in-time scans without live runtime telemetry. | **Resolved**: Implemented `/ws/events` WebSocket streaming endpoint, `/api/stats` metrics API, and real-time auto-reconnecting Dark Mode Security Dashboard. | `mcp_security_common.dashboard`, `proxy.py` (`/dashboard`, `/ws/events`) |
| **G6: Spec Evolution** | MCP specification updates introduce new protocol methods, schema fields, or deprecations. | **Resolved**: `MCPSpecVersion` and `SpecCompatChecker` track protocol versions (`2024-11-05` through `2026-01-15`), selectively enabling rules per spec target. | `mcp_security_common.spec_compat` (`--spec-version`) |
| **G7: Dataset Stagnancy** | Fixed benchmark sizes limit evaluation generalization across emerging attack classes. | **Resolved**: Expanded MCPSecBench to 52 cases and MCPTox to 26 cases; added `ExternalBenchmarkLoader` for loading community JSON benchmarks. | `mcp_scanner.benchmarks.external_loader` (`--external-dataset`) |

---

## Detailed Gap Analysis & Technical Architectures

### 1. Gap G1: LLM-Based Semantic Analysis
- **Problem**: Natural language tool descriptions can encode attacks using Base64, hex encoding, homoglyphs, multiple languages, or split instructions across separate tool definitions that evade single-rule regex patterns.
- **Solution**:
  - `LLMSemanticJudge` dispatches tool manifests to NVIDIA NIM's `deepseek-ai/deepseek-v4-flash-0731` endpoint.
  - The model performs zero-shot reasoning on the holistic tool catalog to detect cross-tool data harvesting, confused deputy setups, and stealthy prompt injections.
  - Results are parsed into structured `Finding` objects and merged into the scanner's aggregated risk score.

### 2. Gap G2: Dynamic Auth & OAuth 2.0 Pass-Through
- **Problem**: Enterprise MCP endpoints require authentication headers (OAuth2 tokens, API keys) which caused connection drops during dynamic testing.
- **Solution**:
  - `AuthProvider` reads YAML configuration or CLI parameters.
  - Automatically fetches and refreshes OAuth 2.0 bearer tokens using client credentials grant.
  - Injects authorization headers on both SSE initialization and JSON-RPC HTTP requests.

### 3. Gap G3: Stdio Subprocess Guardrail
- **Problem**: Many IDEs (such as Claude Desktop, VS Code, Antigravity) launch MCP servers directly as child processes communicating over pipes (`stdin`/`stdout`), bypassing network proxies.
- **Solution**:
  - `StdioGuardrailWrapper` wraps any command line (e.g. `npx -y @modelcontextprotocol/server-postgres`) as a child process.
  - Intercepts and parses every line of JSON-RPC communication on `stdin` and `stdout`.
  - Blocks forbidden tool calls or poisoned outputs before delivering them to the parent application.

### 4. Gap G4: Configurable Runtime Tier 1 Detection
- **Problem**: Fixed thresholds for call rates (e.g., 30 calls/minute) or response sizes (1MB) caused false alarms in bulk data extraction workflows.
- **Solution**:
  - Thresholds are defined in `detection-rules/runtime/tier1_config.yaml`.
  - Added 6 specialized anomaly detection rules:
    1. `T1-RECURSIVE-TOOL-CALL`: Infinite loop mitigation.
    2. `T1-CROSS-TOOL-DATA-LEAK`: Prevents passing output from sensitive tools into untrusted external tools.
    3. `T1-SCHEMA-MUTATION-RUNTIME`: Blocks mid-session parameter definition modifications.
    4. `T1-UNUSUAL-PARAM-INJECTION`: Detects shell command injection payloads in arguments.
    5. `T1-SAMPLING-PROMPT-INJECTION`: Detects prompt poisoning in sampling messages.
    6. `T1-BINARY-PAYLOAD`: Flags unexpected binary or large Base64 blobs.

### 5. Gap G5: Real-Time WebSocket Streaming Dashboard
- **Problem**: Security engineers had to regenerate static HTML reports manually to observe proxy activity.
- **Solution**:
  - `AuditLogger` implements a Pub/Sub subscriber queue.
  - The guardrail proxy exposes `/ws/events` and `/api/stats`.
  - The dashboard frontend streams events live with auto-reconnection, real-time KPI metrics, threat distribution bar gauges, and search filtering.

### 6. Gap G6: MCP Specification Evolution Tracking
- **Problem**: As MCP standardizes from early drafts (`2024-11-05`) to current production (`2025-03-26`, `2025-06-15`, `2026-01-15`), security rules must respect protocol compatibility.
- **Solution**:
  - Rules define `spec_versions: ["2024-11-05", "2025-03-26", ...]`.
  - The scanner filters rules based on the detected or user-specified protocol version.

### 7. Gap G7: Benchmark Extensibility & Community Datasets
- **Problem**: Static benchmark datasets cannot evaluate novel attack vectors discovered in the wild.
- **Solution**:
  - Standardized benchmark JSON format defined in `docs/benchmark-format.md`.
  - `ExternalBenchmarkLoader` validates and loads custom test datasets via `mcp-scan benchmark -e <path>`.

---

## 3. V1 Scope Boundaries & Future Roadmap

The core toolkit fulfills the 3 Blueprint Milestones and resolves all 7 identified gaps. The following capabilities are planned for upcoming releases:

1. **MCP Registry Batch Scanner**: Automated crawler and batch-auditing utility to index, clone, and security-scan public MCP server registries in bulk.
2. **VS Code & Cursor IDE Extension**: Native extension providing one-click MCP security audits, inline vulnerability highlighting, and proxy configuration directly inside developer IDEs.
3. **Formal Empirical Benchmarking Paper**: Comprehensive academic preprint compiling empirical evaluation data from the 78 test cases across MCPSecBench and MCPTox.
4. **Live GCP Cloud Run Production Deployment**: Production execution of the verified Terraform modules and Artifact Registry pipelines under live GCP project credentials.

