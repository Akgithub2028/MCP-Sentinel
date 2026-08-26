# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-26

### Added
- **Complete Vulnerable MCP Lab Suite (ATK-1 to ATK-6)** isolating major MCP vulnerability classes (Description Injection, Dynamic Rug-Pulls, Unicode Homoglyphs, Cross-Server Sampling, Confused Deputy, Insecure Transports).
- **Static & Dynamic Analysis Engines** in `mcp_scanner` supporting rules S001–S010 and playbooks D001–D004.
- **Runtime Guardrail ASGI Reverse Proxy** in `mcp_guardrail` with SHA-256 schema pin verification and parameter blockers.
- **Two-Tier Anomaly Engine** featuring 6 deterministic inspection rules and CPU-optimized ONNX IsolationForest ML model (<0.8ms latency).
- **Standardized Evaluation Harness** integrating MCPSecBench (17 categories) and MCPTox datasets.
- **Production REST API Server** (`mcp_scanner.api`) for containerized deployment on Google Cloud Run.
- **Interactive Security & Benchmark Dashboard** (`mcp_security_common.dashboard`).
- **Terraform Infrastructure as Code** (`infra/terraform/`) for automated Cloud Run, Artifact Registry, IAM, and Cloud Monitoring provisioning.
- **Comprehensive Documentation Suite** (`docs/architecture.md`, `docs/threat-model.md`, `docs/deployment-guide.md`, `docs/rule-contribution-guide.md`).
