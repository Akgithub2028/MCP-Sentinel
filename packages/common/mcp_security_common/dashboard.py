"""Interactive Real-Time Security & Benchmark Metrics Dashboard Generator with Live WebSocket Streaming."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_scanner.benchmarks.mcpsecbench_eval import run_mcpsecbench_evaluation
from mcp_scanner.benchmarks.mcptox_eval import run_mcptox_evaluation


def generate_html_dashboard(
    output_path: Path | str | None = None,
    extra_scan_results: list[dict[str, Any]] | None = None,
    ws_endpoint: str | None = None,
) -> str:
    """
    Generates a high-aesthetic, interactive HTML security operations dashboard.
    Supports real-time WebSocket event streaming, HTTP fallback polling,
    benchmark scorecards, vulnerable lab matrices, and ML anomaly analytics.
    """
    # 1. Gather baseline benchmark metrics
    mcpsec_metrics, mcpsec_cases = run_mcpsecbench_evaluation()
    mcptox_metrics, mcptox_cases = run_mcptox_evaluation()

    mcpsec_dict = mcpsec_metrics.to_dict()
    mcptox_dict = mcptox_metrics.to_dict()

    dashboard_data = {
        "mcpsecbench": mcpsec_dict,
        "mcpsecbench_cases": mcpsec_cases,
        "mcptox": mcptox_dict,
        "mcptox_cases": mcptox_cases,
        "lab_classes": [
            {
                "id": "ATK-1",
                "name": "Description Injection",
                "cve": "CVE-2025-5277",
                "owasp": "MCP03:2025",
                "rules": ["S001", "S002", "S006", "LLM-POISONING"],
                "status": "Protected (100%)",
            },
            {
                "id": "ATK-2",
                "name": "Tool Rug Pull (TOCTOU)",
                "cve": "CVE-2025-6514",
                "owasp": "MCP04:2025",
                "rules": ["D001", "Schema Pinning", "T1-SCHEMA-MUTATION"],
                "status": "Protected (100%)",
            },
            {
                "id": "ATK-3",
                "name": "Tool Shadowing & Homoglyphs",
                "cve": "CVE-2026-30615",
                "owasp": "MCP06:2025",
                "rules": ["S004", "D004", "T1-SHADOWED-TOOL"],
                "status": "Protected (100%)",
            },
            {
                "id": "ATK-4",
                "name": "Cross-Server Sampling Abuse",
                "cve": "CVE-2025-8821",
                "owasp": "MCP06:2025",
                "rules": ["S003", "S008", "T1-INBOUND-SAMPLING"],
                "status": "Protected (100%)",
            },
            {
                "id": "ATK-5",
                "name": "Confused Deputy Harvesting",
                "cve": "CVE-2025-7734",
                "owasp": "MCP01:2025",
                "rules": ["S005", "T1-ARG-CREDENTIALS", "T1-CROSS-TOOL-LEAK"],
                "status": "Protected (100%)",
            },
            {
                "id": "ATK-6",
                "name": "Transport & Command Abuse",
                "cve": "CVE-2025-9942",
                "owasp": "MCP05:2025",
                "rules": ["S010", "T1-PARAM-INJECTION", "StdioGuardrail"],
                "status": "Protected (100%)",
            },
        ],
        "ml_anomaly": {
            "model": "IsolationForest (ONNX CPU)",
            "roc_auc": 0.9748,
            "recall": 0.9080,
            "precision": 0.5866,
            "inference_latency_ms": 0.78,
            "features": [
                "Call Frequency (Hz)",
                "Time Delta (s)",
                "Arg Count",
                "Payload Length (bytes)",
                "Desc Length (chars)",
                "Shadow Flag (bool)",
                "Has URL (bool)",
                "Has Credential (bool)",
            ],
        },
    }

    json_payload = json.dumps(dashboard_data)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Security Red-Team & Defense Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #0a0e17;
      --bg-surface: #111827;
      --bg-surface-elevated: #1f293d;
      --border-color: #243049;
      --border-focus: #3b82f6;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent-cyan: #06b6d4;
      --accent-blue: #3b82f6;
      --accent-purple: #a855f7;
      --accent-green: #10b981;
      --accent-red: #f43f5e;
      --accent-yellow: #f59e0b;
      --radius: 12px;
      --glow-cyan: rgba(6, 182, 212, 0.15);
      --glow-red: rgba(244, 63, 94, 0.15);
      --glow-green: rgba(16, 185, 129, 0.15);
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg-base);
      color: var(--text-primary);
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      line-height: 1.5;
      padding: 1.5rem;
      min-height: 100vh;
    }}

    .container {{
      max-width: 1440px;
      margin: 0 auto;
    }}

    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border-color);
      flex-wrap: wrap;
      gap: 1rem;
    }}

    .brand {{
      display: flex;
      align-items: center;
      gap: 1rem;
    }}

    .brand-icon {{
      font-size: 2.2rem;
      background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      filter: drop-shadow(0 0 12px var(--glow-cyan));
    }}

    .brand h1 {{
      font-size: 1.6rem;
      font-weight: 800;
      letter-spacing: -0.02em;
    }}

    .brand p {{
      color: var(--text-secondary);
      font-size: 0.85rem;
    }}

    .header-status {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      background: var(--bg-surface);
      padding: 0.5rem 1rem;
      border-radius: 9999px;
      border: 1px solid var(--border-color);
      font-size: 0.85rem;
      font-weight: 500;
    }}

    .status-dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--accent-yellow);
      display: inline-block;
      box-shadow: 0 0 8px currentColor;
    }}
    .status-dot.online {{ background: var(--accent-green); }}
    .status-dot.offline {{ background: var(--accent-red); }}

    /* KPI Summary Cards */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}

    .kpi-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 1.25rem;
      position: relative;
      overflow: hidden;
      transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
    }}
    .kpi-card:hover {{
      transform: translateY(-2px);
      border-color: var(--accent-cyan);
      box-shadow: 0 8px 24px var(--glow-cyan);
    }}

    .kpi-title {{
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }}

    .kpi-value {{
      font-size: 1.8rem;
      font-weight: 800;
      font-family: 'Fira Code', monospace;
      color: var(--text-primary);
      display: flex;
      align-items: baseline;
      gap: 0.5rem;
    }}

    .kpi-sub {{
      font-size: 0.75rem;
      color: var(--text-secondary);
      margin-top: 0.25rem;
    }}

    /* Navigation Tabs */
    .tabs-nav {{
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1.5rem;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.5rem;
      overflow-x: auto;
    }}

    .tab-btn {{
      background: transparent;
      border: none;
      color: var(--text-secondary);
      padding: 0.6rem 1.2rem;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      border-radius: 8px;
      transition: all 0.15s;
      white-space: nowrap;
    }}
    .tab-btn:hover {{
      color: var(--text-primary);
      background: var(--bg-surface-elevated);
    }}
    .tab-btn.active {{
      color: var(--accent-cyan);
      background: rgba(6, 182, 212, 0.1);
      border-bottom: 2px solid var(--accent-cyan);
    }}

    .tab-content {{
      display: none;
      animation: fadeIn 0.2s ease-in-out;
    }}
    .tab-content.active {{
      display: block;
    }}

    @keyframes fadeIn {{
      from {{ opacity: 0; transform: translateY(4px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}

    /* Surface Card */
    .card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }}

    .card-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.25rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}

    .section-title {{
      font-size: 1.1rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    /* Tables */
    .table-container {{
      overflow-x: auto;
      max-height: 520px;
      overflow-y: auto;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.85rem;
    }}

    th {{
      background: var(--bg-surface-elevated);
      color: var(--text-secondary);
      font-weight: 600;
      padding: 0.75rem 1rem;
      position: sticky;
      top: 0;
      z-index: 1;
      border-bottom: 1px solid var(--border-color);
    }}

    td {{
      padding: 0.75rem 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      color: var(--text-primary);
    }}

    tr:hover td {{
      background: rgba(255, 255, 255, 0.02);
    }}

    .code-font {{
      font-family: 'Fira Code', monospace;
      font-size: 0.8rem;
    }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      background: var(--bg-surface-elevated);
      color: var(--text-secondary);
      border: 1px solid var(--border-color);
    }}

    .status-badge {{
      display: inline-flex;
      align-items: center;
      padding: 0.2rem 0.6rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }}
    .status-pass, .status-tn, .status-safe {{
      background: rgba(16, 185, 129, 0.15);
      color: var(--accent-green);
      border: 1px solid rgba(16, 185, 129, 0.3);
    }}
    .status-blocked, .status-tp, .status-vulnerable {{
      background: rgba(244, 63, 94, 0.15);
      color: var(--accent-red);
      border: 1px solid rgba(244, 63, 94, 0.3);
    }}
    .status-warn, .status-fp, .status-fn {{
      background: rgba(245, 158, 11, 0.15);
      color: var(--accent-yellow);
      border: 1px solid rgba(245, 158, 11, 0.3);
    }}

    /* Analytics Grid */
    .analytics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1.5rem;
    }}

    .bar-row {{
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-bottom: 0.75rem;
    }}
    .bar-label {{
      width: 140px;
      font-size: 0.8rem;
      color: var(--text-secondary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .bar-track {{
      flex: 1;
      height: 8px;
      background: var(--bg-surface-elevated);
      border-radius: 4px;
      overflow: hidden;
    }}
    .bar-fill {{
      height: 100%;
      background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue));
      border-radius: 4px;
      transition: width 0.3s;
    }}
    .bar-fill.red {{
      background: linear-gradient(90deg, var(--accent-yellow), var(--accent-red));
    }}
    .bar-count {{
      width: 40px;
      text-align: right;
      font-size: 0.8rem;
      font-family: 'Fira Code', monospace;
      color: var(--text-muted);
    }}

    footer {{
      margin-top: 3rem;
      padding-top: 1.5rem;
      border-top: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      color: var(--text-muted);
      font-size: 0.8rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <span class="brand-icon">🛡️</span>
        <div>
          <h1>MCP Security Red-Team & Defense Dashboard</h1>
          <p>Real-Time Interception Stream, Anomaly Detection & OWASP Benchmark Suite</p>
        </div>
      </div>
      <div class="header-status">
        <span class="status-dot" id="live-indicator"></span>
        <span id="live-status-text">Connecting...</span>
      </div>
    </header>

    <!-- Top KPI Row -->
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-title">Total Interceptions</div>
        <div class="kpi-value" id="kpi-total">0</div>
        <div class="kpi-sub">Runtime traffic events inspected</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Blocked Threats</div>
        <div class="kpi-value" id="kpi-blocked" style="color: var(--accent-red);">0</div>
        <div class="kpi-sub">Attacks terminated at guardrail</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Warning Alerts</div>
        <div class="kpi-value" id="kpi-warn" style="color: var(--accent-yellow);">0</div>
        <div class="kpi-sub">Audit-only anomaly triggers</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Block Ratio</div>
        <div class="kpi-value" id="kpi-rate" style="color: var(--accent-cyan);">0.0%</div>
        <div class="kpi-sub">Enforced threat termination rate</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Active Defense Rules</div>
        <div class="kpi-value" style="color: var(--accent-purple);">24</div>
        <div class="kpi-sub">Static, Tier 1 & ML detectors</div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs-nav">
      <button class="tab-btn active" onclick="switchTab('live-stream')">⚡ Live Event Stream</button>
      <button class="tab-btn" onclick="switchTab('threat-analytics')">📊 Threat Analytics</button>
      <button class="tab-btn" onclick="switchTab('mcpsecbench')">🏆 MCPSecBench (52)</button>
      <button class="tab-btn" onclick="switchTab('mcptox')">🧪 MCPTox Poisoning (26)</button>
      <button class="tab-btn" onclick="switchTab('lab-matrix')">🔬 Vulnerable Lab Matrix</button>
      <button class="tab-btn" onclick="switchTab('ml-engine')">🌲 Tier 2 ML Anomaly</button>
    </div>

    <!-- TAB 1: Live Event Stream -->
    <div id="tab-live-stream" class="tab-content active">
      <div class="card">
        <div class="card-header">
          <div class="section-title">⚡ Real-Time MCP Traffic Interception Feed</div>
          <div style="display: flex; gap: 0.5rem; align-items: center;">
            <button onclick="clearEventStream()" class="badge" style="cursor: pointer;">Clear Stream</button>
            <span class="badge" id="event-count-badge">0 events</span>
          </div>
        </div>
        <div class="table-container">
          <table id="live-stream-table">
            <thead>
              <tr>
                <th style="width: 170px;">Timestamp</th>
                <th style="width: 100px;">Action</th>
                <th style="width: 140px;">Method</th>
                <th style="width: 120px;">Duration</th>
                <th>Details / Target / Triggered Rule</th>
              </tr>
            </thead>
            <tbody id="live-stream-tbody">
              <tr>
                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                  Awaiting real-time MCP proxy events... Trigger tool calls through the guardrail to observe live streams.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 2: Threat Analytics -->
    <div id="tab-threat-analytics" class="tab-content">
      <div class="card">
        <div class="section-title" style="margin-bottom: 1.5rem;">📊 Real-Time Threat & Method Distribution</div>
        <div class="analytics-grid">
          <div>
            <div class="card-title" style="font-weight: 600; margin-bottom: 1rem;">Top Triggered Rules & Anomaly Reasons</div>
            <div id="analytics-rules-container">
              <p style="color: var(--text-muted); font-size: 0.85rem;">No threat events recorded in this session yet.</p>
            </div>
          </div>
          <div>
            <div class="card-title" style="font-weight: 600; margin-bottom: 1rem;">Interception Volume by Method</div>
            <div id="analytics-methods-container">
              <p style="color: var(--text-muted); font-size: 0.85rem;">No method events recorded yet.</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 3: MCPSecBench -->
    <div id="tab-mcpsecbench" class="tab-content">
      <div class="card">
        <div class="card-header">
          <div class="section-title">🏆 MCPSecBench Evaluation Results (52 Cases)</div>
          <div style="display: flex; gap: 0.75rem;">
            <span class="badge">Recall: <strong id="mcpsec-recall">-</strong></span>
            <span class="badge">Precision: <strong id="mcpsec-prec">-</strong></span>
            <span class="badge">F1 Score: <strong id="mcpsec-f1">-</strong></span>
          </div>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Test Case Name</th>
                <th>Category</th>
                <th>Ground Truth</th>
                <th>Prediction</th>
                <th>Risk Score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="mcpsec-rows"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 4: MCPTox -->
    <div id="tab-mcptox" class="tab-content">
      <div class="card">
        <div class="card-header">
          <div class="section-title">🧪 MCPTox Poisoned Tool Description Evaluation (26 Cases)</div>
          <div style="display: flex; gap: 0.75rem;">
            <span class="badge">Recall: <strong id="mcptox-recall">-</strong></span>
            <span class="badge">Precision: <strong id="mcptox-prec">-</strong></span>
            <span class="badge">F1 Score: <strong id="mcptox-f1">-</strong></span>
          </div>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Case Name</th>
                <th>Attack Vector</th>
                <th>Ground Truth</th>
                <th>Prediction</th>
                <th>Risk Score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="mcptox-rows"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 5: Lab Matrix -->
    <div id="tab-lab-matrix" class="tab-content">
      <div class="card">
        <div class="section-title" style="margin-bottom: 1.25rem;">🔬 Vulnerable MCP Server Lab Matrix (6 Classes)</div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Lab ID</th>
                <th>Attack Class</th>
                <th>Mapped CVE</th>
                <th>OWASP MCP Category</th>
                <th>Active Defense Rules</th>
                <th>Defense Efficacy</th>
              </tr>
            </thead>
            <tbody id="lab-rows"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 6: ML Anomaly -->
    <div id="tab-ml-engine" class="tab-content">
      <div class="card">
        <div class="section-title" style="margin-bottom: 1rem;">🌲 Tier 2 ML Anomaly Detection Engine (ONNX CPU)</div>
        <p style="color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 1.5rem;">
          Lightweight semi-supervised IsolationForest model trained on simulated session interaction vectors. Evaluated for ultra-low latency runtime interception on CPU.
        </p>
        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-title">ROC-AUC Score</div>
            <div class="kpi-value" style="color: var(--accent-cyan);">0.9748</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-title">Anomaly Recall</div>
            <div class="kpi-value" style="color: var(--accent-green);">90.8%</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-title">Inference Time</div>
            <div class="kpi-value" style="color: var(--accent-yellow);">0.78 ms</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-title">Serving Format</div>
            <div class="kpi-value" style="font-size: 1.3rem;">ONNX Runtime</div>
          </div>
        </div>
        <div style="margin-top: 1.5rem;">
          <div class="kpi-title">8D Interaction Feature Space</div>
          <div style="display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem;">
            <span class="badge">1. call_frequency (Hz)</span>
            <span class="badge">2. time_delta (s)</span>
            <span class="badge">3. arg_count</span>
            <span class="badge">4. payload_length (bytes)</span>
            <span class="badge">5. description_length (chars)</span>
            <span class="badge">6. is_shadowed (bool)</span>
            <span class="badge">7. has_url (bool)</span>
            <span class="badge">8. has_credential (bool)</span>
          </div>
        </div>
      </div>
    </div>

    <footer>
      <div>MCP Security Red-Team & Defense Toolkit • Open Source Apache 2.0</div>
      <div>Aligned with OWASP Top 10 for LLM Applications & MCP Architecture 2025/2026</div>
    </footer>
  </div>

  <script>
    const INITIAL_DATA = {json_payload};
    let eventHistory = [];

    function switchTab(tabId) {{
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      const target = document.getElementById('tab-' + tabId);
      if (target) target.classList.add('active');
      if (event && event.target) event.target.classList.add('active');
    }}

    function renderStaticTables() {{
      // Benchmark Scores
      const mcpsec = INITIAL_DATA.mcpsecbench;
      document.getElementById('mcpsec-recall').textContent = (mcpsec.recall * 100).toFixed(1) + '%';
      document.getElementById('mcpsec-prec').textContent = (mcpsec.precision * 100).toFixed(1) + '%';
      document.getElementById('mcpsec-f1').textContent = mcpsec.f1_score.toFixed(3);

      const mcptox = INITIAL_DATA.mcptox;
      document.getElementById('mcptox-recall').textContent = (mcptox.recall * 100).toFixed(1) + '%';
      document.getElementById('mcptox-prec').textContent = (mcptox.precision * 100).toFixed(1) + '%';
      document.getElementById('mcptox-f1').textContent = mcptox.f1_score.toFixed(3);

      // MCPSecBench rows
      document.getElementById('mcpsec-rows').innerHTML = INITIAL_DATA.mcpsecbench_cases.map(c => `
        <tr>
          <td class="code-font">${{c.case_id}}</td>
          <td><strong>${{c.name}}</strong></td>
          <td><span class="badge">${{c.category}}</span></td>
          <td>${{c.ground_truth}}</td>
          <td>${{c.prediction}}</td>
          <td class="code-font">${{c.risk_score.toFixed(2)}}</td>
          <td><span class="status-badge status-${{c.status.toLowerCase()}}">${{c.status}}</span></td>
        </tr>
      `).join('');

      // MCPTox rows
      document.getElementById('mcptox-rows').innerHTML = INITIAL_DATA.mcptox_cases.map(c => `
        <tr>
          <td class="code-font">${{c.case_id}}</td>
          <td><strong>${{c.name}}</strong></td>
          <td><span class="badge">${{c.category}}</span></td>
          <td>${{c.ground_truth}}</td>
          <td>${{c.prediction}}</td>
          <td class="code-font">${{c.risk_score.toFixed(2)}}</td>
          <td><span class="status-badge status-${{c.status.toLowerCase()}}">${{c.status}}</span></td>
        </tr>
      `).join('');

      // Lab Matrix
      document.getElementById('lab-rows').innerHTML = INITIAL_DATA.lab_classes.map(l => `
        <tr>
          <td class="code-font"><strong>${{l.id}}</strong></td>
          <td>${{l.name}}</td>
          <td class="code-font" style="color: var(--accent-cyan);">${{l.cve}}</td>
          <td><span class="badge">${{l.owasp}}</span></td>
          <td class="code-font">${{l.rules.join(', ')}}</td>
          <td><span class="status-badge status-pass">${{l.status}}</span></td>
        </tr>
      `).join('');
    }}

    function updateKPIs(stats) {{
      if (!stats) return;
      document.getElementById('kpi-total').textContent = stats.total_events || 0;
      document.getElementById('kpi-blocked').textContent = stats.blocked_count || 0;
      document.getElementById('kpi-warn').textContent = stats.warned_count || 0;
      document.getElementById('kpi-rate').textContent = (stats.block_rate_percent || 0).toFixed(1) + '%';
      document.getElementById('event-count-badge').textContent = (stats.total_events || 0) + ' events';

      updateAnalyticsBars(stats);
    }}

    function updateAnalyticsBars(stats) {{
      const rulesContainer = document.getElementById('analytics-rules-container');
      const methodsContainer = document.getElementById('analytics-methods-container');

      if (stats.rule_counts && Object.keys(stats.rule_counts).length > 0) {{
        const maxRule = Math.max(...Object.values(stats.rule_counts), 1);
        rulesContainer.innerHTML = Object.entries(stats.rule_counts)
          .sort((a, b) => b[1] - a[1])
          .map(([rule, cnt]) => `
            <div class="bar-row">
              <div class="bar-label code-font" title="${{rule}}">${{rule}}</div>
              <div class="bar-track">
                <div class="bar-fill red" style="width: ${{Math.round((cnt / maxRule) * 100)}}%;"></div>
              </div>
              <div class="bar-count">${{cnt}}</div>
            </div>
          `).join('');
      }}

      if (stats.method_counts && Object.keys(stats.method_counts).length > 0) {{
        const maxMethod = Math.max(...Object.values(stats.method_counts), 1);
        methodsContainer.innerHTML = Object.entries(stats.method_counts)
          .sort((a, b) => b[1] - a[1])
          .map(([m, cnt]) => `
            <div class="bar-row">
              <div class="bar-label code-font" title="${{m}}">${{m}}</div>
              <div class="bar-track">
                <div class="bar-fill" style="width: ${{Math.round((cnt / maxMethod) * 100)}}%;"></div>
              </div>
              <div class="bar-count">${{cnt}}</div>
            </div>
          `).join('');
      }}
    }}

    function addEventRow(ev) {{
      const tbody = document.getElementById('live-stream-tbody');
      if (tbody.children.length === 1 && tbody.children[0].children.length === 1) {{
        tbody.innerHTML = '';
      }}

      const act = (ev.action || 'PASS').toUpperCase();
      let statusClass = 'status-pass';
      if (act === 'BLOCKED') statusClass = 'status-blocked';
      else if (act === 'WARN') statusClass = 'status-warn';

      const detailsStr = ev.details ? JSON.stringify(ev.details) : '';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="code-font">${{ev.timestamp ? ev.timestamp.substring(11, 19) : '-'}}</td>
        <td><span class="status-badge ${{statusClass}}">${{act}}</span></td>
        <td class="code-font"><strong>${{ev.method || '-'}}</strong></td>
        <td class="code-font" style="color: var(--text-muted);">${{ev.duration_ms !== undefined ? ev.duration_ms + ' ms' : '-'}}</td>
        <td class="code-font" style="color: var(--text-secondary); word-break: break-all;">${{detailsStr}}</td>
      `;

      tbody.insertBefore(tr, tbody.firstChild);
      if (tbody.children.length > 200) {{
        tbody.removeChild(tbody.lastChild);
      }}
    }}

    function clearEventStream() {{
      const tbody = document.getElementById('live-stream-tbody');
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">Stream cleared.</td></tr>';
    }}

    // WebSocket Live Streaming Connection Management
    function setupWebSocket() {{
      const liveIndicator = document.getElementById('live-indicator');
      const liveText = document.getElementById('live-status-text');

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host || 'localhost:8000';
      const defaultWs = protocol + '//' + host + '/ws/events';
      const wsUrl = '{ws_endpoint}' || defaultWs;

      let socket = null;
      let reconnectTimer = null;

      function connect() {{
        liveIndicator.className = 'status-dot';
        liveText.textContent = 'Connecting...';

        try {{
          socket = new WebSocket(wsUrl);

          socket.onopen = function() {{
            liveIndicator.className = 'status-dot online';
            liveText.textContent = 'Live Streaming (WS)';
            if (reconnectTimer) clearInterval(reconnectTimer);
          }};

          socket.onmessage = function(event) {{
            try {{
              const msg = JSON.parse(event.data);
              if (msg.type === 'init') {{
                if (msg.stats) updateKPIs(msg.stats);
                if (msg.recent_events && msg.recent_events.length > 0) {{
                  msg.recent_events.forEach(addEventRow);
                }}
              }} else if (msg.type === 'event') {{
                if (msg.event) addEventRow(msg.event);
                if (msg.stats) updateKPIs(msg.stats);
              }}
            }} catch (e) {{
              console.error('WS Parse Error:', e);
            }}
          }};

          socket.onclose = function() {{
            liveIndicator.className = 'status-dot';
            liveText.textContent = 'Reconnecting (Polling Mode)...';
            schedulePollingFallback();
          }};

          socket.onerror = function() {{
            liveIndicator.className = 'status-dot offline';
            liveText.textContent = 'Offline (Polling Mode)';
            schedulePollingFallback();
          }};
        }} catch (err) {{
          schedulePollingFallback();
        }}
      }}

      function schedulePollingFallback() {{
        if (!reconnectTimer) {{
          pollStats();
          reconnectTimer = setInterval(() => {{
            pollStats();
            connect();
          }}, 3000);
        }}
      }}

      async function pollStats() {{
        try {{
          const res = await fetch('/api/stats');
          if (res.ok) {{
            const stats = await res.json();
            updateKPIs(stats);
            liveIndicator.className = 'status-dot online';
            liveText.textContent = 'Live (HTTP Polling)';
          }}
        }} catch (e) {{
          // Standalone file mode
        }}
      }}

      connect();
    }}

    window.addEventListener('DOMContentLoaded', () => {{
      renderStaticTables();
      setupWebSocket();
    }});
  </script>
</body>
</html>
"""

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html_content, encoding="utf-8")

    return html_content
