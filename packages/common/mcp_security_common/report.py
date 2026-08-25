"""Multi-format report generation (JSON, SARIF 2.1.0, HTML) for MCP security audits."""

from __future__ import annotations

import json
from typing import Any, Dict

from jinja2 import Template

from mcp_security_common.mcp_types import FindingSeverity, ScanResult

SARIF_LEVEL_MAP = {
    FindingSeverity.CRITICAL: "error",
    FindingSeverity.HIGH: "error",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.LOW: "note",
    FindingSeverity.INFO: "note",
}


def generate_json_report(result: ScanResult, indent: int = 2) -> str:
    """Generates formatted JSON report string."""
    return json.dumps(result.to_dict(), indent=indent)


def generate_sarif_report(result: ScanResult) -> str:
    """Generates standard SARIF v2.1.0 JSON report."""
    sarif_rules = {}
    sarif_results = []

    for finding in result.findings:
        rule_id = finding.rule_id
        if rule_id not in sarif_rules:
            sarif_rules[rule_id] = {
                "id": rule_id,
                "name": finding.rule_name,
                "shortDescription": {"text": finding.rule_name},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": SARIF_LEVEL_MAP.get(finding.severity, "warning")
                },
                "help": {
                    "text": finding.remediation or "Review tool metadata and capabilities according to OWASP MCP guidelines."
                },
                "properties": {
                    "tags": [finding.category.value, finding.owasp_mcp or "MCP"]
                },
            }

        target_desc = f"Tool: {finding.target_tool}" if finding.target_tool else "Server Configuration"
        sarif_results.append({
            "ruleId": rule_id,
            "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
            "message": {
                "text": f"[{finding.severity.value}] {finding.description} Evidence: {finding.evidence or 'None'}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result.target_uri
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    },
                    "logicalLocations": [
                        {
                            "name": target_desc,
                            "kind": "tool" if finding.target_tool else "configuration"
                        }
                    ]
                }
            ],
            "properties": {
                "category": finding.category.value,
                "owasp_mcp": finding.owasp_mcp,
                "evidence": finding.evidence,
            }
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-scanner",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/mcp-security/mcp-security-toolkit",
                        "rules": list(sarif_rules.values()),
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": result.scan_timestamp,
                    }
                ]
            }
        ]
    }
    return json.dumps(sarif_doc, indent=2)


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Security Audit Report — {{ result.server_name }}</title>
  <style>
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --text-primary: #f0f6fc;
      --text-secondary: #8b949e;
      --border-color: #30363d;
      --accent-blue: #58a6ff;
      --accent-green: #3fb950;
      --accent-yellow: #d29922;
      --accent-orange: #db6d28;
      --accent-red: #f85149;
      --accent-purple: #bc8cff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 2rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }
    h1 { font-size: 1.8rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.6rem;
      font-size: 0.75rem;
      font-weight: 700;
      border-radius: 9999px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-critical { background: #ffebe9; color: #cf222e; border: 1px solid #ff8182; }
    .badge-high { background: #fff8c5; color: #9a6700; border: 1px solid #d4a72c; }
    .badge-medium { background: #dbedff; color: #0969da; border: 1px solid #54aeff; }
    .badge-low { background: #dafbe1; color: #1a7f37; border: 1px solid #4ac26b; }
    .dark .badge-critical { background: rgba(248,81,73,0.15); color: #f85149; border: 1px solid rgba(248,81,73,0.4); }
    .dark .badge-high { background: rgba(219,109,40,0.15); color: #db6d28; border: 1px solid rgba(219,109,40,0.4); }
    .dark .badge-medium { background: rgba(210,153,34,0.15); color: #d29922; border: 1px solid rgba(210,153,34,0.4); }
    .dark .badge-low { background: rgba(63,185,80,0.15); color: #3fb950; border: 1px solid rgba(63,185,80,0.4); }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1.2rem;
    }
    .stat-val { font-size: 2rem; font-weight: 700; color: var(--text-primary); }
    .stat-label { color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; }

    .card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .card-title { font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem; color: var(--accent-blue); }
    
    .finding-item {
      border-left: 4px solid var(--border-color);
      padding: 1rem 1.2rem;
      margin-bottom: 1rem;
      background: var(--bg-tertiary);
      border-radius: 0 6px 6px 0;
    }
    .finding-critical { border-left-color: var(--accent-red); }
    .finding-high { border-left-color: var(--accent-orange); }
    .finding-medium { border-left-color: var(--accent-yellow); }
    .finding-low { border-left-color: var(--accent-green); }

    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
    }
    .finding-title { font-weight: 600; font-size: 1.05rem; }
    .evidence-block {
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      padding: 0.6rem 0.8rem;
      border-radius: 4px;
      font-family: monospace;
      font-size: 0.85rem;
      margin: 0.5rem 0;
      word-break: break-all;
      color: #ff7b72;
    }
    .remediation-block {
      font-size: 0.9rem;
      color: var(--accent-green);
      margin-top: 0.5rem;
    }
    footer {
      text-align: center;
      color: var(--text-secondary);
      font-size: 0.85rem;
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border-color);
    }
  </style>
</head>
<body class="dark">
  <div class="container">
    <header>
      <div>
        <h1>🛡️ MCP Security Audit Report</h1>
        <p style="color: var(--text-secondary); margin-top: 0.3rem;">Target: <code>{{ result.target_uri }}</code></p>
      </div>
      <div>
        <span style="font-size: 0.85rem; color: var(--text-secondary);">Scanned at: {{ result.scan_timestamp }}</span>
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-val" style="color: {% if result.risk_score >= 3.0 %}var(--accent-red){% elif result.risk_score >= 2.0 %}var(--accent-yellow){% else %}var(--accent-green){% endif %}">
          {{ result.risk_score }}
        </div>
        <div class="stat-label">Composite Risk Score</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{{ result.findings|length }}</div>
        <div class="stat-label">Total Findings</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{{ result.summary_counts.CRITICAL + result.summary_counts.HIGH }}</div>
        <div class="stat-label">Critical & High Risks</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{{ result.tools_scanned|length }}</div>
        <div class="stat-label">Tools Audited</div>
      </div>
    </div>

    <div class="card">
      <h2 class="card-title">Security Findings ({{ result.findings|length }})</h2>
      {% if result.findings %}
        {% for f in result.findings %}
          <div class="finding-item finding-{{ f.severity.value.lower() }}">
            <div class="finding-header">
              <span class="finding-title">{{ f.rule_id }}: {{ f.rule_name }}</span>
              <div>
                <span class="badge badge-{{ f.severity.value.lower() }}">{{ f.severity.value }}</span>
                {% if f.owasp_mcp %}
                  <span class="badge badge-medium" style="margin-left: 0.3rem;">{{ f.owasp_mcp }}</span>
                {% endif %}
              </div>
            </div>
            <p style="font-size: 0.95rem; margin-bottom: 0.4rem;">{{ f.description }}</p>
            {% if f.target_tool %}
              <p style="font-size: 0.85rem; color: var(--text-secondary);">Target Tool: <code>{{ f.target_tool }}</code> ({{ f.target_field }})</p>
            {% endif %}
            {% if f.evidence %}
              <div class="evidence-block">Evidence: {{ f.evidence }}</div>
            {% endif %}
            {% if f.remediation %}
              <div class="remediation-block">💡 <strong>Remediation:</strong> {{ f.remediation }}</div>
            {% endif %}
          </div>
        {% endfor %}
      {% else %}
        <p style="color: var(--accent-green);">✅ No security violations or suspicious patterns detected.</p>
      {% endif %}
    </div>

    <div class="card">
      <h2 class="card-title">Audited Tools & Schema Hashes ({{ result.tools_scanned|length }})</h2>
      <table style="width: 100%; border-collapse: collapse; font-size: 0.9rem;">
        <thead>
          <tr style="text-align: left; border-bottom: 1px solid var(--border-color); color: var(--text-secondary);">
            <th style="padding: 0.5rem;">Tool Name</th>
            <th style="padding: 0.5rem;">Description Length</th>
            <th style="padding: 0.5rem;">SHA-256 Schema Hash</th>
          </tr>
        </thead>
        <tbody>
          {% for tool in result.tools_scanned %}
          <tr style="border-bottom: 1px solid var(--border-color);">
            <td style="padding: 0.5rem;"><code>{{ tool.name }}</code></td>
            <td style="padding: 0.5rem;">{{ tool.description|length }} chars</td>
            <td style="padding: 0.5rem; font-family: monospace; font-size: 0.8rem; color: var(--accent-purple);">
              {{ result.pins_recorded.get(tool.name, 'N/A') }}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>

    <footer>
      Generated by <strong>MCP Security Red-Team & Defense Toolkit</strong> · Protocol Spec 2025-03-26 · OWASP MCP Top 10 Aligned
    </footer>
  </div>
</body>
</html>
"""


def generate_html_report(result: ScanResult) -> str:
    """Generates standalone HTML report with dark mode theme."""
    template = Template(HTML_TEMPLATE)
    return template.render(result=result)
