"""Scoring, risk metric aggregation, and terminal table formatting."""

from __future__ import annotations

from typing import Dict, List

from mcp_security_common.mcp_types import Finding, FindingSeverity, ScanResult


def aggregate_and_deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicates findings while preserving highest severity and unique evidence."""
    seen: Dict[str, Finding] = {}
    for f in findings:
        key = f"{f.rule_id}:{f.target_tool or 'none'}:{f.target_field or 'none'}"
        if key not in seen:
            seen[key] = f
        else:
            # If higher severity or newer, update
            if f.severity.score > seen[key].severity.score:
                seen[key] = f
    return list(seen.values())


def format_cli_table(result: ScanResult) -> str:
    """Formats a rich terminal summary table of the scan result."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        import io

        console = Console(file=io.StringIO(), force_terminal=True)

        # Overview Table
        info_table = Table(title="MCP Security Audit Summary", show_header=False, border_style="blue")
        info_table.add_column("Field", style="cyan", width=20)
        info_table.add_column("Value", style="white")

        info_table.add_row("Target URI", result.target_uri)
        info_table.add_row("Server Name", f"{result.server_name} (v{result.server_version})")
        info_table.add_row("Protocol Version", result.protocol_version)
        info_table.add_row("Tools Audited", str(len(result.tools_scanned)))
        info_table.add_row("Total Findings", str(len(result.findings)))

        score_color = "red" if result.risk_score >= 3.0 else ("yellow" if result.risk_score >= 2.0 else "green")
        info_table.add_row("Risk Score", f"[{score_color}]{result.risk_score:.2f}[/{score_color}]")
        info_table.add_row("Scan Duration", f"{result.scan_duration_ms:.1f} ms")

        console.print(info_table)

        # Findings Table
        if result.findings:
            findings_table = Table(title="Detected Security Findings", border_style="red")
            findings_table.add_column("Rule ID", style="bold yellow", width=12)
            findings_table.add_column("Severity", width=10)
            findings_table.add_column("Target Tool", style="cyan", width=16)
            findings_table.add_column("Finding Summary", style="white")

            for f in result.findings:
                sev_color = {
                    FindingSeverity.CRITICAL: "bold red",
                    FindingSeverity.HIGH: "red",
                    FindingSeverity.MEDIUM: "yellow",
                    FindingSeverity.LOW: "green",
                    FindingSeverity.INFO: "blue",
                }.get(f.severity, "white")

                findings_table.add_row(
                    f.rule_id,
                    f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                    f.target_tool or "Global",
                    f"{f.description}\n[dim]Evidence: {f.evidence or 'None'}[/dim]"
                )
            console.print(findings_table)
        else:
            console.print(Panel("[bold green]✅ No security vulnerabilities detected on this MCP server.[/bold green]"))

        return console.file.getvalue()

    except Exception:
        # Plain text fallback
        lines = [
            "=" * 70,
            f" MCP Security Audit Summary: {result.server_name}",
            "=" * 70,
            f" Target: {result.target_uri}",
            f" Tools Audited: {len(result.tools_scanned)}",
            f" Total Findings: {len(result.findings)}",
            f" Composite Risk Score: {result.risk_score:.2f}",
            "-" * 70,
        ]
        for f in result.findings:
            lines.append(f" [{f.severity.value}] {f.rule_id}: {f.description}")
            if f.target_tool:
                lines.append(f"   Target: {f.target_tool} ({f.target_field})")
            if f.evidence:
                lines.append(f"   Evidence: {f.evidence}")
            lines.append("")
        return "\n".join(lines)
