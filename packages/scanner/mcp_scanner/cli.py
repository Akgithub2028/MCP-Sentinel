"""CLI entry point for the MCP Security Scanner."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from mcp_security_common.mcp_types import ScanResult
from mcp_security_common.report import (
    generate_html_report,
    generate_json_report,
    generate_sarif_report,
)
from mcp_security_common.rules_engine import load_rules
from mcp_scanner.dynamic_engine import DynamicAnalysisEngine
from mcp_scanner.scoring import aggregate_and_deduplicate_findings, format_cli_table
from mcp_scanner.static_engine import StaticAnalysisEngine

app = typer.Typer(
    name="mcp-scan",
    help="MCP Security Red-Team Scanner — Automated security auditor for Model Context Protocol servers.",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target MCP server endpoint (e.g. 'http://localhost:8001' or stdio command 'python server.py')"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, sarif, html"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Optional output file path to write results"),
    pin_file: Optional[Path] = typer.Option(None, "--pin-file", "-p", help="Path to baseline pin file for rug-pull detection"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", "-r", help="Path to custom detection rules directory"),
    dynamic: bool = typer.Option(True, "--dynamic/--static-only", help="Enable dynamic multi-turn probing playbooks"),
):
    """Audits an MCP server against OWASP MCP Top 10 security rules."""
    pinned_hashes = {}
    if pin_file and pin_file.exists():
        try:
            with open(pin_file, "r", encoding="utf-8") as f:
                pin_data = json.load(f)
                pinned_hashes = pin_data.get("pins", pin_data)
        except Exception as e:
            console.print(f"[bold red]Failed to load pin file: {e}[/bold red]")

    static_engine = StaticAnalysisEngine(rules_dir=rules_dir)
    dynamic_engine = DynamicAnalysisEngine() if dynamic else None

    async def _run_scan() -> ScanResult:
        result = await static_engine.scan_target(target, pinned_hashes=pinned_hashes)
        if dynamic_engine:
            from mcp_scanner.connection import create_connection
            conn = await create_connection(target)
            try:
                await conn.initialize()
                dyn_findings = await dynamic_engine.run_playbook_d001_rug_pull(conn)
                side_effects = await dynamic_engine.run_playbook_d003_tool_side_effects(conn, result.tools_scanned)
                result.findings.extend(dyn_findings)
                result.findings.extend(side_effects)
            finally:
                await conn.close()

        result.findings = aggregate_and_deduplicate_findings(result.findings)
        return result

    try:
        with console.status("[bold green]Running MCP security scan...[/bold green]"):
            result = asyncio.run(_run_scan())
    except Exception as e:
        console.print(f"[bold red]Scan failed to execute on '{target}': {e}[/bold red]")
        raise typer.Exit(code=1)

    # Format output
    if output_format.lower() == "json":
        rendered = generate_json_report(result)
    elif output_format.lower() == "sarif":
        rendered = generate_sarif_report(result)
    elif output_format.lower() == "html":
        rendered = generate_html_report(result)
    else:
        rendered = format_cli_table(result)

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(rendered)
        console.print(f"[bold green]Report successfully written to {output_file}[/bold green]")
    else:
        if output_format.lower() == "table":
            print(rendered)
        else:
            print(rendered)

    if result.risk_score >= 3.0:
        raise typer.Exit(code=2)
    elif result.risk_score > 0.0:
        raise typer.Exit(code=1)


@app.command()
def pin(
    target: str = typer.Argument(..., help="Target MCP server to establish baseline pins for"),
    output_file: Path = typer.Option(Path(".mcp-scan-pins.json"), "--output", "-o", help="Output file to write pins to"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", "-r", help="Optional rules directory"),
):
    """Establishes cryptographic SHA-256 schema pins for all tools on an MCP server."""
    static_engine = StaticAnalysisEngine(rules_dir=rules_dir)

    async def _run_pin():
        return await static_engine.scan_target(target)

    try:
        with console.status("[bold green]Querying server for tool schema pins...[/bold green]"):
            result = asyncio.run(_run_pin())
    except Exception as e:
        console.print(f"[bold red]Failed to query target: {e}[/bold red]")
        raise typer.Exit(code=1)

    pin_store = {
        "server_name": result.server_name,
        "target_uri": target,
        "pinned_at": result.scan_timestamp,
        "pins": result.pins_recorded,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(pin_store, f, indent=2)

    console.print(f"[bold green]✅ Recorded {len(result.pins_recorded)} tool schema pins into {output_file}[/bold green]")
    for tool_name, hash_val in result.pins_recorded.items():
        console.print(f"  - [cyan]{tool_name}[/cyan]: [magenta]{hash_val[:16]}...[/magenta]")


@app.command(name="list-rules")
def list_rules(
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", "-r", help="Path to rules directory"),
):
    """Lists all loaded static and dynamic security audit rules."""
    default_dir = Path(__file__).parent.parent.parent.parent / "detection-rules" / "static"
    active_dir = rules_dir or default_dir
    rules = load_rules(active_dir)

    from rich.table import Table
    table = Table(title=f"Loaded MCP Security Rules ({len(rules)})", border_style="blue")
    table.add_column("Rule ID", style="bold yellow", width=10)
    table.add_column("Rule Name", style="white")
    table.add_column("Severity", style="cyan", width=12)
    table.add_column("OWASP Category", style="magenta", width=15)

    for r in rules:
        table.add_row(r.id, r.name, r.severity.value, r.owasp_mcp or "MCP")

    console.print(table)


def main():
    app()


if __name__ == "__main__":
    main()
