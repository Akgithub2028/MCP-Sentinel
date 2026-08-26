"""CLI entry point for the MCP Security Scanner."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mcp_scanner.benchmarks.eval_harness import evaluate_dataset
from mcp_scanner.benchmarks.external_loader import ExternalBenchmarkLoader
from mcp_scanner.benchmarks.mcpsecbench_eval import run_mcpsecbench_evaluation
from mcp_scanner.benchmarks.mcptox_eval import run_mcptox_evaluation
from mcp_scanner.dynamic_engine import DynamicAnalysisEngine
from mcp_scanner.scoring import aggregate_and_deduplicate_findings, format_cli_table
from mcp_scanner.static_engine import StaticAnalysisEngine
from mcp_security_common.mcp_types import ScanResult
from mcp_security_common.report import (
    generate_html_report,
    generate_json_report,
    generate_sarif_report,
)
from mcp_security_common.rules_engine import load_rules

app = typer.Typer(
    name="mcp-scan",
    help="MCP Security Red-Team Scanner — Automated security auditor for Model Context Protocol servers.",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(
        ..., help="Target MCP server endpoint (e.g. 'http://localhost:8001' or stdio command 'python server.py')"
    ),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, sarif, html"),
    output_file: Path | None = typer.Option(None, "--output", "-o", help="Optional output file path to write results"),
    pin_file: Path | None = typer.Option(
        None, "--pin-file", "-p", help="Path to baseline pin file for rug-pull detection"
    ),
    rules_dir: Path | None = typer.Option(None, "--rules-dir", "-r", help="Path to custom detection rules directory"),
    dynamic: bool = typer.Option(True, "--dynamic/--static-only", help="Enable dynamic multi-turn probing playbooks"),
    spec_version: str | None = typer.Option(
        None, "--spec-version", help="Target MCP spec version filter: 2025-03-26, 2025-11-05, 2026-07"
    ),
    auth_file: Path | None = typer.Option(None, "--auth-file", help="Path to YAML/JSON auth config file"),
    auth_token: str | None = typer.Option(None, "--auth-token", help="Inline bearer token for authenticated scans"),
    auth_token_env: str | None = typer.Option(None, "--auth-token-env", help="Env var name containing bearer token"),
    llm_judge: bool = typer.Option(False, "--llm-judge/--no-llm-judge", help="Enable NVIDIA NIM / DeepSeek LLM semantic judge"),
    llm_api_key: str | None = typer.Option(None, "--llm-api-key", help="API key for LLM judge (defaults to NVIDIA_API_KEY)"),
    llm_model: str = typer.Option("deepseek-ai/deepseek-v4-flash-0731", "--llm-model", help="Model name for LLM judge"),
    llm_base_url: str = typer.Option("https://integrate.api.nvidia.com/v1", "--llm-base-url", help="Base URL for LLM judge API"),
):
    """Audits an MCP server against OWASP MCP Top 10 security rules."""
    from mcp_scanner.auth import MCPAuthConfig
    from mcp_security_common.llm_judge import LLMSemanticJudge, LLMSemanticJudgeConfig

    # Resolve authentication configuration
    auth_config = MCPAuthConfig(auth_type="none")
    if auth_file and auth_file.exists():
        auth_config = MCPAuthConfig.from_file(auth_file)
    elif auth_token:
        auth_config = MCPAuthConfig(auth_type="bearer", bearer_token=auth_token)
    elif auth_token_env:
        auth_config = MCPAuthConfig(auth_type="bearer", bearer_token_env_var=auth_token_env)
    else:
        auth_config = MCPAuthConfig.from_env()

    # Resolve LLM semantic judge configuration
    resolved_api_key = llm_api_key or os.environ.get("NVIDIA_API_KEY") or os.environ.get("OPENAI_API_KEY")
    judge_enabled = llm_judge or (resolved_api_key is not None and llm_judge)
    judge_config = LLMSemanticJudgeConfig(
        enabled=judge_enabled,
        api_key=resolved_api_key,
        model=llm_model,
        base_url=llm_base_url,
    )
    judge = LLMSemanticJudge(judge_config) if judge_enabled else None

    pinned_hashes = {}
    if pin_file and pin_file.exists():
        try:
            with open(pin_file, encoding="utf-8") as f:
                pin_data = json.load(f)
                pinned_hashes = pin_data.get("pins", pin_data)
        except Exception as e:
            console.print(f"[bold red]Failed to load pin file: {e}[/bold red]")

    static_engine = StaticAnalysisEngine(
        rules_dir=rules_dir,
        spec_version=spec_version,
        llm_judge=judge,
    )
    dynamic_engine = DynamicAnalysisEngine() if dynamic else None

    async def _run_scan() -> ScanResult:
        result = await static_engine.scan_target(target, pinned_hashes=pinned_hashes, auth_config=auth_config)
        if dynamic_engine:
            from mcp_scanner.connection import create_connection

            conn = await create_connection(
                target,
                protocol_version=spec_version or "2025-03-26",
                auth_config=auth_config,
            )
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
    output_file: Path = typer.Option(
        Path(".mcp-scan-pins.json"), "--output", "-o", help="Output file to write pins to"
    ),
    rules_dir: Path | None = typer.Option(None, "--rules-dir", "-r", help="Optional rules directory"),
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

    console.print(
        f"[bold green]✅ Recorded {len(result.pins_recorded)} tool schema pins into {output_file}[/bold green]"
    )
    for tool_name, hash_val in result.pins_recorded.items():
        console.print(f"  - [cyan]{tool_name}[/cyan]: [magenta]{hash_val[:16]}...[/magenta]")


@app.command(name="list-rules")
def list_rules(
    rules_dir: Path | None = typer.Option(None, "--rules-dir", "-r", help="Path to rules directory"),
    spec_version: str | None = typer.Option(None, "--spec-version", help="Filter by target MCP spec version"),
):
    """Lists all loaded static and dynamic security audit rules."""
    default_dir = Path(__file__).parent.parent.parent.parent / "detection-rules" / "static"
    active_dir = rules_dir or default_dir
    rules = load_rules(active_dir, spec_version=spec_version)

    table = Table(title=f"Loaded MCP Security Rules ({len(rules)})", border_style="blue")
    table.add_column("Rule ID", style="bold yellow", width=10)
    table.add_column("Rule Name", style="white")
    table.add_column("Severity", style="cyan", width=12)
    table.add_column("OWASP Category", style="magenta", width=15)

    for r in rules:
        table.add_row(r.id, r.name, r.severity.value, r.owasp_mcp or "MCP")

    console.print(table)


@app.command(name="benchmark")
def benchmark(
    suite: str = typer.Option("all", "--suite", "-s", help="Benchmark suite: all, mcpsecbench, mcptox"),
    external_dataset: Path | None = typer.Option(
        None, "--external-dataset", "-e", help="Path to external benchmark JSON/YAML file or directory"
    ),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
):
    """Executes automated benchmark evaluation suites against known attack datasets."""
    results = []

    if suite in ("all", "mcpsecbench"):
        with console.status("[bold green]Running MCPSecBench evaluation...[/bold green]"):
            metrics, cases = run_mcpsecbench_evaluation()
            results.append(metrics)

    if suite in ("all", "mcptox"):
        with console.status("[bold green]Running MCPTox evaluation...[/bold green]"):
            metrics, cases = run_mcptox_evaluation()
            results.append(metrics)

    if external_dataset:
        with console.status(f"[bold green]Running external benchmark from {external_dataset}...[/bold green]"):
            if external_dataset.is_dir():
                ext_cases = ExternalBenchmarkLoader.load_from_directory(external_dataset)
            else:
                ext_cases = ExternalBenchmarkLoader.load_from_file(external_dataset)
            ext_metrics, ext_case_results = evaluate_dataset(
                f"External ({external_dataset.name})", ext_cases
            )
            results.append(ext_metrics)

    if output_format.lower() == "json":
        data = [m.to_dict() for m in results]
        print(json.dumps(data, indent=2))
    else:
        table = Table(title="📊 MCP Security Benchmark Evaluation Results", border_style="green")
        table.add_column("Benchmark Dataset", style="bold cyan", width=35)
        table.add_column("Samples", width=10)
        table.add_column("Recall (TPR)", style="bold green", width=14)
        table.add_column("Precision", style="bold yellow", width=12)
        table.add_column("F1 Score", style="bold white", width=12)
        table.add_column("FPR", style="bold magenta", width=10)
        table.add_column("Accuracy", width=10)

        for m in results:
            table.add_row(
                m.dataset_name,
                str(m.total_samples),
                f"{m.recall * 100:.1f}%",
                f"{m.precision * 100:.1f}%",
                f"{m.f1_score:.3f}",
                f"{m.false_positive_rate * 100:.1f}%",
                f"{m.accuracy * 100:.1f}%",
            )
        console.print(table)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host address to bind the API server to"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind the API server to"),
):
    """Starts the MCP Scanner Production REST API server."""
    import uvicorn

    from mcp_scanner.api import create_app

    console.print(f"[bold green]🚀 Starting MCP Scanner REST API on http://{host}:{port}...[/bold green]")
    uvicorn.run(create_app(), host=host, port=port, log_level="info")


@app.command()
def dashboard(
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output path for the HTML dashboard file (e.g. dashboard.html)"
    ),
    serve_http: bool = typer.Option(False, "--serve", "-s", help="Serve dashboard via local HTTP server"),
    port: int = typer.Option(8888, "--port", "-p", help="Port for local HTTP dashboard server"),
    live: bool = typer.Option(False, "--live", "-l", help="Configure dashboard for live WebSocket streaming"),
    ws_url: str | None = typer.Option(
        None, "--ws-url", help="Custom WebSocket streaming endpoint URL (e.g. ws://localhost:8000/ws/events)"
    ),
):
    """Generates the interactive MCP Security & Benchmark Metrics Dashboard."""
    from mcp_security_common.dashboard import generate_html_dashboard

    target_path = output or Path("metrics_dashboard.html")
    with console.status("[bold green]Generating interactive security dashboard...[/bold green]"):
        html_out = generate_html_dashboard(output_path=target_path, ws_endpoint=ws_url)

    console.print(
        f"[bold green]✅ Interactive Metrics Dashboard generated at:[/bold green] [cyan]{target_path.resolve()}[/cyan]"
    )
    if live or ws_url:
        console.print(
            f"[bold magenta]⚡ Live WebSocket streaming enabled targeting:[/bold magenta] [yellow]{ws_url or 'ws://localhost:8000/ws/events'}[/yellow]"
        )

    if serve_http or live:
        import http.server
        import socketserver

        console.print(
            f"[bold cyan]🌐 Serving dashboard at http://localhost:{port}... Press Ctrl+C to stop.[/bold cyan]"
        )

        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(html_out.encode("utf-8"))

        with socketserver.TCPServer(("", port), Handler) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                console.print("\n[yellow]Dashboard server stopped.[/yellow]")


def main():
    app()


if __name__ == "__main__":
    main()
