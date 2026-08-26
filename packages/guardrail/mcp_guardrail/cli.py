"""CLI entrypoint for MCP Runtime Guardrail (HTTP Proxy & Stdio Wrapper)."""

import asyncio
import os
import sys
from pathlib import Path
from typing import List

import typer
import uvicorn
from rich.console import Console

from mcp_guardrail.audit import AuditLogger
from mcp_guardrail.pin_store import SchemaPinStore
from mcp_guardrail.proxy import create_guardrail_app
from mcp_guardrail.stdio_wrapper import StdioGuardrailWrapper

app = typer.Typer(
    name="mcp-guardrail",
    help="MCP Runtime Guardrail & Transport Interceptor (HTTP Proxy & Stdio Wrapper)",
    add_completion=False,
)
console = Console(stderr=True)


@app.command(name="proxy")
def start_proxy(
    upstream_url: str = typer.Option("http://localhost:8001", "--upstream", "-u", help="Upstream MCP server URL"),
    port: int = typer.Option(8000, "--port", "-p", help="Proxy listen port"),
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Proxy bind host"),
    pin_file: Path | None = typer.Option(None, "--pin-file", help="Path to schema pins file"),
    audit_file: Path | None = typer.Option(None, "--audit-file", help="Path to audit log file"),
    enforce: bool = typer.Option(True, "--enforce/--audit-only", help="Block policy violations (vs audit-only warning)"),
):
    """Starts the MCP HTTP/SSE Runtime Guardrail Proxy."""
    starlette_app = create_guardrail_app(
        upstream_url=upstream_url,
        pin_file=str(pin_file) if pin_file else ".guardrail-pins.json",
        audit_file=str(audit_file) if audit_file else "guardrail_audit.ndjson",
        enforce_mode=enforce,
    )
    console.print(
        f"[bold green]🛡️ Starting MCP Runtime Guardrail Proxy[/bold green] on [cyan]{host}:{port}[/cyan] -> Upstream: [magenta]{upstream_url}[/magenta] (Enforce: {enforce})"
    )
    uvicorn.run(starlette_app, host=host, port=port)


@app.command(name="stdio-wrap")
def start_stdio_wrap(
    command: List[str] = typer.Argument(..., help="Target MCP server command to run over stdio, e.g. python server.py"),
    pin_file: Path | None = typer.Option(None, "--pin-file", "-p", help="Path to schema pins file"),
    audit_file: Path | None = typer.Option(None, "--audit-file", "-a", help="Path to audit log file"),
    enforce: bool = typer.Option(True, "--enforce/--audit-only", help="Block policy violations (vs audit-only warning)"),
):
    """Wraps a local stdio MCP server command with real-time guardrail interception."""
    pin_store = SchemaPinStore(pin_file_path=pin_file) if pin_file else SchemaPinStore()
    audit_logger = AuditLogger(log_file_path=audit_file) if audit_file else AuditLogger()

    wrapper = StdioGuardrailWrapper(
        command=command,
        pin_store=pin_store,
        audit_logger=audit_logger,
        enforce_mode=enforce,
    )

    console.print(
        f"[bold green]🛡️ Starting MCP Stdio Guardrail Wrapper[/bold green] for command: [cyan]{' '.join(command)}[/cyan] (Enforce: {enforce})"
    )

    try:
        asyncio.run(wrapper.run_stdio_bridge())
    except KeyboardInterrupt:
        console.print("\n[yellow]Stdio Guardrail shut down cleanly.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Stdio Guardrail error: {e}[/bold red]")
        sys.exit(1)


def main():
    app()


if __name__ == "__main__":
    main()
