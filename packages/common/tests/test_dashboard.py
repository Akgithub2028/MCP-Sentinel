"""Tests for Interactive Dashboard and Report generation."""

from mcp_security_common.dashboard import generate_html_dashboard


def test_dashboard_generation_and_content(tmp_path):
    out_file = tmp_path / "dashboard.html"
    html = generate_html_dashboard(output_path=out_file)

    assert out_file.exists()
    assert len(html) > 1000
    assert "MCPSecBench" in html
    assert "MCPTox" in html
    assert "ATK-1" in html
    assert "ATK-6" in html
    assert "IsolationForest" in html
    assert "0.9748" in html


def test_dashboard_generation_memory_only():
    html = generate_html_dashboard()
    assert "<!DOCTYPE html>" in html
    assert "MCP Security Red-Team & Defense Dashboard" in html
