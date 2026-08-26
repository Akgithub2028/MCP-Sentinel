# Contributing to MCP Security Red-Team & Defense Toolkit

Thank you for your interest in contributing to the MCP Security Toolkit!

## Development Setup

```bash
# 1. Clone repository
git clone https://github.com/example/mcp-security-toolkit.git
cd mcp-security-toolkit

# 2. Set up virtual environment
python -m venv .venv
source .venv/bin/activate

# 3. Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

## Quality Standards

Before submitting a Pull Request, ensure:
1. **Tests Pass**: `pytest --cov` passes with >95% coverage.
2. **Linting & Formatting**: `ruff check .` and `ruff format --check .` pass.
3. **No Flaky Tests**: All test runs are deterministic.

## Reporting Bugs & Security Issues

- For general bugs and feature requests, open a [GitHub Issue](https://github.com/example/mcp-security-toolkit/issues).
- For security vulnerabilities, please refer to our [Security Policy](SECURITY.md).
