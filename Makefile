.PHONY: help install test lint format scan-demo run-lab-atk1 run-lab-atk2 run-guardrail clean

PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest
RUFF ?= .venv/bin/ruff
MCP_SCAN ?= .venv/bin/mcp-scan
MCP_GUARDRAIL ?= .venv/bin/mcp-guardrail

help:
	@echo "MCP Security Red-Team & Defense Toolkit"
	@echo "======================================"
	@echo "make install       - Install virtual environment and editable monorepo packages"
	@echo "make test          - Run full pytest test suite (common, scanner, guardrail, lab)"
	@echo "make lint          - Check code style and formatting with ruff"
	@echo "make format        - Automatically format code with ruff"
	@echo "make scan-demo     - Run live scanner audit on ATK-1 vulnerable lab server"
	@echo "make run-lab-atk1  - Launch ATK-1 Description Injection server on port 8001"
	@echo "make run-lab-atk2  - Launch ATK-2 Rug-Pull server on port 8002"
	@echo "make run-guardrail - Launch runtime guardrail proxy on port 8000 -> upstream 8001"
	@echo "make clean         - Remove temporary test artifacts and cache"

install:
	uv venv --python 3.12 --clear .venv
	uv pip install --python $(PYTHON) -r packages/lab/servers/atk1_description_injection/requirements.txt
	uv pip install --python $(PYTHON) -e ./packages/common -e ./packages/scanner -e ./packages/guardrail

test:
	$(PYTEST) -v

lint:
	$(RUFF) check .

format:
	$(RUFF) format .

scan-demo:
	$(MCP_SCAN) scan "$(PYTHON) packages/lab/servers/atk1_description_injection/server.py --mode vulnerable" --format table

run-lab-atk1:
	$(PYTHON) packages/lab/servers/atk1_description_injection/server.py --transport http --port 8001 --mode vulnerable

run-lab-atk2:
	$(PYTHON) packages/lab/servers/atk2_rug_pull/server.py --transport http --port 8002 --mode vulnerable

run-guardrail:
	$(MCP_GUARDRAIL) --upstream http://localhost:8001 --port 8000 --enforce

clean:
	rm -rf .pytest_cache htmlcov .coverage scan_report.html .mcp-scan-pins.json guardrail_audit.ndjson
	find . -type d -name "__pycache__" -exec rm -rf {} +
