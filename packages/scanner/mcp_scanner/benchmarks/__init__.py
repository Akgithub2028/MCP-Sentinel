"""Benchmark evaluation suites for MCP Scanner."""

from mcp_scanner.benchmarks.eval_harness import BenchmarkCase, EvaluationMetrics, evaluate_dataset
from mcp_scanner.benchmarks.mcpsecbench_eval import get_mcpsecbench_cases, run_mcpsecbench_evaluation
from mcp_scanner.benchmarks.mcptox_eval import get_mcptox_cases, run_mcptox_evaluation

__all__ = [
    "BenchmarkCase",
    "EvaluationMetrics",
    "evaluate_dataset",
    "get_mcpsecbench_cases",
    "get_mcptox_cases",
    "run_mcpsecbench_evaluation",
    "run_mcptox_evaluation",
]
