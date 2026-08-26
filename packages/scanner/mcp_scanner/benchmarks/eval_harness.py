"""Benchmark evaluation harness for computing Precision, Recall, F1, and FPR."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_scanner.static_engine import StaticAnalysisEngine
from mcp_security_common.mcp_types import ScanResult


@dataclass
class BenchmarkCase:
    case_id: str
    name: str
    category: str
    tools: list[dict[str, Any]]
    is_vulnerable: bool
    expected_rule_ids: list[str] = field(default_factory=list)
    capabilities: dict[str, Any] | None = None


@dataclass
class EvaluationMetrics:
    dataset_name: str
    total_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return round(self.true_positives / denom, 4) if denom > 0 else 1.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return round(self.true_positives / denom, 4) if denom > 0 else 1.0

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        return round(2 * (p * r) / (p + r), 4) if (p + r) > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return round(self.false_positives / denom, 4) if denom > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.total_samples
        correct = self.true_positives + self.true_negatives
        return round(correct / total, 4) if total > 0 else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_name": self.dataset_name,
            "total_samples": self.total_samples,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "false_positive_rate": self.false_positive_rate,
            "accuracy": self.accuracy,
        }


def evaluate_dataset(
    dataset_name: str,
    cases: list[BenchmarkCase],
    engine: StaticAnalysisEngine | None = None,
) -> tuple[EvaluationMetrics, list[dict[str, Any]]]:
    """Runs scanner on benchmark cases and computes evaluation metrics."""
    active_engine = engine or StaticAnalysisEngine()
    tp = fp = tn = fn = 0
    case_results: list[dict[str, Any]] = []

    for case in cases:
        scan_res: ScanResult = active_engine.scan_manifest_data(
            tools_data=case.tools,
            capabilities_data=case.capabilities,
        )

        detected_vulnerable = len(scan_res.findings) > 0
        detected_rule_ids = [f.rule_id for f in scan_res.findings]

        if case.is_vulnerable:
            if detected_vulnerable:
                tp += 1
                status = "TP"
            else:
                fn += 1
                status = "FN"
        else:
            if detected_vulnerable:
                fp += 1
                status = "FP"
            else:
                tn += 1
                status = "TN"

        case_results.append(
            {
                "case_id": case.case_id,
                "name": case.name,
                "category": case.category,
                "ground_truth": "vulnerable" if case.is_vulnerable else "safe",
                "prediction": "vulnerable" if detected_vulnerable else "safe",
                "status": status,
                "risk_score": scan_res.risk_score,
                "detected_rules": detected_rule_ids,
            }
        )

    metrics = EvaluationMetrics(
        dataset_name=dataset_name,
        total_samples=len(cases),
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
    )
    return metrics, case_results
