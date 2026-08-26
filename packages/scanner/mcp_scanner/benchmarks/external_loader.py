"""External Benchmark Dataset Loader for community and third-party benchmark evaluations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from mcp_scanner.benchmarks.eval_harness import BenchmarkCase


class BenchmarkValidationError(Exception):
    pass


class ExternalBenchmarkLoader:
    """Loads and validates benchmark test suites from JSON or YAML files and directories."""

    REQUIRED_FIELDS = {"case_id", "name", "category", "tools", "is_vulnerable"}

    @classmethod
    def validate_case_dict(cls, data: dict[str, Any]) -> tuple[bool, list[str]]:
        """Validates that a dictionary conforms to the BenchmarkCase schema."""
        errors: list[str] = []
        missing = cls.REQUIRED_FIELDS - set(data.keys())
        if missing:
            errors.append(f"Missing required fields: {', '.join(sorted(missing))}")

        if "tools" in data and not isinstance(data["tools"], list):
            errors.append("'tools' field must be a list of tool objects")

        if "is_vulnerable" in data and not isinstance(data["is_vulnerable"], bool):
            errors.append("'is_vulnerable' field must be a boolean")

        return len(errors) == 0, errors

    @classmethod
    def parse_case(cls, data: dict[str, Any]) -> BenchmarkCase:
        """Parses a dictionary into a validated BenchmarkCase instance."""
        is_valid, errors = cls.validate_case_dict(data)
        if not is_valid:
            case_id = data.get("case_id", "UNKNOWN")
            raise BenchmarkValidationError(f"Invalid benchmark case '{case_id}': {'; '.join(errors)}")

        return BenchmarkCase(
            case_id=str(data["case_id"]),
            name=str(data["name"]),
            category=str(data["category"]),
            tools=list(data["tools"]),
            is_vulnerable=bool(data["is_vulnerable"]),
            expected_rule_ids=list(data.get("expected_rule_ids", [])),
            capabilities=data.get("capabilities"),
        )

    @classmethod
    def load_from_file(cls, file_path: Path | str) -> list[BenchmarkCase]:
        """Loads benchmark cases from a JSON or YAML file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Benchmark file not found: {path}")

        cases: list[BenchmarkCase] = []
        content = path.read_text(encoding="utf-8")

        if path.suffix.lower() == ".json":
            raw_data = json.loads(content)
        else:
            raw_data = yaml.safe_load(content)

        if isinstance(raw_data, dict):
            # Could be a single case or a container with a "cases" list
            if "cases" in raw_data and isinstance(raw_data["cases"], list):
                raw_list = raw_data["cases"]
            else:
                raw_list = [raw_data]
        elif isinstance(raw_data, list):
            raw_list = raw_data
        else:
            raise BenchmarkValidationError(f"Unexpected benchmark data structure in {path}")

        for item in raw_list:
            if isinstance(item, dict):
                cases.append(cls.parse_case(item))

        return cases

    @classmethod
    def load_from_directory(cls, dir_path: Path | str) -> list[BenchmarkCase]:
        """Loads all benchmark cases from .json and .yaml files in a directory recursively."""
        path = Path(dir_path)
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"Benchmark directory not found: {path}")

        cases: list[BenchmarkCase] = []
        for f in sorted(path.glob("**/*.json")) + sorted(path.glob("**/*.yaml")) + sorted(path.glob("**/*.yml")):
            if f.name.startswith((".", "_")):
                continue
            try:
                loaded = cls.load_from_file(f)
                cases.extend(loaded)
            except Exception as e:
                # Log or skip invalid files while continuing to load others
                continue

        return cases
