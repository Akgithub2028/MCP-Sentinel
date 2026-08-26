"""Tests verifying infrastructure as code (Terraform) and production container definitions."""

from pathlib import Path


def test_terraform_files_exist_and_valid():
    repo_root = Path(__file__).parent.parent.parent.parent
    tf_dir = repo_root / "infra" / "terraform"

    required_tf_files = [
        "main.tf",
        "variables.tf",
        "cloud_run.tf",
        "artifact_registry.tf",
        "iam.tf",
        "monitoring.tf",
        "outputs.tf",
        "terraform.tfvars.example",
    ]

    for fname in required_tf_files:
        fpath = tf_dir / fname
        assert fpath.exists(), f"Missing required Terraform file: {fname}"
        content = fpath.read_text(encoding="utf-8")
        assert len(content.strip()) > 0, f"Terraform file {fname} is empty"


def test_dockerfiles_exist():
    repo_root = Path(__file__).parent.parent.parent.parent
    scanner_df = repo_root / "Dockerfile.scanner"
    guardrail_df = repo_root / "Dockerfile.guardrail"
    base_df = repo_root / "Dockerfile.base"

    assert scanner_df.exists()
    assert guardrail_df.exists()
    assert base_df.exists()

    scanner_content = scanner_df.read_text(encoding="utf-8")
    assert "mcp_scanner.api:create_app" in scanner_content
    assert "EXPOSE 8080" in scanner_content

    guardrail_content = guardrail_df.read_text(encoding="utf-8")
    assert "mcp_guardrail.proxy:create_proxy_app" in guardrail_content
    assert "EXPOSE 8080" in guardrail_content


def test_documentation_suite_exists():
    repo_root = Path(__file__).parent.parent.parent.parent
    docs_dir = repo_root / "docs"

    required_docs = [
        "architecture.md",
        "threat-model.md",
        "deployment-guide.md",
        "rule-contribution-guide.md",
    ]

    for doc in required_docs:
        doc_path = docs_dir / doc
        assert doc_path.exists(), f"Missing required documentation: {doc}"
        assert len(doc_path.read_text(encoding="utf-8").strip()) > 200
