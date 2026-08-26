# Least-Privilege IAM Service Accounts for MCP Services

# 1. Scanner API Service Account
resource "google_service_account" "scanner_sa" {
  account_id   = "mcp-scanner-sa"
  display_name = "MCP Scanner Service Account"
  description  = "Dedicated service account for MCP Scanner Cloud Run instance"
}

resource "google_project_iam_member" "scanner_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.scanner_sa.email}"
}

resource "google_project_iam_member" "scanner_metrics" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.scanner_sa.email}"
}

# 2. Guardrail Proxy Service Account
resource "google_service_account" "guardrail_sa" {
  account_id   = "mcp-guardrail-sa"
  display_name = "MCP Guardrail Service Account"
  description  = "Dedicated service account for MCP Guardrail MITM Proxy Cloud Run instance"
}

resource "google_project_iam_member" "guardrail_logging" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.guardrail_sa.email}"
}

resource "google_project_iam_member" "guardrail_metrics" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.guardrail_sa.email}"
}
