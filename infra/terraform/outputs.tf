# Outputs for MCP Security Infrastructure

output "scanner_service_uri" {
  description = "Public URL endpoint for the MCP Scanner REST API."
  value       = google_cloud_run_v2_service.scanner_service.uri
}

output "guardrail_service_uri" {
  description = "Public URL endpoint for the MCP Guardrail MITM Proxy."
  value       = google_cloud_run_v2_service.guardrail_service.uri
}

output "artifact_registry_repo" {
  description = "Docker repository ID in Artifact Registry."
  value       = google_artifact_registry_repository.mcp_repo.id
}

output "scanner_service_account" {
  description = "Email of the Scanner Service Account."
  value       = google_service_account.scanner_sa.email
}

output "guardrail_service_account" {
  description = "Email of the Guardrail Service Account."
  value       = google_service_account.guardrail_sa.email
}
