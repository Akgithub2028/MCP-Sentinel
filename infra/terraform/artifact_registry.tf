# Artifact Registry Repository for Docker Container Images

resource "google_artifact_registry_repository" "mcp_repo" {
  location      = var.region
  repository_id = "mcp-security-toolkit"
  description   = "Docker container images for MCP Security Red-Team & Defense Toolkit"
  format        = "DOCKER"

  labels = {
    environment = var.environment
    managed_by  = "terraform"
    project     = "mcp-red-team"
  }
}
