variable "project_id" {
  type        = string
  description = "The Google Cloud Project ID to deploy resources into."
  default     = "mcp-security-prod"
}

variable "region" {
  type        = string
  description = "The GCP region for Cloud Run and Artifact Registry deployment."
  default     = "us-central1"
}

variable "environment" {
  type        = string
  description = "Deployment environment name (e.g. dev, staging, prod)."
  default     = "prod"
}

variable "scanner_image" {
  type        = string
  description = "Container image URI for MCP Scanner API."
  default     = "us-central1-docker.pkg.dev/mcp-security-prod/mcp-security-toolkit/mcp-scanner:v1.0.0"
}

variable "guardrail_image" {
  type        = string
  description = "Container image URI for MCP Guardrail Proxy."
  default     = "us-central1-docker.pkg.dev/mcp-security-prod/mcp-security-toolkit/mcp-guardrail:v1.0.0"
}

variable "alert_email" {
  type        = string
  description = "Email address for Cloud Monitoring latency, error, and budget alerts."
  default     = "security-alerts@example.com"
}
