# MCP Security Red-Team & Defense Toolkit — Deployment Guide

This guide covers deploying the **MCP Security Toolkit** locally with Docker Compose, in CI/CD pipelines, and on **Google Cloud Platform (GCP) Cloud Run** using Terraform.

---

## 1. Quick Start: Local Multi-Container Deployment

Run the complete 6-server vulnerable lab suite along with the Guardrail proxy locally in sandboxed Docker containers:

```bash
# 1. Clone repository
git clone https://github.com/example/mcp-security-toolkit.git
cd mcp-security-toolkit

# 2. Launch 6 sandboxed vulnerable lab servers
docker compose -f docker-compose.lab.yml up -d

# 3. Verify server endpoints
curl http://localhost:8001/health  # ATK-1 (Description Injection)
curl http://localhost:8002/health  # ATK-2 (Rug Pull)
curl http://localhost:8003/health  # ATK-3 (Tool Shadow)
curl http://localhost:8004/health  # ATK-4 (Cross-Server)
curl http://localhost:8005/health  # ATK-5 (Confused Deputy)
curl http://localhost:8006/health  # ATK-6 (Transport Abuse)

# 4. Run an automated audit scan
mcp-scan scan "http://localhost:8001/mcp" --format table
```

---

## 2. Google Cloud Platform (GCP) Deployment via Terraform

The toolkit is designed for **scale-to-zero serverless deployment on Google Cloud Run**, keeping idle monthly costs at **$0.00 – $2.50 / month**.

### A. Prerequisites
1. [Google Cloud SDK (`gcloud`)](https://cloud.google.com/sdk/docs/install)
2. [Terraform CLI (>= 1.5.0)](https://developer.hashicorp.com/terraform/install)
3. Docker or Cloud Build for container image builds.

### B. Google Cloud Authentication & OAuth Setup
Authenticate your local environment to GCP using Application Default Credentials:

```bash
# Step 1: Log in with your Google account via OAuth browser flow
gcloud auth login

# Step 2: Acquire application default credentials for Terraform
gcloud auth application-default login

# Step 3: Configure target project and enable required APIs
gcloud config set project YOUR_PROJECT_ID
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  monitoring.googleapis.com \
  logging.googleapis.com \
  cloudbuild.googleapis.com
```

### C. Build & Push Container Images
Build the hardened Scanner and Guardrail container images to Artifact Registry:

```bash
# Set variables
PROJECT_ID="YOUR_PROJECT_ID"
REGION="us-central1"
REPO="mcp-security-toolkit"

# Authenticate Docker to GCP Artifact Registry
gcloud auth configure-docker ${REGION}-docker.pkg.dev

# Build & Push Scanner Image
docker build -f Dockerfile.scanner -t ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/mcp-scanner:v1.0.0 .
docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/mcp-scanner:v1.0.0

# Build & Push Guardrail Image
docker build -f Dockerfile.guardrail -t ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/mcp-guardrail:v1.0.0 .
docker push ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/mcp-guardrail:v1.0.0
```

### D. Deploy with Terraform
```bash
cd infra/terraform

# Copy and edit example configuration
cp terraform.tfvars.example terraform.tfvars
# Update project_id, region, and container image URIs in terraform.tfvars

# Initialize Terraform
terraform init

# Review execution plan
terraform plan

# Apply infrastructure deployment
terraform apply -auto-approve
```

---

## 3. Guardrail Proxy Configuration & Security Modes

The Guardrail proxy accepts environment variables to configure its runtime protection:

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `DOWNSTREAM_MCP_URL` | `http://localhost:8000/mcp` | Target upstream MCP server URL to forward validated traffic to. |
| `PIN_FILE_PATH` | `.mcp-scan-pins.json` | Path to the cryptographic SHA-256 schema pin store. |
| `LEARN_MODE` | `false` | When `true`, automatically learns and records pins on first connection. When `false`, enforces strict fail-closed filtering. |
| `ANOMALY_THRESHOLD` | `0.0` | Threshold for Tier 2 ML IsolationForest score (negative = anomaly). |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `PORT` | `8080` | Port for ASGI web server. |

---

## 4. Cloud Monitoring & Alert Thresholds

Terraform automatically provisions Google Cloud Monitoring alert policies:
1. **High Latency Alert**: Triggers an email alert if Guardrail proxy p99 latency exceeds **50ms** over a 60-second window.
2. **Elevated 5xx Error Rate**: Triggers if 5xx responses exceed 5 requests in 60 seconds.
3. **Monthly Budget Guardrail**: Configurable billing alerts at **$2.50** (50%) and **$5.00** (100%).
