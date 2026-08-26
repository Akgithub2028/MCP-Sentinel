# Cloud Monitoring Dashboard and Alert Policies

# 1. Notification Channel for Security & Infra Alerts
resource "google_monitoring_notification_channel" "email_alerts" {
  display_name = "MCP Security Email Notification Channel"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

# 2. Alert Policy: Guardrail Proxy High Latency (p99 > 50ms)
resource "google_monitoring_alert_policy" "guardrail_high_latency" {
  display_name = "MCP Guardrail High Latency (>50ms p99)"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Run Request Latency > 50ms"
    condition_threshold {
      filter          = "resource.type = \"cloud_run_revision\" AND metric.type = \"run.googleapis.com/request_latencies\" AND resource.labels.service_name = \"${google_cloud_run_v2_service.guardrail_service.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50  # milliseconds
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_PERCENTILE_99"
        cross_series_reducer = "REDUCE_PERCENTILE_99"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.name]
}

# 3. Alert Policy: Elevated 5xx Error Rate (>1%)
resource "google_monitoring_alert_policy" "high_error_rate" {
  display_name = "MCP Service High Error Rate (>1%)"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Run 5xx Errors"
    condition_threshold {
      filter          = "resource.type = \"cloud_run_revision\" AND metric.type = \"run.googleapis.com/request_count\" AND metric.labels.response_code_class = \"5xx\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_alerts.name]
}
