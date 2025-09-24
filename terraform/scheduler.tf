resource "google_cloud_scheduler_job" "invoke_snapshot_deleter" {
  name        = "snapshot-deleter-job"
  schedule    = var.schedule_cron
  time_zone   = var.time_zone

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.snapshot_deleter.service_config[0].uri

    oidc_token {
      service_account_email = google_service_account.scheduler_sa.email
      audience              = google_cloudfunctions2_function.snapshot_deleter.service_config[0].uri
    }
  }
}
