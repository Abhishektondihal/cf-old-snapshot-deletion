output "function_url" {
  value = google_cloudfunctions2_function.snapshot_deleter.service_config[0].uri
}

output "cf_sa_email" {
  value = google_service_account.cf_sa.email
}

output "scheduler_sa_email" {
  value = google_service_account.scheduler_sa.email
}
