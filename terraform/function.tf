# Note: google_cloudfunctions2_function is in beta/provider versions; adjust provider/provider features as needed.
resource "google_storage_bucket" "function_source" {
  name     = var.function_source_bucket
  location = var.region
  uniform_bucket_level_access = true
}

# Upload source manually to the bucket and set object path via var.source_object
resource "google_cloudfunctions2_function" "snapshot_deleter" {
  name        = "delete-old-snapshots"
  location    = var.region
  build_config {
    runtime = "python311"
    entry_point = "delete_old_snapshots"
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = var.source_object
      }
    }
    environment_variables = {
      DAYS_THRESHOLD = tostring(var.days_threshold)
      REPORT_BUCKET   = var.report_bucket
      ORG_ID          = var.org_id
    }
  }

  service_config {
    service_account_email = google_service_account.cf_sa.email
    # Set available memory and timeout as needed
    available_memory = "512M"
    timeout_seconds  = 540
  }
}
