# Service accounts and roles

resource "google_service_account" "cf_sa" {
  account_id   = "snapshot-deleter-cf-sa"
  display_name = "Snapshot Deleter Cloud Function SA"
}

resource "google_project_iam_member" "cf_sa_compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer" # For listing snapshots and disks
  member  = "serviceAccount:${google_service_account.cf_sa.email}"
}

resource "google_project_iam_member" "cf_sa_compute_delete" {
  project = var.project_id
  role    = "roles/compute.storageAdmin" # storageAdmin gives snapshot deletion; adjust if needed
  member  = "serviceAccount:${google_service_account.cf_sa.email}"
}

# Scheduler service account (used by Cloud Scheduler to call the function)
resource "google_service_account" "scheduler_sa" {
  account_id   = "snapshot-scheduler-sa"
  display_name = "Scheduler SA for snapshot deleter"
}

resource "google_project_iam_member" "scheduler_invoker_binding" {
  project = var.project_id
  role    = "roles/cloudfunctions.invoker"
  member  = "serviceAccount:${google_service_account.scheduler_sa.email}"
}

resource "google_project_iam_member" "scheduler_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.scheduler_sa.email}"
}
