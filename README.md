# Private Cloud Function: Delete Old GCP Snapshots (Scheduler + OIDC)

This package deploys a **Gen 2 Cloud Function** that deletes Compute Engine snapshots older than a threshold and uploads a report to GCS.
It is intended to be invoked **only** by **Cloud Scheduler** using **OIDC** (private invocation) — **not** publicly accessible.

## Files
- `main.py` - Cloud Function source (entry point: `delete_old_snapshots`)
- `requirements.txt` - Python dependencies
- `terraform/` - Terraform to create service account, GCS bucket, the function, and scheduler job
- `.gcloudignore` - exclude local files when deploying

## Deploy steps (gcloud)
1. Enable APIs:
```bash
gcloud services enable cloudfunctions.googleapis.com cloudbuild.googleapis.com compute.googleapis.com cloudresourcemanager.googleapis.com storage.googleapis.com cloudscheduler.googleapis.com
```

2. Create a GCS bucket for reports (if not using Terraform):
```bash
gsutil mb -l us-central1 gs://YOUR_REPORT_BUCKET
```

3. Deploy the function (no `--allow-unauthenticated`):
```bash
gcloud functions deploy delete-old-snapshots \
  --gen2 \
  --region=us-central1 \
  --runtime=python311 \
  --source=. \
  --entry-point=delete_old_snapshots \
  --trigger-http \
  --service-account=SNAPSHOT_CF_SA@YOUR_PROJECT.iam.gserviceaccount.com \
  --set-env-vars=DAYS_THRESHOLD=180,REPORT_BUCKET=YOUR_REPORT_BUCKET,ORG_ID=
```
Leave `ORG_ID` empty to scan all accessible projects, or set your org id to restrict.

4. Allow only Cloud Scheduler (or specific service account) to invoke the function:
```bash
gcloud functions add-iam-policy-binding delete-old-snapshots \
  --region=us-central1 \
  --member="serviceAccount:YOUR_SCHEDULER_SA@YOUR_PROJECT.iam.gserviceaccount.com" \
  --role="roles/cloudfunctions.invoker"
```

5. Create a Cloud Scheduler job that calls the function with OIDC authentication using `YOUR_SCHEDULER_SA`:
```bash
FUNCTION_URL=$(gcloud functions describe delete-old-snapshots --region=us-central1 --gen2 --format='value(serviceConfig.uri)')

gcloud scheduler jobs create http snapshot-cleanup-job \
  --schedule="0 3 * * *" \
  --uri="$FUNCTION_URL" \
  --http-method=POST \
  --oidc-service-account-email=YOUR_SCHEDULER_SA@YOUR_PROJECT.iam.gserviceaccount.com \
  --oidc-token-audience="$FUNCTION_URL"
```

## Terraform (included)
The `terraform/` folder includes an example that:
- Creates a service account for the Cloud Function
- Creates a service account for Cloud Scheduler to use when invoking
- Creates a GCS bucket for reports
- Deploys the Cloud Function (via `google_cloudfunctions2_function`)
- Creates a Cloud Scheduler job that invokes the function with OIDC

**Review and adjust IAM roles before applying in production.**

## Safety notes
- This script permanently deletes snapshots. Test in non-production first.
- Use least privilege for service accounts.
- Ensure monitoring/alerts for unintended deletions.
