import os
import tempfile
import json
from datetime import datetime, timezone, timedelta
from googleapiclient import discovery
from googleapiclient.errors import HttpError
import pandas as pd
from google.cloud import storage
from flask import Request, make_response

# Environment variables
DAYS_THRESHOLD = int(os.environ.get("DAYS_THRESHOLD", "1"))
REPORT_BUCKET = os.environ.get("REPORT_BUCKET")  # optional: GCS bucket to upload reports
ORG_ID = os.environ.get("ORG_ID")  # optional: restrict to org id

def get_client(service, version='v1'):
    return discovery.build(service, version, cache_discovery=False)

def list_projects():
    crm = get_client('cloudresourcemanager','v1')
    req = crm.projects().list()
    projects = []
    while req is not None:
        resp = req.execute()
        for p in resp.get('projects', []):
            if p.get('lifecycleState') != 'ACTIVE':
                continue
            if ORG_ID:
                parent = p.get('parent', {})
                if str(parent.get('id')) != str(ORG_ID):
                    continue
            projects.append({'projectId': p['projectId'], 'name': p.get('name')})
        req = crm.projects().list_next(prev_req=req, prev_resp=resp)
    return projects

def list_snapshots(project_id):
    compute = get_client('compute','v1')
    snaps = []
    req = compute.snapshots().list(project=project_id)
    while req is not None:
        resp = req.execute()
        snaps.extend(resp.get('items', []))
        req = compute.snapshots().list_next(prev_req=req, prev_resp=resp)
    return snaps

def delete_snapshot(project_id, snapshot_name):
    compute = get_client('compute','v1')
    return compute.snapshots().delete(project=project_id, snapshot=snapshot_name).execute()

def upload_to_bucket(local_path, bucket_name, dest_name):
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(dest_name)
    blob.upload_from_filename(local_path)
    return f"gs://{bucket_name}/{dest_name}"

def _run_deletion():
    cutoff = datetime.now(timezone.utc) - timedelta(days=DAYS_THRESHOLD)
    deleted = []
    projects = list_projects()
    total_considered = 0

    for p in projects:
        pid = p['projectId']
        snaps = list_snapshots(pid)
        total_considered += len(snaps)
        for s in snaps:
            ts = s.get('creationTimestamp')
            if not ts:
                continue
            try:
                created = datetime.fromisoformat(ts.replace('Z','+00:00'))
            except Exception:
                continue
            age = (datetime.now(timezone.utc) - created).days
            if age >= DAYS_THRESHOLD:
                name = s.get('name')
                try:
                    delete_snapshot(pid, name)
                    deleted.append({
                        'projectId': pid,
                        'projectName': p.get('name'),
                        'snapshotName': name,
                        'creationTimestamp': ts,
                        'age_days': age,
                        'status': s.get('status'),
                        'selfLink': s.get('selfLink')
                    })
                except HttpError as e:
                    deleted.append({
                        'projectId': pid,
                        'projectName': p.get('name'),
                        'snapshotName': name,
                        'creationTimestamp': ts,
                        'age_days': age,
                        'status': s.get('status'),
                        'selfLink': s.get('selfLink'),
                        'error': str(e)
                    })

    # write reports
    tmpdir = tempfile.mkdtemp()
    xlsx_path = os.path.join(tmpdir, "deleted_snapshots_report.xlsx")
    csv_path = os.path.join(tmpdir, "deleted_snapshots_report.csv")

    if deleted:
        df = pd.DataFrame(deleted)
        df.to_excel(xlsx_path, index=False)
        df.to_csv(csv_path, index=False)
    else:
        df = pd.DataFrame(columns=['projectId','projectName','snapshotName','creationTimestamp','age_days','status','selfLink','error'])
        df.to_excel(xlsx_path, index=False)
        df.to_csv(csv_path, index=False)

    uploaded = {}
    if REPORT_BUCKET:
        try:
            uploaded['xlsx'] = upload_to_bucket(xlsx_path, REPORT_BUCKET, "deleted_snapshots_report.xlsx")
            uploaded['csv'] = upload_to_bucket(csv_path, REPORT_BUCKET, "deleted_snapshots_report.csv")
        except Exception as e:
            uploaded['upload_error'] = str(e)

    result = {
        'deleted_count': len([d for d in deleted if 'error' not in d]),
        'failed_count': len([d for d in deleted if 'error' in d]),
        'total_considered': total_considered,
        'reports_uploaded': uploaded
    }
    return result

def delete_old_snapshots(request: Request):
    """
    HTTP Cloud Function (Gen 2) entry point. Designed to be called by Cloud Scheduler with OIDC auth.
    The function requires IAM-based invocation (no unauthenticated access).
    """
    # Optional: basic auth for extra safety (disabled by default). See README for configuration.
    result = _run_deletion()
    return make_response(json.dumps(result), 200, {'Content-Type': 'application/json'})
