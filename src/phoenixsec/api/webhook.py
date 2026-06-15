"""
PhoenixSec Webhook Server — receives GitHub push events and triggers scans.

Endpoint: POST /webhook/github
  Validates HMAC-SHA256 signature from X-Hub-Signature-256.
  Triggers a background PhoenixSec scan on the changed files.
  Posts findings as PR comments via GitHub API.

Environment Variables
---------------------
PHOENIXSEC_WEBHOOK_SECRET   : GitHub webhook secret (for HMAC validation)
GITHUB_TOKEN                : GitHub PAT for posting comments
PHOENIXSEC_AI_KEY           : Gemini API key for AI patching (optional)
PHOENIXSEC_FAIL_ON          : Severity threshold (default HIGH)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from phoenixsec.core.logger import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/webhook", tags=["Webhook"])

# Global thread-safe job queue and status tracking registry
JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()
JOB_QUEUE: queue.Queue = queue.Queue()


# ─────────────────────────────────────────────────────────────────────────────
# HMAC Signature Validation
# ─────────────────────────────────────────────────────────────────────────────


def _validate_signature(payload: bytes, signature: str | None) -> bool:
    """Validate GitHub webhook HMAC-SHA256 signature.

    Parameters
    ----------
    payload:
        Raw request body bytes.
    signature:
        Value of X-Hub-Signature-256 header (e.g. 'sha256=abc123...').

    Returns
    -------
    bool
        True if signature is valid, False otherwise.
    """
    secret = os.environ.get("PHOENIXSEC_WEBHOOK_SECRET", "")
    if not secret:
        is_dev = os.environ.get("PHOENIXSEC_DEV_MODE", "false").lower() == "true"
        if is_dev:
            log.warning(
                "PHOENIXSEC_WEBHOOK_SECRET not set — skipping signature validation in DEV MODE"
            )
            return True
        log.error("PHOENIXSEC_WEBHOOK_SECRET not set. Webhook signature validation failed.")
        return False

    if not signature or not signature.startswith("sha256="):
        log.warning("Missing or malformed X-Hub-Signature-256 header")
        return False

    expected = (
        "sha256="
        + hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()
    )

    return hmac.compare_digest(expected, signature)


# ─────────────────────────────────────────────────────────────────────────────
# Background Scan Worker
# ─────────────────────────────────────────────────────────────────────────────


class ScanJob:
    """Represents a background scan triggered by a webhook push event."""

    def __init__(
        self,
        repo_name: str,
        repo_clone_url: str,
        branch: str,
        commit_sha: str,
        changed_files: list[str],
        pusher: str,
        pr_number: int | None = None,
    ) -> None:
        self.repo_name = repo_name
        self.repo_clone_url = repo_clone_url
        self.branch = branch
        self.commit_sha = commit_sha
        self.changed_files = changed_files
        self.pusher = pusher
        self.pr_number = pr_number
        self.started_at = time.time()
        self.job_id = f"{repo_name.replace('/', '-')}-{commit_sha[:8]}-{int(self.started_at)}"


def _run_scan_job(job: ScanJob) -> None:
    """Execute a PhoenixSec scan in a background thread.

    Clones the repo at the pushed commit, runs `phoenixsec scan`,
    and posts findings as PR comments if a PR number is available.
    """
    log.info(f"[Webhook] Starting scan job {job.job_id} for {job.repo_name}@{job.commit_sha[:8]}")

    with JOBS_LOCK:
        if job.job_id in JOBS:
            JOBS[job.job_id]["status"] = "running"

    import tempfile

    workspace = Path(tempfile.gettempdir()) / f"phoenixsec_scan_{job.job_id}"
    try:
        # 1. Clone repo at commit
        token = os.environ.get("GITHUB_TOKEN", "")
        clone_url = job.repo_clone_url
        if token:
            # Inject token into HTTPS clone URL
            clone_url = clone_url.replace("https://", f"https://x-access-token:{token}@")

        log.info(f"[Webhook] Cloning {job.repo_name} to {workspace}")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", job.branch, clone_url, str(workspace)],
            capture_output=True,
            check=False,
            timeout=120,
        )
        if result.returncode != 0:
            log.error(f"[Webhook] Clone failed: {result.stderr.decode()}")
            with JOBS_LOCK:
                if job.job_id in JOBS:
                    JOBS[job.job_id]["status"] = "failed"
                    JOBS[job.job_id]["error"] = f"Clone failed: {result.stderr.decode()}"
                    JOBS[job.job_id]["completed_at"] = time.time()
            return

        # 2. Run PhoenixSec scan
        fail_on = os.environ.get("PHOENIXSEC_FAIL_ON", "HIGH")
        auto_patch = os.environ.get("PHOENIXSEC_AUTO_PATCH", "false").lower() == "true"

        cmd = [
            "phoenixsec",
            "scan",
            str(workspace),
            "--severity",
            "LOW",
            "--format",
            "json",
        ]
        if auto_patch:
            cmd.append("--patch")

        log.info(f"[Webhook] Running scan: {' '.join(cmd)}")
        scan_result = subprocess.run(
            cmd,
            capture_output=True,
            check=False,
            timeout=300,
        )

        # 3. Parse findings
        findings_data: list[dict[str, Any]] = []
        try:
            report = json.loads(scan_result.stdout.decode("utf-8", errors="replace"))
            findings_data = report.get("findings", [])
        except (json.JSONDecodeError, ValueError):
            log.warning("[Webhook] Could not parse scan JSON output")

        total = len(findings_data)
        critical = sum(1 for f in findings_data if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings_data if f.get("severity") == "HIGH")

        log.info(
            f"[Webhook] Scan complete for {job.job_id}: "
            f"{total} total, {critical} critical, {high} high"
        )

        # 4. Post PR comments if applicable
        if job.pr_number and findings_data and token:
            _post_pr_findings(job, findings_data)

        # 5. Log summary
        severity_threshold_values = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold_val = severity_threshold_values.get(fail_on.upper(), 3)
        blocking_findings = [
            f
            for f in findings_data
            if severity_threshold_values.get(f.get("severity", "INFO"), 0) >= threshold_val
        ]

        if blocking_findings:
            log.warning(
                f"[Webhook] ⚠️  {len(blocking_findings)} blocking findings in "
                f"{job.repo_name}@{job.commit_sha[:8]} "
                f"(threshold: {fail_on})"
            )
        else:
            log.info(f"[Webhook] ✅ No blocking findings in {job.repo_name}@{job.commit_sha[:8]}")

        with JOBS_LOCK:
            if job.job_id in JOBS:
                JOBS[job.job_id]["status"] = "completed"
                JOBS[job.job_id]["completed_at"] = time.time()
                JOBS[job.job_id]["findings_count"] = total

    except Exception as exc:
        log.error(f"[Webhook] Scan job {job.job_id} failed: {exc}")
        with JOBS_LOCK:
            if job.job_id in JOBS:
                JOBS[job.job_id]["status"] = "failed"
                JOBS[job.job_id]["error"] = str(exc)
                JOBS[job.job_id]["completed_at"] = time.time()
    finally:
        # Cleanup cloned workspace
        import shutil

        if workspace.exists():
            shutil.rmtree(workspace, ignore_errors=True)
        log.info(f"[Webhook] Scan job {job.job_id} complete, workspace cleaned up")


def _worker() -> None:
    """Worker thread to process scan jobs sequentially from the queue."""
    while True:
        job = JOB_QUEUE.get()
        if job is None:
            break
        try:
            _run_scan_job(job)
        except Exception as exc:
            log.error(f"[Webhook] Worker error during job {job.job_id}: {exc}")
        finally:
            JOB_QUEUE.task_done()


# Spawn background worker thread
WORKER_THREAD = threading.Thread(target=_worker, daemon=True)
WORKER_THREAD.start()


def _post_pr_findings(job: ScanJob, findings: list[dict[str, Any]]) -> None:
    """Post PhoenixSec findings as inline PR review comments."""
    import urllib.request

    token = os.environ.get("GITHUB_TOKEN", "")
    owner, repo = job.repo_name.split("/", 1) if "/" in job.repo_name else ("", job.repo_name)

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
        "User-Agent": "PhoenixSec-Webhook-Bot",
    }

    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

    for finding in findings[:20]:  # Limit to 20 comments per push
        severity = finding.get("severity", "INFO")
        vuln_type = finding.get("vulnerability_type", "Unknown")
        file_path = finding.get("file_path", "")
        line_number = finding.get("line_number")
        recommendation = finding.get("recommendation", "")
        cwe_id = finding.get("cwe_id", "")
        rule_id = finding.get("rule_id", "")
        confidence = finding.get("confidence_percent", 0)

        if not line_number:
            continue

        # Make file path relative to repo root
        try:
            rel_path = Path(file_path).name  # Fallback to filename
        except Exception:
            rel_path = str(file_path)

        emoji = severity_emoji.get(severity, "⚪")
        body = (
            f"### {emoji} PhoenixSec: {vuln_type}\n\n"
            f"**Severity:** `{severity}` | "
            f"**Confidence:** `{confidence}%` | "
            f"**Rule:** `{rule_id}`" + (f" | **CWE:** `{cwe_id}`" if cwe_id else "") + f"\n\n"
            f"#### 📝 Recommendation\n{recommendation}\n\n"
            f"---\n"
            f"*Detected by [PhoenixSec](https://github.com/phoenixsec) "
            f"— Autonomous DevSecOps Pipeline*"
        )

        payload = {
            "body": body,
            "commit_id": job.commit_sha,
            "path": rel_path,
            "line": line_number,
            "side": "RIGHT",
        }

        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{job.pr_number}/comments"
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 201:
                    log.debug(f"[Webhook] Posted comment on {rel_path}:{line_number}")
        except Exception as exc:
            log.warning(f"[Webhook] Failed to post comment on {rel_path}:{line_number}: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Webhook Endpoint
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/github",
    summary="GitHub Push/PR Webhook",
    description=(
        "Receives GitHub `push` and `pull_request` events. "
        "Validates HMAC signature, then triggers a background PhoenixSec scan. "
        "Posts findings as inline PR comments when a PR is associated."
    ),
)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
) -> JSONResponse:
    """Handle incoming GitHub webhook events."""
    # Read raw body for HMAC validation
    payload_bytes = await request.body()

    # Validate signature
    if not _validate_signature(payload_bytes, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Parse JSON payload
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {exc}") from exc

    event_type = x_github_event or "unknown"
    log.info(f"[Webhook] Received GitHub event: {event_type}")

    # Handle ping (used to verify webhook setup)
    if event_type == "ping":
        return JSONResponse(
            content={"message": "🛡️ PhoenixSec webhook is active!", "zen": payload.get("zen", "")},
            status_code=200,
        )

    # Extract repo info
    repo = payload.get("repository", {})
    repo_name = repo.get("full_name", "unknown/repo")
    repo_clone_url = repo.get("clone_url", "")

    # Handle push events
    if event_type == "push":
        ref = payload.get("ref", "")
        branch = ref.replace("refs/heads/", "") if ref.startswith("refs/heads/") else ref
        commit_sha = payload.get("after", payload.get("head_commit", {}).get("id", ""))
        pusher = payload.get("pusher", {}).get("name", "unknown")

        # Get changed files
        commits = payload.get("commits", [])
        changed_files: set[str] = set()
        for commit in commits:
            changed_files.update(commit.get("added", []))
            changed_files.update(commit.get("modified", []))

        # Skip deletions-only pushes and fix branches
        if not changed_files or branch.startswith("phoenixsec-fix"):
            return JSONResponse(
                content={"message": "No scannable changes detected"},
                status_code=200,
            )

        job = ScanJob(
            repo_name=repo_name,
            repo_clone_url=repo_clone_url,
            branch=branch,
            commit_sha=commit_sha,
            changed_files=list(changed_files),
            pusher=pusher,
        )

        with JOBS_LOCK:
            JOBS[job.job_id] = {
                "job_id": job.job_id,
                "status": "queued",
                "repo_name": repo_name,
                "branch": branch,
                "commit_sha": commit_sha,
                "started_at": job.started_at,
                "completed_at": None,
            }
        JOB_QUEUE.put(job)

        log.info(
            f"[Webhook] Queued scan job {job.job_id} for {repo_name} "
            f"branch={branch} files={len(changed_files)}"
        )

        return JSONResponse(
            content={
                "message": "🛡️ PhoenixSec scan queued",
                "job_id": job.job_id,
                "repo": repo_name,
                "branch": branch,
                "commit": commit_sha[:8],
                "files_to_scan": len(changed_files),
            },
            status_code=202,
        )

    # Handle pull_request events
    elif event_type == "pull_request":
        action = payload.get("action", "")
        if action not in ("opened", "synchronize", "reopened"):
            return JSONResponse(
                content={"message": f"Ignoring PR action: {action}"},
                status_code=200,
            )

        pr_data = payload.get("pull_request", {})
        pr_number = pr_data.get("number")
        branch = pr_data.get("head", {}).get("ref", "")
        commit_sha = pr_data.get("head", {}).get("sha", "")
        sender = payload.get("sender", {}).get("login", "unknown")

        # Get changed files from PR
        changed_files = []  # Will be determined by clone + diff

        job = ScanJob(
            repo_name=repo_name,
            repo_clone_url=repo_clone_url,
            branch=branch,
            commit_sha=commit_sha,
            changed_files=changed_files,
            pusher=sender,
            pr_number=pr_number,
        )

        with JOBS_LOCK:
            JOBS[job.job_id] = {
                "job_id": job.job_id,
                "status": "queued",
                "repo_name": repo_name,
                "branch": branch,
                "commit_sha": commit_sha,
                "started_at": job.started_at,
                "completed_at": None,
                "pr_number": pr_number,
            }
        JOB_QUEUE.put(job)

        log.info(f"[Webhook] Queued PR scan job {job.job_id} for PR #{pr_number} in {repo_name}")

        return JSONResponse(
            content={
                "message": "🛡️ PhoenixSec PR scan queued",
                "job_id": job.job_id,
                "repo": repo_name,
                "pr_number": pr_number,
                "branch": branch,
                "commit": commit_sha[:8],
            },
            status_code=202,
        )

    else:
        return JSONResponse(
            content={"message": f"Event type '{event_type}' not handled"},
            status_code=200,
        )


@router.get("/health", summary="Webhook server health check")
async def webhook_health() -> JSONResponse:
    """Health check endpoint for the webhook server."""
    return JSONResponse(
        content={
            "status": "healthy",
            "service": "PhoenixSec Webhook Server",
            "secret_configured": bool(os.environ.get("PHOENIXSEC_WEBHOOK_SECRET")),
            "auto_patch": os.environ.get("PHOENIXSEC_AUTO_PATCH", "false"),
            "fail_on": os.environ.get("PHOENIXSEC_FAIL_ON", "HIGH"),
        }
    )


@router.get(
    "/jobs/{job_id}",
    summary="Get Webhook Scan Job Status",
    description="Get the status of a queued or running scan job.",
)
async def get_job_status(job_id: str) -> JSONResponse:
    """Get the status of a specific scan job."""
    with JOBS_LOCK:
        job_info = JOBS.get(job_id)

    if not job_info:
        raise HTTPException(status_code=404, detail="Job not found")

    return JSONResponse(content=job_info)
