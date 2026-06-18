"""
FastAPI REST API server for PhoenixSec.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse

import phoenixsec
from phoenixsec.api.schema import (
    DirectScanRequest,
    PatchRequest,
    PatchResponse,
    ScanAsyncResponse,
    ScanRequest,
    TaskStatusResponse,
)
from phoenixsec.core.ai_patcher import AIPatcher
from phoenixsec.core.config import load_config
from phoenixsec.core.exceptions import PhoenixSecError
from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.report import Report
from phoenixsec.models.vulnerability import Severity
from phoenixsec.reporters.html import HtmlReporter
from phoenixsec.reporters.json_reporter import JsonReporter
from phoenixsec.reporters.sarif import SarifReporter
from phoenixsec.rules.engine import RuleEngine

log = get_logger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="PhoenixSec API",
    description=(
        "REST API for the Autonomous DevSecOps Security Pipeline. "
        "Includes scan, patch, report endpoints AND a GitHub webhook receiver "
        "for real-time push/PR scanning."
    ),
    version=phoenixsec.__version__,
)

# ── Webhook router ────────────────────────────────────────────────────────────
from phoenixsec.api.webhook import router as webhook_router  # noqa: E402

app.include_router(webhook_router)

# Global configuration and engine
config = load_config()
engine = RuleEngine()

# In-memory database to store async task statuses
tasks_db: dict[str, dict[str, Any]] = {}


def run_background_scan(task_id: str, target_path: Path, min_severity: Severity, fmt: str) -> None:
    """Run security scan in background and store results."""
    tasks_db[task_id]["status"] = "RUNNING"
    log.info(f"Background task {task_id}: scan started on target {target_path}")

    try:
        if target_path.is_file():
            report = engine.scan_file_to_report(target_path)
        else:
            results = engine.scan_directory(target_path, recursive=True)
            report = Report(
                scan_target=str(target_path),
                scanner_name="RuleEngine",
                metadata={
                    "files_scanned": len(results),
                    "duration_seconds": sum(r.duration_seconds for r in results),
                },
            )
            for res in results:
                for finding in res.findings:
                    report.add_finding(finding)

        # Filter report by min_severity
        filtered_report = Report(
            scan_target=report.scan_target,
            scanner_name=report.scanner_name,
            metadata=report.metadata,
        )
        filtered_report.scan_timestamp = report.scan_timestamp
        for finding in report.findings:
            if finding.severity >= min_severity:
                filtered_report.add_finding(finding)
        report = filtered_report

        # Serialize report using JsonReporter
        json_reporter = JsonReporter(config.reporting)
        report_dict = json_reporter.generate_dict(report)

        # Automatically save report to configured output directory
        filename = f"phoenixsec_report_{task_id}.json"
        save_path = config.reporting.output_dir / filename
        json_reporter.generate(report, save_path)
        log.info(f"Background task {task_id}: JSON report saved to {save_path}")

        # Also save in HTML or SARIF if requested
        if fmt.lower() == "html":
            html_reporter = HtmlReporter(config.reporting)
            html_path = config.reporting.output_dir / f"phoenixsec_report_{task_id}.html"
            html_reporter.generate(report, html_path)
        elif fmt.lower() == "sarif":
            sarif_reporter = SarifReporter(config.reporting)
            sarif_path = config.reporting.output_dir / f"phoenixsec_report_{task_id}.sarif"
            sarif_reporter.generate(report, sarif_path)

        tasks_db[task_id].update(
            {
                "status": "COMPLETED",
                "result": report_dict,
                "completed_at": datetime.now(UTC).isoformat(),
            }
        )
        log.info(f"Background task {task_id}: scan completed successfully")

    except Exception as exc:
        err_msg = str(exc)
        tasks_db[task_id].update(
            {"status": "FAILED", "error": err_msg, "completed_at": datetime.now(UTC).isoformat()}
        )
        log.error(f"Background task {task_id}: scan failed: {err_msg}")


@app.get("/health", tags=["Status"])
def health_check() -> dict[str, str]:
    """Health check endpoint to verify API server is responsive."""
    return {"status": "ok", "service": "PhoenixSec API", "version": phoenixsec.__version__}


@app.post("/scan", tags=["Scanning"])
def scan_code_direct(request: DirectScanRequest) -> dict[str, Any]:
    """Perform a synchronous scan on raw code text directly."""
    try:
        result = engine.scan_code(
            request.code,
            file_path=request.file_path,
            language=request.language.lower(),
        )
        report = Report(
            scan_target=request.file_path,
            scanner_name="RuleEngine",
            metadata={
                "language": request.language.lower(),
                "rules_run": result.rules_run,
                "duration_seconds": result.duration_seconds,
            },
        )
        for finding in result.findings:
            report.add_finding(finding)

        json_reporter = JsonReporter(config.reporting)
        return json_reporter.generate_dict(report)
    except Exception as exc:
        log.error(f"Direct scan failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Direct code scan encountered an error: {exc}",
        ) from exc


@app.post("/api/scan", tags=["Scanning"])
def scan_sync(request: ScanRequest) -> dict[str, Any]:
    """Perform a synchronous security scan on the specified target.

    Returns the formatted scan report dictionary directly.
    """
    target_path = Path(request.target).resolve()
    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target path '{request.target}' does not exist on disk.",
        )

    try:
        min_severity = Severity.from_string(request.severity)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    log.info(f"Synchronous scan requested on target {target_path} at severity {request.severity}")

    try:
        if target_path.is_file():
            report = engine.scan_file_to_report(target_path)
        else:
            results = engine.scan_directory(target_path, recursive=True)
            report = Report(
                scan_target=str(target_path),
                scanner_name="RuleEngine",
                metadata={
                    "files_scanned": len(results),
                    "duration_seconds": sum(r.duration_seconds for r in results),
                },
            )
            for res in results:
                for finding in res.findings:
                    report.add_finding(finding)

        # Filter by severity
        filtered_report = Report(
            scan_target=report.scan_target,
            scanner_name=report.scanner_name,
            metadata=report.metadata,
        )
        filtered_report.scan_timestamp = report.scan_timestamp
        for finding in report.findings:
            if finding.severity >= min_severity:
                filtered_report.add_finding(finding)
        report = filtered_report

        json_reporter = JsonReporter(config.reporting)
        return json_reporter.generate_dict(report)

    except Exception as exc:
        log.error(f"Synchronous scan failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security scan encountered an error: {exc}",
        )


@app.post("/api/scan/async", response_model=ScanAsyncResponse, tags=["Scanning"])
def scan_async(request: ScanRequest, background_tasks: BackgroundTasks) -> ScanAsyncResponse:
    """Trigger an asynchronous security scan on the specified target.

    Spawns the scan process as a background task and immediately returns a task ID.
    """
    target_path = Path(request.target).resolve()
    if not target_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target path '{request.target}' does not exist.",
        )

    try:
        min_severity = Severity.from_string(request.severity)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    task_id = str(uuid.uuid4())
    tasks_db[task_id] = {
        "task_id": task_id,
        "status": "PENDING",
        "target": str(target_path),
        "created_at": datetime.now(UTC).isoformat(),
        "completed_at": None,
        "result": None,
        "error": None,
    }

    # Queue background task
    background_tasks.add_task(
        run_background_scan,
        task_id=task_id,
        target_path=target_path,
        min_severity=min_severity,
        fmt=request.format,
    )

    return ScanAsyncResponse(
        task_id=task_id, status="PENDING", message="Scan task queued successfully in background."
    )


@app.get("/api/scan/tasks/{task_id}", response_model=TaskStatusResponse, tags=["Scanning"])
def get_task_status(task_id: str) -> TaskStatusResponse:
    """Retrieve the status and results of a background scan task."""
    task = tasks_db.get(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Background scan task '{task_id}' not found.",
        )

    return TaskStatusResponse(
        task_id=task["task_id"],
        status=task["status"],
        result=task["result"],
        error=task["error"],
    )


@app.get("/api/reports", tags=["Reports"])
def list_reports() -> dict[str, list[str]]:
    """List filenames of all saved security reports."""
    output_dir = config.reporting.output_dir
    if not output_dir.exists():
        return {"reports": []}

    reports = [f.name for f in sorted(output_dir.iterdir()) if f.is_file()]
    return {"reports": reports}


@app.get("/api/reports/{filename}", tags=["Reports"])
def get_report(filename: str) -> Any:
    """Retrieve the content of a saved report by filename.

    Supports JSON, SARIF, and HTML outputs.
    """
    report_path = (config.reporting.output_dir / filename).resolve()
    if not report_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Report file '{filename}' not found."
        )

    # Security check to prevent path traversal
    if config.reporting.output_dir.resolve() not in report_path.parents:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

    try:
        content = report_path.read_text(encoding="utf-8")
        if report_path.suffix.lower() == ".json" or report_path.suffix.lower() == ".sarif":
            import json

            return json.loads(content)
        elif report_path.suffix.lower() == ".html":
            return HTMLResponse(content=content)
        else:
            return content
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load report: {exc}",
        )


@app.post("/api/patch", response_model=PatchResponse, tags=["Remediation"])
def apply_patch(request: PatchRequest) -> PatchResponse:
    """Apply auto-patching to a file using fallback rule-based or AI patch models."""
    file_path = Path(request.file_path).resolve()
    if not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target file to patch '{request.file_path}' not found.",
        )

    # Parse finding dictionary objects into Finding domain objects
    findings = []
    for f_dict in request.findings:
        try:
            # Reconstruct vulnerability type
            v_type_str = (
                f_dict.get("vulnerability_type") or f_dict.get("vulnerability") or "Unknown"
            )
            try:
                vuln_type = VulnerabilityType(v_type_str)
            except ValueError:
                vuln_type = VulnerabilityType.UNKNOWN

            # Reconstruct severity
            sev_str = f_dict.get("severity") or "INFO"
            try:
                severity = Severity.from_string(sev_str)
            except ValueError:
                severity = Severity.INFO

            finding = Finding(
                vulnerability_type=vuln_type,
                severity=severity,
                confidence_score=float(
                    f_dict.get("confidence_score") or f_dict.get("confidence", 0.5)
                ),
                recommendation=f_dict.get("recommendation") or "N/A",
                file_path=str(file_path),
                line_number=f_dict.get("line_number"),
                source=f_dict.get("source"),
                sink=f_dict.get("sink"),
                rule_id=f_dict.get("rule_id", "PATCH-RULE"),
                code_snippet=f_dict.get("code_snippet"),
                cwe_id=f_dict.get("cwe_id"),
            )
            findings.append(finding)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid finding payload layout: {exc}",
            )

    if not findings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one valid finding must be provided to apply patches.",
        )

    try:
        ai_patcher = AIPatcher(rule_engine=engine)
        success, patched_code, is_ai_patch = ai_patcher.patch_with_fallback(file_path, findings)

        if success:
            patch_desc = "AI-generated patch" if is_ai_patch else "rule-based patch"
            msg = f"File successfully patched using {patch_desc} and verified."
            return PatchResponse(
                success=True, is_ai_patch=is_ai_patch, message=msg, patched_code=patched_code
            )
        else:
            return PatchResponse(
                success=False,
                is_ai_patch=False,
                message=(
                    "Patch application failed validation checks "
                    "(syntax compile or re-scan failed)."
                ),
                patched_code=None,
            )

    except PhoenixSecError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message) from exc
    except Exception as exc:
        log.error(f"Patching failed with unexpected error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Patching failed: {exc}",
        ) from exc


from phoenixsec.api.schema import AnalyzeFPRequest, AnalyzeFPResponse


@app.post("/api/analyze-fp", response_model=AnalyzeFPResponse, tags=["Remediation"])
def analyze_false_positive(request: AnalyzeFPRequest) -> AnalyzeFPResponse:
    """Analyze a finding using AI to determine if it is a false positive."""
    f_dict = request.finding
    try:
        v_type_str = f_dict.get("vulnerability_type") or f_dict.get("vulnerability") or "Unknown"
        try:
            vuln_type = VulnerabilityType(v_type_str)
        except ValueError:
            vuln_type = VulnerabilityType.UNKNOWN

        sev_str = f_dict.get("severity") or "INFO"
        try:
            severity = Severity.from_string(sev_str)
        except ValueError:
            severity = Severity.INFO

        finding = Finding(
            vulnerability_type=vuln_type,
            severity=severity,
            confidence_score=float(f_dict.get("confidence_score") or f_dict.get("confidence", 0.5)),
            recommendation=f_dict.get("recommendation") or "N/A",
            file_path=f_dict.get("file_path", "app.py"),
            line_number=f_dict.get("line_number"),
            source=f_dict.get("source"),
            sink=f_dict.get("sink"),
            rule_id=f_dict.get("rule_id", "UNKNOWN"),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding payload layout: {exc}",
        )

    try:
        ai_patcher = AIPatcher(rule_engine=engine)
        is_fp, reasoning = ai_patcher.analyze_false_positive(request.code, finding)
        return AnalyzeFPResponse(is_false_positive=is_fp, reasoning=reasoning)
    except PhoenixSecError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message) from exc
    except Exception as exc:
        log.error(f"AI FP Analysis failed with unexpected error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI FP Analysis failed: {exc}",
        ) from exc
