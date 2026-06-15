"""Domain models package."""

from phoenixsec.models.finding import ConfidenceTier, Finding, VulnerabilityType
from phoenixsec.models.report import Report, SeveritySummary
from phoenixsec.models.scan_result import ScanResult
from phoenixsec.models.scan_target import ScanTarget, TargetType
from phoenixsec.models.vulnerability import Severity, Vulnerability, VulnerabilityCategory

__all__ = [
    # Severity + core detection
    "Severity",
    "VulnerabilityCategory",
    "Vulnerability",
    # Taint-analysis finding
    "VulnerabilityType",
    "ConfidenceTier",
    "Finding",
    # Report
    "SeveritySummary",
    "Report",
    # Pipeline models
    "ScanResult",
    "ScanTarget",
    "TargetType",
]
