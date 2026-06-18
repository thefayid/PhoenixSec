"""
CSRF (Cross-Site Request Forgery) detection rule.

Detection strategy
------------------
Detects globally disabled CSRF protection or explicitly bypassed endpoints.

Python patterns
~~~~~~~~~~~~~~~
- ``app.config['WTF_CSRF_ENABLED'] = False``
- ``@csrf_exempt`` (Django)
- ``csrf.exempt(app)`` (Flask-WTF)

Scoring
~~~~~~~
+1.00 for explicitly disabling CSRF globally or on a route.
"""

from __future__ import annotations

import re

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.base_rule import BaseRule, RuleContext
from phoenixsec.rules.registry import rule

log = get_logger(__name__)

# ── Python patterns ─────────────────────────────────────────────────────────────
_PY_SINK_RE = re.compile(
    r"(?:\bWTF_CSRF_ENABLED['\"]\s*\]?\s*=\s*False|"
    r"@csrf_exempt\b|"
    r"\bcsrf\.exempt\s*\()",
    re.IGNORECASE,
)


@rule
class PythonCSRFRule(BaseRule):
    """Detects missing or disabled CSRF protections in Python frameworks."""

    rule_id = "PSEC-CSRF-PY-001"
    name = "Python Disabled CSRF Protection"
    languages = ["python"]
    severity = Severity.HIGH
    cwe_id = "CWE-352"

    def scan(self, code: str, file_path: str) -> Finding | None:
        results = self.scan_context(RuleContext.from_code(code, file_path, "python"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for line_idx, line in enumerate(ctx.lines):
            m = _PY_SINK_RE.search(line)
            if not m:
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    vulnerability_type=VulnerabilityType.CSRF,
                    severity=Severity.HIGH,
                    confidence_score=1.0,
                    file_path=ctx.file_path,
                    line_number=line_idx + 1,
                    source="disabled CSRF token validation",
                    sink=m.group(0).strip(),
                    cwe_id="CWE-352",
                    recommendation=(
                        "Do not disable CSRF protections globally or on state-changing endpoints. "
                        "Ensure `WTF_CSRF_ENABLED = True` in Flask, and keep `CsrfViewMiddleware` "
                        "enabled in Django."
                    ),
                    references=[
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/352.html",
                    ],
                )
            )

        return findings
