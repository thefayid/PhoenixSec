"""
Hardcoded secrets detection rule — Language-agnostic.

Detection strategy
------------------
This rule checks all source lines for potential hardcoded secrets such as
passwords, API keys, tokens, JWT secrets, and AWS keys:

1. **Scan lines** for variable assignments or dictionary mappings matching:
   - Secret identifiers: ``password``, ``passwd``, ``api_key``, ``secret_token``, etc.
   - Specific formats: AWS Keys (``AKIA...``) or OpenAI generic keys (``sk-...``).

2. **Compute confidence score** based on naming, pattern matching, Shannon entropy,
   and length, while subtracting score for placeholder values:
   - Variable name identifier: +0.40
   - Specific format match (AWS/Generic key): +0.70
   - Shannon Entropy H:
     - H >= 4.0: +0.35 (highly random)
     - H >= 3.0: +0.20
     - H >= 2.0: +0.10
     - H < 2.0: -0.40 (dummy or plain words)
   - Length:
     - len >= 32: +0.15
     - len >= 16: +0.10
     - len < 8: -0.30
   - Placeholder suppressor (your_, placeholder, dummy, xxxx, replace_me, todo): -0.60

3. **Emit** a ``Finding`` when the score is ≥ 0.50.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.base_rule import BaseRule
from phoenixsec.rules.registry import rule

log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Compiled regex patterns
# ══════════════════════════════════════════════════════════════════════════════

# ── Naming Identifier Assignments ─────────────────────────────────────────────
# Matches: password = "xxx", API_KEY: 'xxx', secret_token => "xxx", etc.
_ASSIGNMENT_RE = re.compile(
    r"\b(password|passwd|api[_-]?key|jwt[_-]?secret|secret[_-]?token|token|aws[_-]?key|access[_-]?key|secret|credential|auth[_-]?token)\s*[:=]\s*([\"'])([^\"'\n\r]+)\2",
    re.IGNORECASE,
)

# ── Specific Secret Formats ───────────────────────────────────────────────────
_AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_GENERIC_KEY_RE = re.compile(r"\b(sk-[a-zA-Z0-9]{24,40})\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b")

# ── Placeholder Suppressor Heuristic ──────────────────────────────────────────
_PLACEHOLDER_RE = re.compile(
    r"\b(?:your[_-]?\w+|placeholder|dummy|todo|xxxx|secret[_-]?here|replace[_-]?me)\b",
    re.IGNORECASE,
)


# ══════════════════════════════════════════════════════════════════════════════
# Entropy math helper
# ══════════════════════════════════════════════════════════════════════════════


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string to measure its randomness."""
    if not s:
        return 0.0
    probabilities = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probabilities)


def verify_secret(secret_type: str, value: str) -> bool:
    """Verify if a detected secret is active by pinging the provider's API.

    Returns True if verified active, False otherwise.
    """
    import os
    if os.environ.get("PHOENIXSEC_OFFLINE") == "1" or os.environ.get("PHOENIXSEC_DISABLE_SECRET_VALIDATION") == "1":
        return False

    secret_type_lower = secret_type.lower()
    
    # 1. GitHub API Verification
    if "github" in secret_type_lower or value.startswith("ghp_") or value.startswith("github_pat_"):
        import urllib.request
        import urllib.error
        req = urllib.request.Request(
            "https://api.github.com/user",
            headers={"Authorization": f"token {value}", "User-Agent": "PhoenixSec-Scanner"}
        )
        try:
            with urllib.request.urlopen(req, timeout=1.5) as response:
                if response.status == 200:
                    return True
        except Exception:
            return False

    # 2. OpenAI API Verification
    elif "openai" in secret_type_lower or "generic key" in secret_type_lower or value.startswith("sk-"):
        import urllib.request
        import urllib.error
        req = urllib.request.Request(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {value}", "User-Agent": "PhoenixSec-Scanner"}
        )
        try:
            with urllib.request.urlopen(req, timeout=1.5) as response:
                if response.status == 200:
                    return True
        except Exception:
            return False

    return False


# ══════════════════════════════════════════════════════════════════════════════
# Scorer
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class _SecretMatch:
    line_number: int
    matched_line: str
    secret_type: str
    secret_value: str

    def compute_score(self) -> float:
        """Compute the confidence score of the matched secret candidates."""
        score = 0.0

        # Base configuration matches
        if self.secret_type in {"AWS Key", "Generic Key", "GitHub Token"}:
            score += 0.70
        else:
            # Identifier matching
            score += 0.40

        entropy = shannon_entropy(self.secret_value)
        length = len(self.secret_value)

        # Shannon entropy contributions
        if entropy >= 4.0:
            score += 0.35
        elif entropy >= 3.0:
            score += 0.20
        elif entropy >= 2.0:
            score += 0.10
        else:
            score -= 0.40

        # Length contributions
        if length >= 32:
            score += 0.15
        elif length >= 16:
            score += 0.10
        elif length < 8:
            score -= 0.30

        # Placeholder checks (suppressions)
        if _PLACEHOLDER_RE.search(self.secret_value) or _PLACEHOLDER_RE.search(self.secret_type):
            score -= 0.60

        return max(0.0, min(1.0, score))


# ══════════════════════════════════════════════════════════════════════════════
# Rule class
# ══════════════════════════════════════════════════════════════════════════════


@rule
class HardcodedSecretsRule(BaseRule):
    """Detect hardcoded secrets (API keys, credentials, tokens, AWS keys).

    Language-agnostic rule: scans Python, Java, and other supported codebase
    formats for static variable secrets assignments and specific keys formatting.
    """

    rule_id = "ALL-SEC-001"
    name = "Hardcoded Secret Detection"
    description = (
        "Detected a hardcoded credential, API token, password, or AWS key "
        "stored in cleartext. Committing active secrets to source repositories "
        "allows unauthorized actors to access cloud services, databases, or "
        "third-party APIs, causing data leaks or resource hijack."
    )
    severity = Severity.CRITICAL
    category = VulnerabilityType.HARDCODED_SECRET
    language = "*"
    confidence = 0.75
    cwe_id = "CWE-798"
    references = (
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
        "https://cwe.mitre.org/data/definitions/798.html",
    )

    def _recommendation(self) -> str:
        return (
            "Never store cleartext passwords, API keys, or access tokens in source code. "
            "Retrieve credentials dynamically at runtime using environment variables, "
            "config mappings, or key managers (e.g. AWS Secrets Manager, HashiCorp Vault). "
            "If this credential was committed, revoke and rotate it immediately."
        )

    def scan(self, code: str, file_path: str) -> Finding | None:
        """Return the first secret finding found, or None if clean."""
        findings = self._detect_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        """Return all secret findings in the file."""
        return self._detect_all(code, file_path)

    def _detect_all(self, code: str, file_path: str) -> list[Finding]:
        if not code.strip():
            return []

        lines = code.splitlines()
        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for idx, line in enumerate(lines):
            # Skip comments or blank lines
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith("#")
                or stripped.startswith("//")
                or stripped.startswith("*")
            ):
                continue

            # Skip lines matching SQL statement patterns or python f-strings
            # with multiple interpolations
            if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", line, re.IGNORECASE):
                continue
            is_fstring = bool(re.search(r"\bf['\"]", line)) or 'f"""' in line or "f'''" in line
            has_multiple_interpolations = len(re.findall(r"\{[^}]+\}", line)) >= 2
            if is_fstring and has_multiple_interpolations:
                continue

            matches: list[_SecretMatch] = []

            # 1. AWS Key ID specific check
            aws_match = _AWS_KEY_RE.search(line)
            if aws_match:
                matches.append(
                    _SecretMatch(
                        line_number=idx + 1,
                        matched_line=line,
                        secret_type="AWS Key",
                        secret_value=aws_match.group(1),
                    )
                )

            # 2. Generic API Key check (sk-...)
            gen_match = _GENERIC_KEY_RE.search(line)
            if gen_match:
                matches.append(
                    _SecretMatch(
                        line_number=idx + 1,
                        matched_line=line,
                        secret_type="Generic Key",
                        secret_value=gen_match.group(1),
                    )
                )

            # 3. GitHub Token specific check
            github_match = _GITHUB_TOKEN_RE.search(line)
            if github_match:
                matches.append(
                    _SecretMatch(
                        line_number=idx + 1,
                        matched_line=line,
                        secret_type="GitHub Token",
                        secret_value=github_match.group(1),
                    )
                )

            # 4. Variable assignment checks
            assign_match = _ASSIGNMENT_RE.search(line)
            if assign_match:
                matches.append(
                    _SecretMatch(
                        line_number=idx + 1,
                        matched_line=line,
                        secret_type=assign_match.group(1),
                        secret_value=assign_match.group(3),
                    )
                )

            # Score each potential match on this line
            for match in matches:
                score = match.compute_score()
                log.debug(
                    "HardcodedSecretsRule: candidate scored",
                    file=file_path,
                    line=match.line_number,
                    score=round(score, 2),
                    type=match.secret_type,
                )

                if score >= 0.50:
                    if match.line_number not in seen_lines:
                        seen_lines.add(match.line_number)

                        # Active validation check
                        is_active = verify_secret(match.secret_type, match.secret_value)

                        sink_msg = "Hardcoded value in variable assignment"
                        if is_active:
                            sink_msg = "Active and verified hardcoded secret via API ping"
                            score = 1.0

                        findings.append(
                            self._make_finding(
                                file_path,
                                line_number=match.line_number,
                                snippet=match.matched_line.strip(),
                                source=match.secret_type,
                                sink=sink_msg,
                                confidence=score,
                            )
                        )

        return findings
