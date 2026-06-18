"""
Infrastructure as Code (IaC) security rules for Dockerfiles and Terraform configurations.
"""

from __future__ import annotations

import re

from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.base_rule import BaseRule
from phoenixsec.rules.registry import rule


# ══════════════════════════════════════════════════════════════════════════════
# Dockerfile Rules
# ══════════════════════════════════════════════════════════════════════════════

@rule
class DockerfileUnpinnedTagRule(BaseRule):
    """Detect unpinned or ':latest' base image tags in Dockerfiles.

    Using unpinned base images can lead to non-reproducible builds and
    accidental introduction of newer, untested, or vulnerable base dependencies.
    """

    rule_id = "IAC-DKR-001"
    name = "Unpinned Docker Base Image Tag"
    description = (
        "Detected a base image in a Dockerfile that is unpinned or uses the "
        "':latest' tag. Base images should use specific version tags or "
        "SHA-256 digests to ensure build reproducibility and prevent "
        "supply-chain attacks."
    )
    severity = Severity.MEDIUM
    category = VulnerabilityType.MISCONFIGURATION
    language = "dockerfile"
    confidence = 0.90
    cwe_id = "CWE-1104"
    references = (
        "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
        "https://cwe.mitre.org/data/definitions/1104.html",
    )

    def _recommendation(self) -> str:
        return (
            "Pin your base images to a specific version tag (e.g., 'python:3.12-slim') "
            "or a SHA-256 digest (e.g., 'ubuntu@sha256:...') instead of using ':latest' "
            "or omitting the tag."
        )

    def scan(self, code: str, file_path: str) -> Finding | None:
        findings = self.scan_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        if not code.strip():
            return findings

        # Matches: FROM base_image or FROM base_image:latest
        from_pattern = re.compile(r"^\s*FROM\s+([^\s#]+)(?:\s+AS\s+\w+)?", re.IGNORECASE)

        for idx, line in enumerate(code.splitlines(), start=1):
            match = from_pattern.match(line)
            if match:
                image_spec = match.group(1)
                # Check if tag is present and if it's latest
                if "@" in image_spec:
                    # Pinned via digest, safe
                    continue
                
                parts = image_spec.split(":")
                if len(parts) == 1 or parts[1].lower() == "latest":
                    findings.append(
                        self._make_finding(
                            file_path,
                            line_number=idx,
                            snippet=line.strip(),
                            sink="Unpinned base image reference",
                        )
                    )
        return findings


@rule
class DockerfileUserRootRule(BaseRule):
    """Detect Dockerfiles executing container processes as 'root' user.

    Containers running as root can lead to container escape vulnerabilities
    or privilege escalation if the host kernel is compromised.
    """

    rule_id = "IAC-DKR-002"
    name = "Running Container as Root User"
    description = (
        "Detected container configured to run processes as root by default. "
        "Containers should run under a dedicated non-root user (e.g. USER node, "
        "USER 1000) to adhere to the principle of least privilege."
    )
    severity = Severity.HIGH
    category = VulnerabilityType.MISCONFIGURATION
    language = "dockerfile"
    confidence = 0.85
    cwe_id = "CWE-250"
    references = (
        "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
        "https://cwe.mitre.org/data/definitions/250.html",
    )

    def _recommendation(self) -> str:
        return (
            "Create a non-root system user and switch to it using the 'USER <name>' "
            "instruction at the end of your Dockerfile."
        )

    def scan(self, code: str, file_path: str) -> Finding | None:
        findings = self.scan_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        if not code.strip():
            return findings

        lines = code.splitlines()
        last_user_line = None
        is_root = True

        user_pattern = re.compile(r"^\s*USER\s+(\w+)", re.IGNORECASE)

        for idx, line in enumerate(lines, start=1):
            match = user_pattern.match(line)
            if match:
                last_user_line = idx
                username = match.group(1).lower()
                is_root = (username == "root")

        # If no USER was ever specified, or the last user was root
        if last_user_line is None:
            findings.append(
                self._make_finding(
                    file_path,
                    line_number=len(lines),
                    snippet=lines[-1].strip() if lines else "",
                    sink="No non-root USER configured (defaults to root)",
                )
            )
        elif is_root:
            findings.append(
                self._make_finding(
                    file_path,
                    line_number=last_user_line,
                    snippet=lines[last_user_line - 1].strip(),
                    sink="Explicitly switched user context to root",
                )
            )

        return findings


@rule
class DockerfileEnvSecretsRule(BaseRule):
    """Detect hardcoded credentials or API keys stored in Dockerfile ENV variables."""

    rule_id = "IAC-DKR-003"
    name = "Hardcoded Secret in ENV Variable"
    description = (
        "Detected potential credential or API key stored in cleartext inside "
        "a Dockerfile ENV instruction. These environment variables persist in the "
        "image metadata and can be extracted by anyone with pull access."
    )
    severity = Severity.HIGH
    category = VulnerabilityType.HARDCODED_SECRET
    language = "dockerfile"
    confidence = 0.80
    cwe_id = "CWE-798"
    references = (
        "https://docs.docker.com/develop/develop-images/instructions/#env",
        "https://cwe.mitre.org/data/definitions/798.html",
    )

    def _recommendation(self) -> str:
        return (
            "Never store cleartext secrets in Dockerfile ENV instructions. "
            "Use build secrets (e.g. 'docker build --secret') or inject keys "
            "dynamically at container execution runtime."
        )

    def scan(self, code: str, file_path: str) -> Finding | None:
        findings = self.scan_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        if not code.strip():
            return findings

        # Match ENV key=value or ENV key value
        env_pattern = re.compile(
            r"^\s*ENV\s+(\w*(?:password|passwd|api[_-]?key|secret|token)\w*)\s*=\s*(.+)|^\s*ENV\s+(\w*(?:password|passwd|api[_-]?key|secret|token)\w*)\s+(.+)",
            re.IGNORECASE,
        )

        for idx, line in enumerate(code.splitlines(), start=1):
            match = env_pattern.match(line)
            if match:
                findings.append(
                    self._make_finding(
                        file_path,
                        line_number=idx,
                        snippet=line.strip(),
                        sink="Cleartext secret assignment in container ENV metadata",
                    )
                )
        return findings


# ══════════════════════════════════════════════════════════════════════════════
# Terraform Rules
# ══════════════════════════════════════════════════════════════════════════════

@rule
class TerraformOpenIngressRule(BaseRule):
    """Detect wide-open ingress rules (0.0.0.0/0) on sensitive SSH or RDP ports in Terraform."""

    rule_id = "IAC-TF-001"
    name = "Security Group Allowing Open Ingress"
    description = (
        "Detected wide-open CIDR block (0.0.0.0/0) allowing remote access to "
        "sensitive administrative services (port 22 for SSH, 3389 for RDP, "
        "or all ports). This exposes internal servers to brute-force attacks "
        "and scanning from the entire internet."
    )
    severity = Severity.HIGH
    category = VulnerabilityType.MISCONFIGURATION
    language = "terraform"
    confidence = 0.85
    cwe_id = "CWE-732"
    references = (
        "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
        "https://cwe.mitre.org/data/definitions/732.html",
    )

    def _recommendation(self) -> str:
        return (
            "Restrict the ingress source CIDR block to authorized IP addresses "
            "or security group IDs instead of wide-open '0.0.0.0/0' access."
        )

    def scan(self, code: str, file_path: str) -> Finding | None:
        findings = self.scan_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        if not code.strip():
            return findings

        lines = code.splitlines()
        
        # We slide a window over lines to associate cidr_blocks and port assignments within blocks.
        # Simple window tracking:
        for idx in range(len(lines)):
            line = lines[idx]
            if "0.0.0.0/0" in line and "cidr_blocks" in line:
                # Look 5 lines up and 5 lines down for sensitive port assignments
                start_win = max(0, idx - 5)
                end_win = min(len(lines), idx + 6)
                
                has_sensitive_port = False
                port_desc = ""
                for j in range(start_win, end_win):
                    win_line = lines[j]
                    if re.search(r"\b(from_port|to_port)\s*=\s*(22|3389|0)\b", win_line):
                        has_sensitive_port = True
                        if "22" in win_line:
                            port_desc = "SSH (22)"
                        elif "3389" in win_line:
                            port_desc = "RDP (3389)"
                        else:
                            port_desc = "All Ports (0)"
                        break

                if has_sensitive_port:
                    findings.append(
                        self._make_finding(
                            file_path,
                            line_number=idx + 1,
                            snippet=line.strip(),
                            sink=f"Wide-open access to {port_desc} configured in ingress rules",
                        )
                    )
        return findings


@rule
class TerraformPublicS3BucketRule(BaseRule):
    """Detect S3 bucket configurations set to public-read or public-read-write in Terraform."""

    rule_id = "IAC-TF-002"
    name = "Public Access S3 Bucket Configuration"
    description = (
        "Detected an S3 bucket configured with a public access control list "
        "(ACL) like 'public-read' or 'public-read-write'. This can lead to "
        "unintentional public exposure of sensitive data stored in S3."
    )
    severity = Severity.HIGH
    category = VulnerabilityType.MISCONFIGURATION
    language = "terraform"
    confidence = 0.90
    cwe_id = "CWE-732"
    references = (
        "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_acl",
        "https://cwe.mitre.org/data/definitions/732.html",
    )

    def _recommendation(self) -> str:
        return (
            "Change S3 bucket ACLs to 'private' or remove public access configurations. "
            "Use S3 Public Access Blocks to enforce absolute bucket privacy."
        )

    def scan(self, code: str, file_path: str) -> Finding | None:
        findings = self.scan_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        if not code.strip():
            return findings

        acl_pattern = re.compile(r"acl\s*=\s*[\"'](public-read|public-read-write)[\"']", re.IGNORECASE)

        for idx, line in enumerate(code.splitlines(), start=1):
            match = acl_pattern.search(line)
            if match:
                findings.append(
                    self._make_finding(
                        file_path,
                        line_number=idx,
                        snippet=line.strip(),
                        sink=f"Bucket access ACL set to public: '{match.group(1)}'",
                    )
                )
        return findings
