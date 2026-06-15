"""
Compliance Mapping Module.
Maps CWE IDs to major regulatory and industry standards.
"""

from __future__ import annotations

# Maps clean CWE number or string (e.g. "89" or "CWE-89") to standard requirements.
CWE_COMPLIANCE_MAP: dict[str, dict[str, str]] = {
    "89": {
        "OWASP Top 10": "A03:2021-Injection",
        "PCI-DSS v4.0": "Requirement 6.2.4",
        "SOC 2": "CC7.1",
        "ISO 27001": "A.8.28",
        "HIPAA": "164.306(a)",
    },
    "78": {
        "OWASP Top 10": "A03:2021-Injection",
        "PCI-DSS v4.0": "Requirement 6.2.4",
        "SOC 2": "CC7.1",
        "ISO 27001": "A.8.28",
        "HIPAA": "164.306(a)",
    },
    "79": {
        "OWASP Top 10": "A03:2021-Injection",
        "PCI-DSS v4.0": "Requirement 6.2.4",
        "SOC 2": "CC7.1",
        "ISO 27001": "A.8.28",
    },
    "798": {
        "OWASP Top 10": "A02:2021-Cryptographic Failures",
        "PCI-DSS v4.0": "Requirement 8.2",
        "SOC 2": "CC6.1",
        "ISO 27001": "A.8.20",
        "HIPAA": "164.312(a)(2)(iv)",
    },
    "22": {
        "OWASP Top 10": "A01:2021-Broken Access Control",
        "PCI-DSS v4.0": "Requirement 6.2.4",
        "SOC 2": "CC6.1",
        "ISO 27001": "A.8.28",
    },
    "918": {
        "OWASP Top 10": "A10:2021-Server-Side Request Forgery",
        "PCI-DSS v4.0": "Requirement 6.2.4",
        "SOC 2": "CC7.1",
        "ISO 27001": "A.8.28",
    },
    "502": {
        "OWASP Top 10": "A08:2021-Software and Data Integrity Failures",
        "PCI-DSS v4.0": "Requirement 6.2.4",
        "SOC 2": "CC7.1",
        "ISO 27001": "A.8.28",
    },
    "90": {
        "OWASP Top 10": "A03:2021-Injection",
        "PCI-DSS v4.0": "Requirement 6.2.4",
        "SOC 2": "CC7.1",
        "ISO 27001": "A.8.28",
    },
    "643": {
        "OWASP Top 10": "A03:2021-Injection",
        "PCI-DSS v4.0": "Requirement 6.2.4",
        "SOC 2": "CC7.1",
        "ISO 27001": "A.8.28",
    },
    "943": {
        "OWASP Top 10": "A03:2021-Injection",
        "PCI-DSS v4.0": "Requirement 6.2.4",
        "SOC 2": "CC7.1",
        "ISO 27001": "A.8.28",
    },
    "601": {
        "OWASP Top 10": "A01:2021-Broken Access Control",
        "PCI-DSS v4.0": "Requirement 6.2.4",
        "SOC 2": "CC6.1",
        "ISO 27001": "A.8.28",
    },
    "327": {
        "OWASP Top 10": "A02:2021-Cryptographic Failures",
        "PCI-DSS v4.0": "Requirement 6.2.1",
        "SOC 2": "CC6.1",
        "ISO 27001": "A.8.24",
        "HIPAA": "164.312(a)(2)(iv)",
    },
    "338": {
        "OWASP Top 10": "A02:2021-Cryptographic Failures",
        "PCI-DSS v4.0": "Requirement 6.2.1",
        "SOC 2": "CC6.1",
        "ISO 27001": "A.8.24",
    },
    "287": {
        "OWASP Top 10": "A07:2021-Identification and Authentication Failures",
        "PCI-DSS v4.0": "Requirement 8.1",
        "SOC 2": "CC6.1",
        "ISO 27001": "A.8.5",
        "HIPAA": "164.312(a)(1)",
    },
    "942": {
        "OWASP Top 10": "A05:2021-Security Misconfiguration",
        "PCI-DSS v4.0": "Requirement 2.2",
        "SOC 2": "CC6.3",
        "ISO 27001": "A.8.9",
        "HIPAA": "164.308(a)(1)(ii)",
    },
}


def get_compliance_mappings(cwe_id: str | int | None) -> dict[str, str]:
    """Get the compliance standards mapped to a specific CWE ID.

    Parameters
    ----------
    cwe_id:
        The CWE ID (e.g., "CWE-89", 89, or "89").

    Returns
    -------
    dict[str, str]
        A dictionary mapping compliance framework names to requirement/identifier codes.
    """
    if cwe_id is None:
        return {}

    # Normalize clean integer string representation
    cwe_str = str(cwe_id).upper().replace("CWE-", "").strip()
    return CWE_COMPLIANCE_MAP.get(cwe_str, {})
