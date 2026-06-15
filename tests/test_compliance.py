from phoenixsec.core.compliance import get_compliance_mappings
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity


def test_compliance_mapping_resolution():
    # Test valid mapping
    mappings = get_compliance_mappings("89")
    assert mappings["OWASP Top 10"] == "A03:2021-Injection"
    assert mappings["PCI-DSS v4.0"] == "Requirement 6.2.4"
    assert mappings["SOC 2"] == "CC7.1"
    assert mappings["ISO 27001"] == "A.8.28"
    assert mappings["HIPAA"] == "164.306(a)"

    # Test case insensitive and CWE prefix strip
    mappings_cwe = get_compliance_mappings("CWE-89")
    assert mappings_cwe == mappings

    mappings_int = get_compliance_mappings(89)
    assert mappings_int == mappings

    # Test unknown CWE
    assert get_compliance_mappings("CWE-999") == {}
    assert get_compliance_mappings(None) == {}


def test_finding_to_dict_includes_compliance():
    finding = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=0.9,
        recommendation="Use parameterized queries",
        file_path="app.py",
        cwe_id="CWE-89",
    )
    d = finding.to_dict()
    assert "compliance" in d
    assert d["compliance"]["OWASP Top 10"] == "A03:2021-Injection"
