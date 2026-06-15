def test_broken_auth_python():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.broken_auth import PythonBrokenAuthRule

    rule = PythonBrokenAuthRule()
    vuln_code_jwt = """
    payload = jwt.decode(token, verify=False, algorithms=['HS256'])
    """
    ctx = RuleContext.from_code(vuln_code_jwt, "test.py", "python")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-347"

    vuln_code_eq = """
    if password == input_pass:
        auth_success()
    """
    ctx2 = RuleContext.from_code(vuln_code_eq, "test.py", "python")
    findings2 = rule.scan_context(ctx2)
    assert len(findings2) == 1
    assert findings2[0].cwe_id == "CWE-208"


def test_broken_auth_javascript():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.broken_auth import JavaScriptBrokenAuthRule

    rule = JavaScriptBrokenAuthRule()
    vuln_code = """
    jwt.verify(token, { ignoreExpiration: true });
    """
    ctx = RuleContext.from_code(vuln_code, "test.js", "javascript")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-347"
