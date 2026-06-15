def test_misconfiguration_python():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.misconfiguration import PythonSecurityMisconfigurationRule

    rule = PythonSecurityMisconfigurationRule()
    vuln_code_debug = """
    DEBUG = True
    """
    ctx = RuleContext.from_code(vuln_code_debug, "settings.py", "python")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-2"

    vuln_code_cors = """
    allow_origins=["*"], allow_credentials=True
    """
    ctx2 = RuleContext.from_code(vuln_code_cors, "app.py", "python")
    findings2 = rule.scan_context(ctx2)
    assert len(findings2) == 1
    assert findings2[0].cwe_id == "CWE-942"


def test_misconfiguration_javascript():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.misconfiguration import JavaScriptSecurityMisconfigurationRule

    rule = JavaScriptSecurityMisconfigurationRule()
    vuln_code_listen = """
    app.listen(port, "0.0.0.0");
    """
    ctx = RuleContext.from_code(vuln_code_listen, "server.js", "javascript")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-2"
