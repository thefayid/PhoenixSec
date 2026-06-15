def test_open_redirect_python():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.open_redirect import PythonOpenRedirectRule

    rule = PythonOpenRedirectRule()
    vuln_code = """
    target_url = request.args.get("next")
    redirect(target_url)
    """
    ctx = RuleContext.from_code(vuln_code, "test.py", "python")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-REDIR-PY-001"

    safe_code = """
    url = "/dashboard"
    if is_safe_url(url):
        redirect(url)
    """
    ctx = RuleContext.from_code(safe_code, "test.py", "python")
    findings = rule.scan_context(ctx)
    assert len(findings) == 0


def test_open_redirect_javascript():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.open_redirect import JavaScriptOpenRedirectRule

    rule = JavaScriptOpenRedirectRule()
    vuln_code = """
    const target = req.query.url;
    res.redirect(target);
    """
    ctx = RuleContext.from_code(vuln_code, "test.js", "javascript")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-REDIR-JS-001"


def test_open_redirect_java():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.open_redirect import JavaOpenRedirectRule

    rule = JavaOpenRedirectRule()
    vuln_code = """
    String next = request.getParameter("next");
    response.sendRedirect(next);
    """
    ctx = RuleContext.from_code(vuln_code, "Test.java", "java")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-REDIR-JAVA-001"
