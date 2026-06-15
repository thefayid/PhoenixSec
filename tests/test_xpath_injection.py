def test_xpath_injection_python():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.xpath_injection import PythonXPathInjectionRule

    rule = PythonXPathInjectionRule()
    vuln_code = """
    user_input = request.args.get("user")
    expr = f"//user[username/text()='{user_input}']"
    root.xpath(expr)
    """
    ctx = RuleContext.from_code(vuln_code, "test.py", "python")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-XPATH-PY-001"


def test_xpath_injection_javascript():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.xpath_injection import JavaScriptXPathInjectionRule

    rule = JavaScriptXPathInjectionRule()
    vuln_code = """
    const expr = "//user[username/text()='" + req.query.user + "']";
    xpath.select(expr, doc);
    """
    ctx = RuleContext.from_code(vuln_code, "test.js", "javascript")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-XPATH-JS-001"


def test_xpath_injection_java():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.xpath_injection import JavaXPathInjectionRule

    rule = JavaXPathInjectionRule()
    vuln_code = """
    String expr = "//user[username/text()='" + request.getParameter("user") + "']";
    XPath.evaluate(expr, doc);
    """
    ctx = RuleContext.from_code(vuln_code, "Test.java", "java")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-XPATH-JAVA-001"
