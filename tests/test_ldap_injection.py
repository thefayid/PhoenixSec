def test_ldap_injection_python():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.ldap_injection import PythonLDAPInjectionRule

    rule = PythonLDAPInjectionRule()
    vuln_code = """
    user_input = request.args.get("user")
    filter_str = f"(uid={user_input})"
    ldap.search("dc=example,dc=com", scope, filter_str)
    """
    ctx = RuleContext.from_code(vuln_code, "test.py", "python")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-LDAP-PY-001"

    safe_code = """
    user_input = request.args.get("user")
    filter_str = f"(uid={ldap.filter.escape_filter_chars(user_input)})"
    ldap.search("dc=example,dc=com", scope, filter_str)
    """
    ctx = RuleContext.from_code(safe_code, "test.py", "python")
    findings = rule.scan_context(ctx)
    assert len(findings) == 0


def test_ldap_injection_javascript():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.ldap_injection import JavaScriptLDAPInjectionRule

    rule = JavaScriptLDAPInjectionRule()
    vuln_code = """
    const filter = '(|(uid=' + req.query.user + '))';
    client.search('o=myorg', filter, (err, res) => {});
    """
    ctx = RuleContext.from_code(vuln_code, "test.js", "javascript")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-LDAP-JS-001"

    safe_code = """
    const filter = '(|(uid=' + escape(req.query.user) + '))';
    client.search('o=myorg', filter, (err, res) => {});
    """
    ctx = RuleContext.from_code(safe_code, "test.js", "javascript")
    findings = rule.scan_context(ctx)
    assert len(findings) == 0


def test_ldap_injection_java():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.ldap_injection import JavaLDAPInjectionRule

    rule = JavaLDAPInjectionRule()
    vuln_code = """
    String filter = "(uid=" + request.getParameter("user") + ")";
    InitialDirContext.search("ou=people", filter, controls);
    """
    ctx = RuleContext.from_code(vuln_code, "Test.java", "java")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-LDAP-JAVA-001"
