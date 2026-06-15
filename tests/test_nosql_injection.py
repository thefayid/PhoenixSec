def test_nosql_injection_python():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.nosql_injection import PythonNoSQLInjectionRule

    rule = PythonNoSQLInjectionRule()
    vuln_code = """
    user_input = request.args.get("user")
    query = {"$where": "this.username == '" + user_input + "'"}
    db.users.find(query)
    """
    ctx = RuleContext.from_code(vuln_code, "test.py", "python")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-NOSQL-PY-001"


def test_nosql_injection_javascript():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.nosql_injection import JavaScriptNoSQLInjectionRule

    rule = JavaScriptNoSQLInjectionRule()
    vuln_code = """
    const user_input = req.query.user;
    db.collection.find({ $where: "this.name == '" + user_input + "'" });
    """
    ctx = RuleContext.from_code(vuln_code, "test.js", "javascript")
    findings = rule.scan_context(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "PSEC-NOSQL-JS-001"
