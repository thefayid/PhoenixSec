def test_weak_crypto_python():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.weak_crypto import PythonWeakCryptoRule

    rule = PythonWeakCryptoRule()
    vuln_code = """
    import hashlib
    h = hashlib.md5(data)
    r = random.random()
    """
    ctx = RuleContext.from_code(vuln_code, "test.py", "python")
    findings = rule.scan_context(ctx)
    assert len(findings) == 2
    assert any(f.cwe_id == "CWE-327" for f in findings)
    assert any(f.cwe_id == "CWE-338" for f in findings)


def test_weak_crypto_javascript():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.weak_crypto import JavaScriptWeakCryptoRule

    rule = JavaScriptWeakCryptoRule()
    vuln_code = """
    const hash = crypto.createHash("md5");
    const rand = Math.random();
    """
    ctx = RuleContext.from_code(vuln_code, "test.js", "javascript")
    findings = rule.scan_context(ctx)
    assert len(findings) == 2
    assert any(f.cwe_id == "CWE-327" for f in findings)
    assert any(f.cwe_id == "CWE-338" for f in findings)


def test_weak_crypto_java():
    from phoenixsec.rules.base_rule import RuleContext
    from phoenixsec.rules.weak_crypto import JavaWeakCryptoRule

    rule = JavaWeakCryptoRule()
    vuln_code = """
    MessageDigest md = MessageDigest.getInstance("MD5");
    Cipher c = Cipher.getInstance("DES");
    """
    ctx = RuleContext.from_code(vuln_code, "Test.java", "java")
    findings = rule.scan_context(ctx)
    assert len(findings) == 2
    assert all(f.cwe_id == "CWE-327" for f in findings)
