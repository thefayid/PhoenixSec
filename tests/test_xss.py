from __future__ import annotations

import phoenixsec.rules.xss  # noqa: F401
from phoenixsec.models.finding import VulnerabilityType
from phoenixsec.rules.base_rule import RuleContext
from phoenixsec.rules.xss import JavaScriptXSSRule, PythonXSSRule


def test_python_xss_detection() -> None:
    code = """
def view(request):
    user_input = request.GET.get('name')
    return Markup(f"<h1>Hello {user_input}</h1>")
"""
    rule = PythonXSSRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.py", "python"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.XSS
    assert "Markup" in findings[0].sink


def test_python_xss_safe() -> None:
    code = """
def view():
    # Safe - using escape sanitisation to drop score below threshold
    val = escape("hello")
    return Markup(val)
"""
    rule = PythonXSSRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.py", "python"))
    assert len(findings) == 0


def test_js_xss_detection() -> None:
    code = """
app.get('/hello', (req, res) => {
    const name = req.query.name;
    document.getElementById('output').innerHTML = "Hello " + name;
});
"""
    rule = JavaScriptXSSRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.js", "javascript"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.XSS
    assert "innerHTML" in findings[0].sink


def test_js_xss_safe() -> None:
    code = """
app.get('/hello', (req, res) => {
    const name = req.query.name;
    document.getElementById('output').textContent = "Hello " + name;
});
"""
    rule = JavaScriptXSSRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.js", "javascript"))
    assert len(findings) == 0
