from __future__ import annotations

import phoenixsec.rules.ssrf  # noqa: F401
from phoenixsec.models.finding import VulnerabilityType
from phoenixsec.rules.base_rule import RuleContext
from phoenixsec.rules.ssrf import (
    JavaScriptSSRFRule,
    JavaSSRFRule,
    PythonSSRFRule,
)


def test_python_ssrf_detection() -> None:
    code = """
def fetch_url(request):
    url = request.GET.get('url')
    response = requests.get(url)
    return response.text
"""
    rule = PythonSSRFRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.py", "python"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.SSRF
    assert "requests" in findings[0].sink


def test_python_ssrf_safe() -> None:
    code = """
def fetch_url():
    # Safe - startswith allowlist check provides safety signal to drop score
    url = "https://safe.example.com/api"
    if url.startswith("https://"):
        response = requests.get(url)
        return response.text
"""
    rule = PythonSSRFRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.py", "python"))
    assert len(findings) == 0


def test_js_ssrf_detection() -> None:
    code = """
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const response = await fetch(url);
    res.send(await response.text());
});
"""
    rule = JavaScriptSSRFRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.js", "javascript"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.SSRF
    assert "fetch" in findings[0].sink


def test_js_ssrf_safe() -> None:
    code = """
app.get('/fetch', async (req, res) => {
    const url = "https://safe.example.com/api";
    // Safe - startsWith allowlist check provides safety signal
    if (url.startsWith("https://")) {
        const response = await fetch(url);
        res.send(await response.text());
    }
});
"""
    rule = JavaScriptSSRFRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.js", "javascript"))
    assert len(findings) == 0


def test_java_ssrf_detection() -> None:
    code = """
public void fetchUrl(HttpServletRequest request) throws Exception {
    String target = request.getParameter("url");
    URL url = new URL(target);
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
}
"""
    rule = JavaSSRFRule()
    findings = rule.scan_context(RuleContext.from_code(code, "Test.java", "java"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.SSRF
    assert "URL" in findings[0].sink
