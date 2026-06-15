from __future__ import annotations

import phoenixsec.rules.path_traversal  # noqa: F401
from phoenixsec.models.finding import VulnerabilityType
from phoenixsec.rules.base_rule import RuleContext
from phoenixsec.rules.path_traversal import (
    JavaPathTraversalRule,
    JavaScriptPathTraversalRule,
    PythonPathTraversalRule,
)


def test_python_path_traversal_detection() -> None:
    code = """
def download(request):
    filename = request.GET.get('file')
    with open(filename, 'r') as f:
        return f.read()
"""
    rule = PythonPathTraversalRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.py", "python"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.PATH_TRAVERSAL
    assert "open" in findings[0].sink


def test_python_path_traversal_safe() -> None:
    code = """
def download():
    # Safe - active secure_filename validation drops score below threshold
    filename = secure_filename("default_config.txt")
    with open(filename, 'r') as f:
        return f.read()
"""
    rule = PythonPathTraversalRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.py", "python"))
    assert len(findings) == 0


def test_js_path_traversal_detection() -> None:
    code = """
app.get('/download', (req, res) => {
    const file = req.query.file;
    fs.readFile(file, 'utf8', (err, data) => {
        res.send(data);
    });
});
"""
    rule = JavaScriptPathTraversalRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.js", "javascript"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.PATH_TRAVERSAL
    assert "readFile" in findings[0].sink


def test_js_path_traversal_safe() -> None:
    code = """
app.get('/download', (req, res) => {
    // Safe - path.resolve provides safety signal without triggering require() sink
    const safePath = path.resolve('welcome.txt');
    fs.readFile(safePath, 'utf8', (err, data) => {
        res.send(data);
    });
});
"""
    rule = JavaScriptPathTraversalRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.js", "javascript"))
    assert len(findings) == 0


def test_java_path_traversal_detection() -> None:
    code = """
public void downloadFile(HttpServletRequest request) {
    String filename = request.getParameter("file");
    File file = new File(filename);
}
"""
    rule = JavaPathTraversalRule()
    findings = rule.scan_context(RuleContext.from_code(code, "Test.java", "java"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.PATH_TRAVERSAL
    assert "File" in findings[0].sink
