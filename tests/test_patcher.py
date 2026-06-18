from __future__ import annotations

from phoenixsec.core.patcher import Patcher
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity


def test_patch_python_secrets_no_os_import() -> None:
    code = 'API_KEY = "sk-proj-123456789"\n'
    finding = Finding(
        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Store secrets in environment variables.",
        file_path="app/config.py",
        line_number=1,
    )

    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])

    expected = 'import os\nAPI_KEY = os.environ.get("API_KEY")\n'
    assert patched == expected
    assert changed == [1, 2]
    assert "replaced 1 hardcoded secret(s)" in summary


def test_patch_python_secrets_existing_os_import() -> None:
    code = 'import os\nAPI_KEY = "sk-proj-123456789"\n'
    finding = Finding(
        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Store secrets in environment variables.",
        file_path="app/config.py",
        line_number=2,
    )

    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])

    expected = 'import os\nAPI_KEY = os.environ.get("API_KEY")\n'
    assert patched == expected
    assert changed == [2]


def test_patch_java_secrets() -> None:
    code = 'public class Config {\n    private static final String API_KEY = "my-secret-key";\n}\n'
    finding = Finding(
        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Store secrets in environment variables.",
        file_path="Config.java",
        line_number=2,
    )

    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])

    expected = (
        "public class Config {\n"
        '    private static final String API_KEY = System.getenv("API_KEY");\n'
        "}\n"
    )
    assert patched == expected
    assert changed == [2]


def test_patch_python_sqli_direct() -> None:
    code = "cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")\n"
    finding = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Use parameterized queries.",
        file_path="db.py",
        line_number=1,
    )

    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])

    expected = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
    assert patched == expected
    assert changed == [1]


def test_patch_python_sqli_split() -> None:
    code = (
        "query = f\"SELECT * FROM users WHERE id = '{user_id}' AND status = {status}\"\n"
        "cursor.execute(query)\n"
    )
    finding = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Use parameterized queries.",
        file_path="db.py",
        line_number=2,
    )

    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])

    expected = (
        'query = "SELECT * FROM users WHERE id = ? AND status = ?"\n'
        "cursor.execute(query, (user_id, status))\n"
    )
    assert patched == expected
    assert changed == [1, 2]


def test_patch_java_sqli() -> None:
    code = (
        "Statement stmt = conn.createStatement();\n"
        'String query = "SELECT * FROM users WHERE username = \'" + userInput + "\'";\n'
        "ResultSet rs = stmt.executeQuery(query);\n"
    )
    finding = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Use prepared statements.",
        file_path="SQLi.java",
        line_number=3,
    )

    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])

    expected = (
        "// Statement stmt = conn.createStatement();\n"
        'String query = "SELECT * FROM users WHERE username = ?";\n'
        "PreparedStatement pstmt = conn.prepareStatement(query);\n"
        "pstmt.setString(1, userInput);\n"
        "ResultSet rs = pstmt.executeQuery();\n"
    )
    assert patched == expected
    assert changed == [1, 2, 3]


def test_patch_multiple_findings() -> None:
    # Python file with multiple secrets
    code = 'DB_PASS = "admin_pwd"\nAUTH_TOKEN = "jwt_token_123"\n'
    f1 = Finding(
        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Store secrets in env vars.",
        file_path="settings.py",
        line_number=1,
    )
    f2 = Finding(
        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Store secrets in env vars.",
        file_path="settings.py",
        line_number=2,
    )

    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [f1, f2])

    expected = (
        "import os\n"
        'DB_PASS = os.environ.get("DB_PASS")\n'
        'AUTH_TOKEN = os.environ.get("AUTH_TOKEN")\n'
    )
    assert patched == expected
    assert changed == [1, 2, 3]
    assert "replaced 2 hardcoded secret(s)" in summary


def test_patch_python_xss() -> None:
    code = 'html_content = Markup(f"<h1>Hello {name}</h1>")\n'
    finding = Finding(
        vulnerability_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        confidence_score=1.0,
        recommendation="Escape XSS.",
        file_path="app/views.py",
        line_number=1,
    )
    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])
    expected = 'import html\nhtml_content = html.escape(f"<h1>Hello {name}</h1>")\n'
    assert patched == expected
    assert changed == [1, 2]
    assert "escaped/remediated 1 XSS" in summary


def test_patch_python_ssrf() -> None:
    code = "response = requests.get(url)\n"
    finding = Finding(
        vulnerability_type=VulnerabilityType.SSRF,
        severity=Severity.HIGH,
        confidence_score=1.0,
        recommendation="Validate URL.",
        file_path="app/client.py",
        line_number=1,
    )
    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])
    expected = 'if not url.startswith(("http://example.com", "https://example.com")): raise ValueError("Forbidden URL")\nresponse = requests.get(url)\n'
    assert patched == expected
    assert changed == [1]
    assert "added allowlist validation to 1 SSRF" in summary


def test_patch_python_path_traversal() -> None:
    code = 'with open(filename, "r") as f:\n    pass\n'
    finding = Finding(
        vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        confidence_score=1.0,
        recommendation="Sanitize path.",
        file_path="app/utils.py",
        line_number=1,
    )
    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])
    expected = 'from werkzeug.utils import secure_filename\nwith open(secure_filename(filename), "r") as f:\n    pass\n'
    assert patched == expected
    assert changed == [1, 2]
    assert "sanitized 1 path traversal" in summary


def test_patch_python_deserialization() -> None:
    code = "obj = pickle.loads(data)\n"
    finding = Finding(
        vulnerability_type=VulnerabilityType.INSECURE_DESERIALIZATION,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Use safe serialization formats.",
        file_path="app/worker.py",
        line_number=1,
    )
    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])
    expected = "import json\nobj = json.loads(data)\n"
    assert patched == expected
    assert changed == [1, 2]
    assert "secured 1 deserialization" in summary


def test_patch_sqli_and_secret_on_same_line() -> None:
    code = (
        "query = f\"SELECT * FROM users WHERE username='{username}' AND password='{password}'\"\n"
        "cursor.execute(query)\n"
    )
    # SQL injection on line 2
    f_sqli = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Use parameterized queries.",
        file_path="app.py",
        line_number=2,
        rule_id="PY-SQLI-001",
    )
    # False positive secret on line 1
    f_secret = Finding(
        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Store secrets in environment variables.",
        file_path="app.py",
        line_number=1,
        rule_id="ALL-SEC-001",
    )

    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [f_sqli, f_secret])

    # Result should parameterize the query (SQLi patch) and SKIP the secret patch on line 1.
    expected = (
        'query = "SELECT * FROM users WHERE username=? AND password=?"\n'
        "cursor.execute(query, (username, password))\n"
    )
    assert patched == expected
    assert "replaced" not in summary  # no secrets replaced
    assert "parameterised 1 SQL injection" in summary


def test_patch_python_csrf() -> None:
    code = "app.config['WTF_CSRF_ENABLED'] = False\n"
    finding = Finding(
        vulnerability_type=VulnerabilityType.CSRF,
        severity=Severity.HIGH,
        confidence_score=1.0,
        recommendation="Enable CSRF",
        file_path="app.py",
        line_number=1,
    )
    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])
    expected = "app.config['WTF_CSRF_ENABLED'] = True\n"
    assert patched == expected
    assert changed == [1]
    assert "enabled CSRF protection" in summary


def test_patch_java_xxe() -> None:
    code = (
        "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
        "DocumentBuilder db = dbf.newDocumentBuilder();\n"
    )
    finding = Finding(
        vulnerability_type=VulnerabilityType.XXE,
        severity=Severity.HIGH,
        confidence_score=1.0,
        recommendation="Disable DTDs",
        file_path="XML.java",
        line_number=1,
    )
    patcher = Patcher()
    patched, summary, changed = patcher.patch(code, [finding])
    expected = (
        "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
        'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
        "DocumentBuilder db = dbf.newDocumentBuilder();\n"
    )
    assert patched == expected
    assert changed == [1]
    assert "disabled XML external entities" in summary
