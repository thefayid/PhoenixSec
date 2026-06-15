from __future__ import annotations

from phoenixsec.rules.command_injection import GoCommandInjectionRule, PhpCommandInjectionRule
from phoenixsec.rules.sqli import GoSQLiRule, PhpSQLiRule


def test_go_sqli_detection() -> None:
    code = """
package main
import "database/sql"
func get(db *sql.DB, id string) {
    query := "SELECT * FROM users WHERE id = " + id
    db.Query(query)
}
"""
    rule = GoSQLiRule()
    findings = rule.scan_all(code, "test.go")
    assert len(findings) == 1
    assert findings[0].line_number == 6
    assert findings[0].rule_id == "GO-SQLI-001"


def test_go_sqli_safe() -> None:
    code = """
package main
import "database/sql"
func get(db *sql.DB, id string) {
    db.Query("SELECT * FROM users WHERE id = ?", id)
}
"""
    rule = GoSQLiRule()
    findings = rule.scan_all(code, "test.go")
    assert len(findings) == 0


def test_php_sqli_detection() -> None:
    code = """
<?php
$query = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($conn, $query);
?>
"""
    rule = PhpSQLiRule()
    findings = rule.scan_all(code, "test.php")
    assert len(findings) == 1
    assert findings[0].line_number == 4
    assert findings[0].rule_id == "PHP-SQLI-001"


def test_php_sqli_safe() -> None:
    code = """
<?php
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("s", $id);
$stmt->execute();
?>
"""
    rule = PhpSQLiRule()
    findings = rule.scan_all(code, "test.php")
    assert len(findings) == 0


def test_go_cmd_injection_detection() -> None:
    code = """
package main
import "os/exec"
func run(cmd string) {
    exec.Command("sh", "-c", "ping -c 3 " + cmd)
}
"""
    rule = GoCommandInjectionRule()
    findings = rule.scan_all(code, "test.go")
    assert len(findings) == 1
    assert findings[0].line_number == 5
    assert findings[0].rule_id == "GO-CMD-001"


def test_go_cmd_injection_safe() -> None:
    code = """
package main
import "os/exec"
func run(cmd string) {
    exec.Command("ping", "-c", "3", cmd)
}
"""
    rule = GoCommandInjectionRule()
    findings = rule.scan_all(code, "test.go")
    assert len(findings) == 0


def test_php_cmd_injection_detection() -> None:
    code = """
<?php
system("ping -c 3 " . $host);
?>
"""
    rule = PhpCommandInjectionRule()
    findings = rule.scan_all(code, "test.php")
    assert len(findings) == 1
    assert findings[0].line_number == 3
    assert findings[0].rule_id == "PHP-CMD-001"


def test_php_cmd_injection_safe() -> None:
    code = """
<?php
system("ping -c 3 " . escapeshellarg($host));
?>
"""
    rule = PhpCommandInjectionRule()
    findings = rule.scan_all(code, "test.php")
    assert len(findings) == 0
