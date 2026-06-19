import pytest
from unittest.mock import Mock, patch

from lsprotocol.types import (
    DidChangeTextDocumentParams,
    DidOpenTextDocumentParams,
    TextDocumentItem,
    VersionedTextDocumentIdentifier,
    DiagnosticSeverity
)

from phoenixsec.lsp.server import did_open, did_change, uri_to_path, _map_severity
from phoenixsec.models.vulnerability import Severity


def test_uri_to_path() -> None:
    # Test standard UNIX path
    assert uri_to_path("file:///home/user/code.py") == "/home/user/code.py"
    # Test Windows path conversion if needed (e.g., removing leading slash from C:)
    import os
    if os.name == "nt":
        assert uri_to_path("file:///C:/Users/user/code.py") == "C:/Users/user/code.py"


def test_map_severity() -> None:
    assert _map_severity(Severity.CRITICAL) == DiagnosticSeverity.Error
    assert _map_severity(Severity.HIGH) == DiagnosticSeverity.Error
    assert _map_severity(Severity.MEDIUM) == DiagnosticSeverity.Warning
    assert _map_severity(Severity.LOW) == DiagnosticSeverity.Information
    assert _map_severity(Severity.INFO) == DiagnosticSeverity.Information


@patch("phoenixsec.lsp.server.server.text_document_publish_diagnostics")
def test_lsp_did_open(mock_publish) -> None:
    code = "import os\nfrom flask import request\ncmd = request.args.get('cmd')\nos.system(cmd)\n"
    params = DidOpenTextDocumentParams(
        text_document=TextDocumentItem(
            uri="file:///test/vulnerable.py",
            language_id="python",
            version=1,
            text=code
        )
    )
    # Call the event handler directly (bypassing full LSP network stack)
    did_open(Mock(), params)
    
    mock_publish.assert_called_once()
    args, kwargs = mock_publish.call_args
    assert args[0] == "file:///test/vulnerable.py"
    diagnostics = args[1]
    assert len(diagnostics) > 0
    assert any("Command Injection" in diag.message for diag in diagnostics)


@patch("phoenixsec.lsp.server.server.text_document_publish_diagnostics")
def test_lsp_did_change(mock_publish) -> None:
    code = "import sqlite3\nconn.execute(f'SELECT * FROM users WHERE id={user_id}')\n"
    params = DidChangeTextDocumentParams(
        text_document=VersionedTextDocumentIdentifier(
            uri="file:///test/sqli.py",
            version=2
        ),
        content_changes=[]
    )
    
    # Mock the workspace document retrieval
    mock_ls = Mock()
    mock_doc = Mock()
    mock_doc.source = code
    mock_ls.workspace.get_text_document.return_value = mock_doc
    
    did_change(mock_ls, params)
    
    mock_publish.assert_called_once()
    args, kwargs = mock_publish.call_args
    diagnostics = args[1]
    assert len(diagnostics) > 0
    assert any("SQL Injection" in diag.message for diag in diagnostics)


def test_lsp_code_action() -> None:
    from lsprotocol.types import CodeActionParams, CodeActionContext, Diagnostic, Range, Position, CodeActionKind
    
    diag = Diagnostic(
        range=Range(start=Position(line=1, character=0), end=Position(line=1, character=20)),
        message="Test SQLi",
        source="PhoenixSec Vibe-Guard",
        code="PSEC-SQLI-001"
    )
    
    params = CodeActionParams(
        text_document=TextDocumentItem(
            uri="file:///test/sqli.py",
            language_id="python",
            version=1,
            text=""
        ),
        range=Range(start=Position(line=1, character=0), end=Position(line=1, character=20)),
        context=CodeActionContext(diagnostics=[diag])
    )
    
    from phoenixsec.lsp.server import code_action
    actions = code_action(Mock(), params)
    
    assert actions is not None
    assert len(actions) == 1
    assert actions[0].kind == CodeActionKind.QuickFix
    assert actions[0].command.command == "phoenixsec.applyFix"
    assert actions[0].command.arguments[1] == "PSEC-SQLI-001"


def test_lsp_execute_command_rule_based() -> None:
    from lsprotocol.types import ExecuteCommandParams
    from phoenixsec.lsp.server import execute_command

    code = "my_secret = 'sk-proj-1234567890abcdef1234567890abcdef12345678'\n"
    uri = "file:///test/secrets.py"

    mock_ls = Mock()
    mock_doc = Mock()
    mock_doc.source = code
    mock_ls.workspace.get_text_document.return_value = mock_doc

    params = ExecuteCommandParams(
        command="phoenixsec.applyFix",
        arguments=[uri, "ALL-SEC-001", 0]
    )

    with patch("phoenixsec.lsp.server.RuleEngine") as mock_engine_cls:
        from phoenixsec.models.finding import Finding, VulnerabilityType
        from phoenixsec.models.vulnerability import Severity
        mock_engine = Mock()
        mock_res = Mock()
        mock_finding = Finding(
            rule_id="ALL-SEC-001",
            vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
            severity=Severity.CRITICAL,
            confidence_score=0.9,
            recommendation="Use environment variables",
            file_path="/test/secrets.py",
            line_number=1,
            code_snippet="my_secret = 'sk-proj-1234567890abcdef1234567890abcdef12345678'"
        )
        mock_res.findings = [mock_finding]
        mock_engine.scan_code.return_value = mock_res
        mock_engine_cls.return_value = mock_engine

        execute_command(mock_ls, params)

        mock_ls.apply_edit.assert_called_once()
        edit_args = mock_ls.apply_edit.call_args[0][0]
        assert uri in edit_args.changes
        new_text = edit_args.changes[uri][0].new_text
        assert "os.environ.get" in new_text
        mock_ls.show_message.assert_any_call("PhoenixSec Auto-Fix applied successfully!")


@patch("phoenixsec.core.ai_patcher.AIPatcher")
def test_lsp_execute_command_ai_fallback(mock_ai_patcher_cls) -> None:
    from lsprotocol.types import ExecuteCommandParams
    from phoenixsec.lsp.server import execute_command

    code = "some_vulnerable_code_here\n"
    uri = "file:///test/other.py"

    mock_ai_patcher = Mock()
    mock_ai_patcher.generate_patch.return_value = "patched_by_ai_code"
    mock_ai_patcher_cls.return_value = mock_ai_patcher

    mock_ls = Mock()
    mock_doc = Mock()
    mock_doc.source = code
    mock_ls.workspace.get_text_document.return_value = mock_doc

    params = ExecuteCommandParams(
        command="phoenixsec.applyFix",
        arguments=[uri, "SOME-RULE-001", 0]
    )

    with patch("phoenixsec.lsp.server.RuleEngine") as mock_engine_cls:
        from phoenixsec.models.finding import Finding, VulnerabilityType
        from phoenixsec.models.vulnerability import Severity
        mock_engine = Mock()
        mock_res = Mock()
        mock_finding = Finding(
            rule_id="SOME-RULE-001",
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            confidence_score=0.9,
            recommendation="Fix it",
            file_path="/test/other.py",
            line_number=1,
            code_snippet="some_vulnerable_code_here"
        )
        mock_res.findings = [mock_finding]
        mock_engine.scan_code.return_value = mock_res
        mock_engine_cls.return_value = mock_engine

        execute_command(mock_ls, params)

        mock_ls.apply_edit.assert_called_once()
        edit_args = mock_ls.apply_edit.call_args[0][0]
        assert uri in edit_args.changes
        assert edit_args.changes[uri][0].new_text == "patched_by_ai_code"
        mock_ls.show_message.assert_any_call("PhoenixSec Auto-Fix applied successfully!")


def test_lsp_language_detection_expanded() -> None:
    from phoenixsec.lsp.server import _validate_document
    # Mock text document publish diagnostics to verify
    # language is detected properly by the engine scan
    with patch("phoenixsec.lsp.server.server.text_document_publish_diagnostics") as mock_publish:
        with patch("phoenixsec.lsp.server.RuleEngine.scan_code") as mock_scan:
            mock_scan.return_value.findings = []
            
            # Test .rs -> rust
            _validate_document("file:///test/main.rs", "fn main() {}")
            mock_scan.assert_called_with(code="fn main() {}", file_path="/test/main.rs", language="rust")

            # Test .kt -> kotlin
            _validate_document("file:///test/main.kt", "fun main() {}")
            mock_scan.assert_called_with(code="fun main() {}", file_path="/test/main.kt", language="kotlin")


@patch("phoenixsec.lsp.server.server.text_document_publish_diagnostics")
def test_lsp_diagnostics_dynamic_line_len(mock_publish) -> None:
    # A short line should highlight precisely the line's character length, not 200
    code = "import os\nfrom flask import request\ncmd = request.args.get('cmd')\nos.system(cmd)\n"
    # Line index 3 (0-indexed line 3) is "os.system(cmd)" which has length 14
    params = DidOpenTextDocumentParams(
        text_document=TextDocumentItem(
            uri="file:///test/vulnerable.py",
            language_id="python",
            version=1,
            text=code
        )
    )
    did_open(Mock(), params)
    
    mock_publish.assert_called_once()
    diagnostics = mock_publish.call_args[0][1]
    assert len(diagnostics) > 0
    found = False
    for diag in diagnostics:
        if diag.range.start.line == 3:
            assert diag.range.end.character == 14
            found = True
    assert found


