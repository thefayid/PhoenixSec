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
