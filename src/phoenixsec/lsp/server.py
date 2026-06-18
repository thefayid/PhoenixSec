import os
from pathlib import Path
from urllib.parse import unquote, urlparse

from lsprotocol.types import (
    TEXT_DOCUMENT_DID_CHANGE,
    TEXT_DOCUMENT_DID_OPEN,
    Diagnostic,
    DiagnosticSeverity,
    DidChangeTextDocumentParams,
    DidOpenTextDocumentParams,
    Position,
    Range,
)
from pygls.lsp.server import LanguageServer

from phoenixsec.core.logger import get_logger
from phoenixsec.models.vulnerability import Severity as PhoenixSeverity
from phoenixsec.rules.engine import RuleEngine

log = get_logger(__name__)

server = LanguageServer("phoenixsec-lsp", "0.1.0")


def uri_to_path(uri: str) -> str:
    """Convert a file URI to an absolute OS path."""
    parsed = urlparse(uri)
    path = unquote(parsed.path)
    # Handle Windows paths (e.g. /C:/path -> C:/path)
    if os.name == "nt" and path.startswith("/") and len(path) > 2 and path[2] == ":":
        path = path[1:]
    return path


def _map_severity(severity: PhoenixSeverity) -> DiagnosticSeverity:
    """Map PhoenixSec severity to LSP diagnostic severity."""
    if severity in (PhoenixSeverity.CRITICAL, PhoenixSeverity.HIGH):
        return DiagnosticSeverity.Error
    elif severity == PhoenixSeverity.MEDIUM:
        return DiagnosticSeverity.Warning
    else:
        return DiagnosticSeverity.Information


def _validate_document(uri: str, text: str) -> None:
    """Run PhoenixSec RuleEngine on the current text and publish diagnostics."""
    file_path = uri_to_path(uri)
    
    # Simple language inference based on extension
    ext = Path(file_path).suffix.lower()
    lang_map = {
        ".py": "python",
        ".pyw": "python",
        ".java": "java",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".go": "go",
        ".php": "php",
        ".rb": "ruby",
        ".tf": "terraform"
    }
    language = lang_map.get(ext, "unknown")
    
    # We always run the engine, even if language is unknown, because some rules are language-agnostic
    engine = RuleEngine()
    result = engine.scan_code(code=text, file_path=file_path, language=language)

    diagnostics = []
    for finding in result.findings:
        # LSP positions are 0-indexed
        line = max(0, (finding.line_number or 1) - 1)
        
        diagnostic = Diagnostic(
            range=Range(
                start=Position(line=line, character=0),
                end=Position(line=line, character=200),  # Highlight entire line roughly
            ),
            message=f"[{finding.severity.value}] {finding.vulnerability_type.value} ({finding.rule_id})\nRecommendation: {finding.recommendation}",
            severity=_map_severity(finding.severity),
            source="PhoenixSec Vibe-Guard",
            code=finding.rule_id,
        )
        diagnostics.append(diagnostic)

    # Publish diagnostics to the client
    server.text_document_publish_diagnostics(uri, diagnostics)


@server.feature(TEXT_DOCUMENT_DID_OPEN)
def did_open(ls: LanguageServer, params: DidOpenTextDocumentParams):
    """Handle textDocument/didOpen."""
    uri = params.text_document.uri
    text = params.text_document.text
    _validate_document(uri, text)


@server.feature(TEXT_DOCUMENT_DID_CHANGE)
def did_change(ls: LanguageServer, params: DidChangeTextDocumentParams):
    """Handle textDocument/didChange."""
    uri = params.text_document.uri
    # For full sync we can get the entire document text directly from the server's workspace
    document = ls.workspace.get_text_document(uri)
    _validate_document(uri, document.source)


def start() -> None:
    """Start the Language Server."""
    log.info("Starting PhoenixSec LSP Server on stdio...")
    server.start_io()
