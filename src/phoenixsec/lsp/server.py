import os
from pathlib import Path
from urllib.parse import unquote, urlparse

from lsprotocol.types import (
    TEXT_DOCUMENT_DID_CHANGE,
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_CODE_ACTION,
    WORKSPACE_EXECUTE_COMMAND,
    ApplyWorkspaceEditParams,
    CodeAction,
    CodeActionKind,
    CodeActionParams,
    Command,
    Diagnostic,
    DiagnosticSeverity,
    DidChangeTextDocumentParams,
    DidOpenTextDocumentParams,
    ExecuteCommandParams,
    Position,
    Range,
    TextEdit,
    WorkspaceEdit,
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
    document = ls.workspace.get_text_document(uri)
    _validate_document(uri, document.source)


@server.feature(TEXT_DOCUMENT_CODE_ACTION)
def code_action(ls: LanguageServer, params: CodeActionParams) -> list[CodeAction] | None:
    """Provide quick fixes for PhoenixSec diagnostics."""
    actions = []
    
    for diagnostic in params.context.diagnostics:
        if diagnostic.source == "PhoenixSec Vibe-Guard":
            # Return a command to be executed by the server
            action = CodeAction(
                title=f"PhoenixSec: Apply Auto-Fix for {diagnostic.code}",
                kind=CodeActionKind.QuickFix,
                diagnostics=[diagnostic],
                command=Command(
                    title="Apply AI Patch",
                    command="phoenixsec.applyFix",
                    arguments=[params.text_document.uri, diagnostic.code, diagnostic.range.start.line]
                )
            )
            actions.append(action)
            
    return actions


@server.feature(WORKSPACE_EXECUTE_COMMAND)
def execute_command(ls: LanguageServer, params: ExecuteCommandParams):
    """Handle custom commands (like applying patches)."""
    if params.command == "phoenixsec.applyFix":
        args = params.arguments
        if not args or len(args) < 3:
            return
            
        uri = args[0]
        rule_id = args[1]
        start_line = args[2]
        
        document = ls.workspace.get_text_document(uri)
        code_content = document.source
        file_path = uri_to_path(uri)
        
        # Re-scan to get the specific finding
        engine = RuleEngine()
        result = engine.scan_code(code=code_content, file_path=file_path)
        
        target_finding = None
        for f in result.findings:
            if f.rule_id == rule_id and max(0, (f.line_number or 1) - 1) == start_line:
                target_finding = f
                break
                
        if not target_finding:
            ls.show_message("Could not locate the finding in the current buffer.", 2)
            return
            
        ls.show_message(f"PhoenixSec is generating a patch for {rule_id}...")
        
        try:
            from phoenixsec.core.rule_based_patcher import RuleBasedPatcher
            from phoenixsec.core.ai_patcher import AIPatcher
            
            # Try rule-based first
            patcher = RuleBasedPatcher()
            patched_code = patcher.generate_patch(code_content, target_finding)
            
            # Fallback to AI
            if not patched_code:
                ai_patcher = AIPatcher(rule_engine=engine)
                patched_code = ai_patcher.generate_patch(code_content, target_finding)
                
            if patched_code and patched_code != code_content:
                lines = code_content.splitlines()
                last_line = max(0, len(lines) - 1)
                last_char = len(lines[-1]) if lines else 0
                
                edit = WorkspaceEdit(
                    changes={
                        uri: [
                            TextEdit(
                                range=Range(
                                    start=Position(line=0, character=0),
                                    end=Position(line=last_line, character=last_char)
                                ),
                                new_text=patched_code
                            )
                        ]
                    }
                )
                ls.apply_edit(edit)
                ls.show_message("PhoenixSec Auto-Fix applied successfully!")
            else:
                ls.show_message("PhoenixSec could not generate a safe patch for this issue.", 2)
                
        except Exception as e:
            log.error(f"Failed to generate patch: {e}")
            ls.show_message(f"PhoenixSec patch generation failed: {e}", 1)


def start() -> None:
    """Start the Language Server."""
    log.info("Starting PhoenixSec LSP Server on stdio...")
    server.start_io()
