const vscode = require('vscode');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

let diagnosticCollection;
let scanTimeout = null;

function activate(context) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('phoenixsec');
    context.subscriptions.push(diagnosticCollection);

    // Real-Time As-You-Type "Vibe-Guard" Scan
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument((event) => {
            const document = event.document;
            if (isSupportedLanguage(document)) {
                // Debounce the real-time scan by 1000ms
                if (scanTimeout) {
                    clearTimeout(scanTimeout);
                }
                scanTimeout = setTimeout(() => {
                    runRealTimeScan(document);
                }, 1000);
            }
        })
    );

    // Also scan on save to ensure final state is captured
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument((document) => {
            if (isSupportedLanguage(document)) {
                runScan(document);
            }
        })
    );

    // Manual Scan Command
    let scanCommand = vscode.commands.registerCommand('phoenixsec.scan', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor && isSupportedLanguage(editor.document)) {
            runScan(editor.document);
        } else {
            vscode.window.showWarningMessage('Active file language is not supported by PhoenixSec.');
        }
    });
    context.subscriptions.push(scanCommand);

    // Apply Patch Command
    let fixCommand = vscode.commands.registerCommand('phoenixsec.applyFix', (documentUri) => {
        applyPatch(documentUri);
    });
    context.subscriptions.push(fixCommand);

    // Register QuickFix provider
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { scheme: 'file' },
            new PhoenixSecQuickFixProvider(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );
}

function isSupportedLanguage(document) {
    const ext = path.extname(document.fileName).toLowerCase();
    const supported = ['.py', '.pyw', '.java', '.js', '.jsx', '.ts', '.tsx', '.go', '.php', '.rb', '.tf'];
    return supported.includes(ext) || path.basename(document.fileName) === 'Dockerfile';
}

function runScan(document) {
    const filePath = document.fileName;
    exec(`phoenixsec scan "${filePath}" --format json`, (error, stdout, stderr) => {
        diagnosticCollection.set(document.uri, []); // clear old diagnostics

        if (stderr && stderr.includes('phoenixsec command not found')) {
            vscode.window.showErrorMessage('PhoenixSec command not found on PATH. Install it first.');
            return;
        }

        try {
            const data = JSON.parse(stdout);
            const findings = data.findings || [];
            const diagnostics = [];

            findings.forEach((finding) => {
                const line = Math.max(0, (finding.line_number || 1) - 1);
                const range = new vscode.Range(line, 0, line, 100);
                const severity = getDiagnosticSeverity(finding.severity);
                
                const diag = new vscode.Diagnostic(
                    range,
                    `[${finding.severity}] ${finding.vulnerability_type} (${finding.rule_id})\nRecommendation: ${finding.recommendation}`,
                    severity
                );
                diag.source = 'PhoenixSec';
                diag.code = finding.rule_id;
                diagnostics.push(diag);
            });

            diagnosticCollection.set(document.uri, diagnostics);

            if (diagnostics.length > 0) {
                vscode.window.showWarningMessage(`PhoenixSec detected ${diagnostics.length} vulnerabilities in ${path.basename(filePath)}.`);
            }

        } catch (e) {
            // No findings or invalid JSON output (clean run)
        }
    });
}

function runRealTimeScan(document) {
    const originalExt = path.extname(document.fileName);
    const tempFilePath = path.join(os.tmpdir(), `phoenixsec_${Date.now()}${originalExt}`);
    
    // Write the unsaved document content to the temp file
    try {
        fs.writeFileSync(tempFilePath, document.getText(), 'utf8');
    } catch (err) {
        console.error('Failed to write temp file for Vibe-Guard scan:', err);
        return;
    }

    // Execute scan on the temp file
    exec(`phoenixsec scan "${tempFilePath}" --format json`, (error, stdout, stderr) => {
        // Always clean up temp file
        try {
            if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);
        } catch (e) { /* ignore cleanup errors */ }

        diagnosticCollection.set(document.uri, []); // clear old diagnostics

        if (stderr && stderr.includes('phoenixsec command not found')) {
            return; // Don't spam warnings on every keystroke
        }

        try {
            const data = JSON.parse(stdout);
            const findings = data.findings || [];
            const diagnostics = [];

            findings.forEach((finding) => {
                const line = Math.max(0, (finding.line_number || 1) - 1);
                const range = new vscode.Range(line, 0, line, 100);
                const severity = getDiagnosticSeverity(finding.severity);
                
                const diag = new vscode.Diagnostic(
                    range,
                    `[${finding.severity}] ${finding.vulnerability_type} (${finding.rule_id})\nRecommendation: ${finding.recommendation}`,
                    severity
                );
                diag.source = 'PhoenixSec Vibe-Guard';
                diag.code = finding.rule_id;
                diagnostics.push(diag);
            });

            diagnosticCollection.set(document.uri, diagnostics);

        } catch (e) {
            // No findings or invalid JSON output (clean run)
        }
    });
}

function getDiagnosticSeverity(sevString) {
    switch (sevString) {
        case 'CRITICAL':
        case 'HIGH':
            return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM':
            return vscode.DiagnosticSeverity.Warning;
        case 'LOW':
        case 'INFO':
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}

function applyPatch(documentUri) {
    const filePath = documentUri.fsPath;
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "PhoenixSec: Applying AI security patch...",
        cancellable: false
    }, (progress) => {
        return new Promise((resolve, reject) => {
            exec(`phoenixsec scan "${filePath}" --patch --yes`, (error, stdout, stderr) => {
                if (error) {
                    vscode.window.showErrorMessage(`Failed to apply patch: ${stderr || error.message}`);
                    reject(error);
                } else {
                    vscode.window.showInformationMessage('Vulnerability successfully patched and verified!');
                    vscode.commands.executeCommand('workbench.action.files.revert');
                    resolve();
                }
            });
        });
    });
}

class PhoenixSecQuickFixProvider {
    provideCodeActions(document, range, context, token) {
        const diagnostics = context.diagnostics.filter(diag => diag.source === 'PhoenixSec');
        if (diagnostics.length === 0) {
            return [];
        }

        const action = new vscode.CodeAction('🛡️ Autofix with PhoenixSec', vscode.CodeActionKind.QuickFix);
        action.command = {
            command: 'phoenixsec.applyFix',
            title: 'Auto-patch File',
            arguments: [document.uri]
        };
        action.diagnostics = diagnostics;
        action.isPreferred = true;

        return [action];
    }
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
