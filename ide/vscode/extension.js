const vscode = require('vscode');
const cp = require('child_process');
const path = require('path');

let diagnosticCollection;

function activate(context) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('phoenixsec');
    context.subscriptions.push(diagnosticCollection);

    // Register scan command
    let scanCommand = vscode.commands.registerCommand('phoenixsec.scan', function () {
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor) {
            runScan(activeEditor.document);
        }
    });
    context.subscriptions.push(scanCommand);

    // Scan on save and open
    vscode.workspace.onDidSaveTextDocument(document => runScan(document), null, context.subscriptions);
    vscode.workspace.onDidOpenTextDocument(document => runScan(document), null, context.subscriptions);

    // Initial scan of active editor
    if (vscode.window.activeTextEditor) {
        runScan(vscode.window.activeTextEditor.document);
    }
}

function runScan(document) {
    const supportedExts = ['.py', '.java', '.js', '.jsx', '.ts', '.tsx', '.go', '.php', '.rb'];
    const ext = path.extname(document.fileName).toLowerCase();
    if (!supportedExts.includes(ext)) {
        return;
    }

    const config = vscode.workspace.getConfiguration('phoenixsec');
    const executable = config.get('executablePath') || 'phoenixsec';
    const severity = config.get('severity') || 'LOW';

    const args = [
        'scan',
        document.fileName,
        '--format', 'json',
        '--severity', severity
    ];

    cp.execFile(executable, args, (error, stdout, stderr) => {
        // Clear old diagnostics for this file
        diagnosticCollection.delete(document.uri);

        if (error && error.code !== 1) {
            // Error code 1 means vulnerabilities found, which is expected.
            // Other codes mean tool execution failed.
            console.error(`PhoenixSec scan execution failed: ${stderr || error.message}`);
            return;
        }

        try {
            // Find start of JSON
            const jsonStart = stdout.indexOf('{');
            if (jsonStart === -1) return;
            const report = JSON.parse(stdout.substring(jsonStart));
            const findings = report.findings || [];

            const diagnostics = findings.map(finding => {
                const line = Math.max(0, (finding.line_number || 1) - 1);
                // Highlight the line
                const range = new vscode.Range(
                    new vscode.Position(line, 0),
                    new vscode.Position(line, 80)
                );

                const severityMap = {
                    'CRITICAL': vscode.DiagnosticSeverity.Error,
                    'HIGH': vscode.DiagnosticSeverity.Error,
                    'MEDIUM': vscode.DiagnosticSeverity.Warning,
                    'LOW': vscode.DiagnosticSeverity.Information,
                    'INFO': vscode.DiagnosticSeverity.Hint
                };
                const diagnosticSeverity = severityMap[finding.severity] || vscode.DiagnosticSeverity.Information;

                const message = `[PhoenixSec] ${finding.vulnerability_type} (${finding.rule_id})\n` +
                                `Remediation: ${finding.recommendation}`;
                
                const diagnostic = new vscode.Diagnostic(range, message, diagnosticSeverity);
                diagnostic.source = 'PhoenixSec';
                diagnostic.code = finding.cwe_id;
                return diagnostic;
            });

            diagnosticCollection.set(document.uri, diagnostics);
        } catch (e) {
            console.error(`Failed to parse PhoenixSec output: ${e.message}`);
        }
    });
}

function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
}

module.exports = {
    activate,
    deactivate
};
