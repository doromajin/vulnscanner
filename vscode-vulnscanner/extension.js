// VulnScanner VS Code Extension
// Runs vulnscanner on Python/Java/JS/TS/Go/Ruby/PHP files and shows findings as diagnostics.
const vscode = require('vscode');
const { execFile } = require('child_process');
const path = require('path');

const SUPPORTED_LANGUAGES = new Set([
    'python', 'java', 'javascript', 'typescript',
    'javascriptreact', 'typescriptreact', 'go', 'ruby', 'php',
]);

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/** @type {vscode.DiagnosticCollection} */
let diagnosticCollection;

/** @type {vscode.StatusBarItem} */
let statusBarItem;

/** @type {Map<string, AbortController>} */
const pendingScans = new Map();

// ── Activation ────────────────────────────────────────────────────────────────

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('vulnscanner');
    context.subscriptions.push(diagnosticCollection);

    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'vulnscanner.scanFile';
    statusBarItem.tooltip = 'VulnScanner: click to scan current file';
    context.subscriptions.push(statusBarItem);

    // Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('vulnscanner.scanFile', cmdScanFile),
        vscode.commands.registerCommand('vulnscanner.scanWorkspace', cmdScanWorkspace),
        vscode.commands.registerCommand('vulnscanner.clearDiagnostics', () => {
            diagnosticCollection.clear();
            updateStatusBar(null);
        }),
    );

    // Scan on save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(doc => {
            const cfg = vscode.workspace.getConfiguration('vulnscanner');
            if (cfg.get('scanOnSave') && SUPPORTED_LANGUAGES.has(doc.languageId)) {
                scanDocument(doc);
            }
        }),
    );

    // Clear diagnostics when a file is closed
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument(doc => {
            diagnosticCollection.delete(doc.uri);
        }),
    );

    // Update status bar when active editor changes
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && SUPPORTED_LANGUAGES.has(editor.document.languageId)) {
                statusBarItem.show();
                const existing = diagnosticCollection.get(editor.document.uri);
                updateStatusBar(existing ? existing.length : null);
            } else {
                statusBarItem.hide();
            }
        }),
    );

    // Show status bar for initial editor
    const initial = vscode.window.activeTextEditor;
    if (initial && SUPPORTED_LANGUAGES.has(initial.document.languageId)) {
        statusBarItem.show();
        updateStatusBar(null);
    }
}

function deactivate() {
    diagnosticCollection?.dispose();
    statusBarItem?.dispose();
    for (const ctrl of pendingScans.values()) {
        try { ctrl.abort(); } catch (_) {}
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

function cmdScanFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('VulnScanner: no active editor.');
        return;
    }
    if (!SUPPORTED_LANGUAGES.has(editor.document.languageId)) {
        vscode.window.showWarningMessage(
            `VulnScanner: ${editor.document.languageId} is not supported.`
        );
        return;
    }
    scanDocument(editor.document);
}

function cmdScanWorkspace() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage('VulnScanner: no workspace folder open.');
        return;
    }
    const target = folders[0].uri.fsPath;
    vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'VulnScanner: scanning workspace…', cancellable: false },
        () => runScan(target, null),
    );
}

// ── Scanning ──────────────────────────────────────────────────────────────────

/**
 * Scan a single document and update its diagnostics.
 * @param {vscode.TextDocument} doc
 */
function scanDocument(doc) {
    // Cancel any in-flight scan for the same file
    const existing = pendingScans.get(doc.uri.toString());
    if (existing) {
        try { existing.abort(); } catch (_) {}
    }

    const ctrl = { aborted: false, abort() { this.aborted = true; } };
    pendingScans.set(doc.uri.toString(), ctrl);

    setStatusScanning();

    runScan(doc.fileName, ctrl).then(findings => {
        if (ctrl.aborted) return;
        pendingScans.delete(doc.uri.toString());

        const cfg = vscode.workspace.getConfiguration('vulnscanner');
        const minSev = cfg.get('minSeverity', 'MEDIUM');
        const minIdx = SEVERITY_ORDER.indexOf(minSev);

        const filtered = (findings || []).filter(
            f => SEVERITY_ORDER.indexOf(f.severity) <= minIdx
        );

        const diagnostics = filtered.map(f => findingToDiagnostic(f, doc));
        diagnosticCollection.set(doc.uri, diagnostics);
        updateStatusBar(diagnostics.length);
    }).catch(err => {
        pendingScans.delete(doc.uri.toString());
        updateStatusBar(null);
        if (err && err.message && !err.message.includes('aborted')) {
            vscode.window.showErrorMessage(`VulnScanner error: ${err.message}`);
        }
    });
}

/**
 * Invoke the vulnscanner CLI and return an array of finding objects.
 * @param {string} target  file path or directory
 * @param {{ aborted: boolean } | null} ctrl
 * @returns {Promise<any[]>}
 */
function runScan(target, ctrl) {
    return new Promise((resolve, reject) => {
        const cfg = vscode.workspace.getConfiguration('vulnscanner');
        const python = cfg.get('pythonPath', 'python');
        const timeout = (cfg.get('timeoutSeconds', 30)) * 1000;

        const args = ['-m', 'vulnscanner.cli', 'scan', target, '--stdout-json'];

        const child = execFile(python, args, { timeout }, (error, stdout, stderr) => {
            if (ctrl && ctrl.aborted) return resolve([]);

            if (error && !stdout) {
                // Real invocation failure (missing package, wrong python path, etc.)
                return reject(new Error(
                    stderr ? stderr.slice(0, 300) : error.message
                ));
            }

            try {
                const result = JSON.parse(stdout);
                resolve(result.findings || []);
            } catch (_) {
                // stdout might be mixed (rich output leaked), try to extract JSON
                const jsonStart = stdout.indexOf('{');
                if (jsonStart !== -1) {
                    try {
                        const result = JSON.parse(stdout.slice(jsonStart));
                        resolve(result.findings || []);
                        return;
                    } catch (_2) {}
                }
                resolve([]);
            }
        });

        // Hook into ctrl so callers can abort mid-flight
        if (ctrl) {
            const originalAbort = ctrl.abort.bind(ctrl);
            ctrl.abort = () => {
                originalAbort();
                try { child.kill(); } catch (_) {}
            };
        }
    });
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

/**
 * @param {any} finding
 * @param {vscode.TextDocument} doc
 * @returns {vscode.Diagnostic}
 */
function findingToDiagnostic(finding, doc) {
    const lineIdx = Math.max(0, (finding.line_number || 1) - 1);
    const lineText = doc.lineAt(Math.min(lineIdx, doc.lineCount - 1)).text;
    const trimStart = lineText.search(/\S/);
    const colStart = trimStart >= 0 ? trimStart : 0;
    const colEnd = lineText.trimEnd().length || 1;

    const range = new vscode.Range(lineIdx, colStart, lineIdx, colEnd);
    const sev = mapSeverity(finding.severity);

    const diag = new vscode.Diagnostic(
        range,
        `[${finding.rule_id}] ${finding.description}`,
        sev,
    );
    diag.source = 'VulnScanner';
    diag.code = {
        value: finding.rule_id,
        target: vscode.Uri.parse(
            `https://github.com/doromajin/vulnscanner#${finding.rule_id.toLowerCase()}`
        ),
    };

    // Add CWE tag if present
    if (finding.cwe_id) {
        diag.tags = [];
        diag.relatedInformation = [
            new vscode.DiagnosticRelatedInformation(
                new vscode.Location(doc.uri, range),
                `CWE-${finding.cwe_id} | Severity: ${finding.severity} | Confidence: ${finding.confidence ?? 'N/A'}%`,
            ),
        ];
    }

    return diag;
}

/** @param {string} sev */
function mapSeverity(sev) {
    switch (sev) {
        case 'CRITICAL':
        case 'HIGH':
            return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM':
            return vscode.DiagnosticSeverity.Warning;
        case 'LOW':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

// ── Status bar ────────────────────────────────────────────────────────────────

function setStatusScanning() {
    statusBarItem.text = '$(sync~spin) VulnScanner…';
    statusBarItem.backgroundColor = undefined;
    statusBarItem.show();
}

/** @param {number | null} count  null = no data yet */
function updateStatusBar(count) {
    if (count === null) {
        statusBarItem.text = '$(shield) VulnScanner';
        statusBarItem.backgroundColor = undefined;
    } else if (count === 0) {
        statusBarItem.text = '$(shield) VulnScanner ✓';
        statusBarItem.backgroundColor = undefined;
    } else {
        statusBarItem.text = `$(warning) VulnScanner ${count} issue${count === 1 ? '' : 's'}`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }
}

module.exports = { activate, deactivate };
