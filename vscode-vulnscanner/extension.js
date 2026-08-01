// VulnScanner VS Code Extension
// Runs vulnscanner on Python/Java/JS/TS/Go/Ruby/PHP/C/C++/C# files and shows findings as diagnostics.
const vscode = require('vscode');
const { execFile } = require('child_process');
const path = require('path');

const SUPPORTED_LANGUAGES = new Set([
    'python', 'java', 'javascript', 'typescript',
    'javascriptreact', 'typescriptreact', 'go', 'ruby', 'php',
    'c', 'cpp', 'csharp',
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
        vscode.commands.registerCommand('vulnscanner.addIgnoreComment', cmdAddIgnoreComment),
    );

    // Code Action provider: "Suppress with vulnscanner: ignore"
    const selector = [...SUPPORTED_LANGUAGES].map(lang => ({ language: lang }));
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            selector,
            new VulnScannerCodeActionProvider(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
        ),
    );

    // Hover provider: show remediation advice
    context.subscriptions.push(
        vscode.languages.registerHoverProvider(selector, new VulnScannerHoverProvider()),
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

// ── Remediation advice ────────────────────────────────────────────────────────

const REMEDIATION = {
    // SQL Injection
    'JAST-SQL-001': 'Use parameterized queries / PreparedStatement instead of string concatenation.',
    'AST-SQL-001':  'Use parameterized queries (cursor.execute("… %s", (val,))) instead of f-strings.',
    'CAST-SQL-001': 'Use parameterized queries via sqlite3_bind_*() or similar.',
    // Command Injection
    'JAST-CMD-001': 'Avoid Runtime.exec()/ProcessBuilder with user input. Validate and escape, or use a fixed command list.',
    'AST-CMD-001':  'Use subprocess with a list argument (no shell=True) and validate input.',
    'CAST-CMD-001': 'Validate input before passing to system()/popen(). Prefer execv() with argv instead of shell commands.',
    // XSS
    'JAST-XSS-001': 'Escape output with HtmlUtils.htmlEscape() or use a template engine with auto-escaping.',
    'AST-XSS-001':  'Use markupsafe.escape() or a template engine. Never render raw user input as HTML.',
    // Path Traversal
    'JAST-PATH-001': 'Canonicalize the path with File.getCanonicalPath() and verify it starts with the expected base directory.',
    'AST-PATH-001':  'Use os.path.realpath() and verify the resolved path is within the intended directory.',
    'CAST-PATH-001': 'Use realpath() and check the result starts with the allowed directory prefix.',
    // Buffer Overflow
    'CAST-BUF-001': 'Use strncpy/snprintf instead of strcpy/sprintf. Ensure the destination buffer is large enough.',
    'CAST-BUF-002': 'Check array bounds before subscript access. Use safe alternatives like std::vector with .at().',
    // Format String
    'CAST-FMT-001': 'Never pass user-controlled data directly as a printf format string. Use printf("%s", data) instead.',
    // UAF
    'CAST-UAF-001': 'Set pointer to NULL immediately after free(). Use smart pointers (unique_ptr/shared_ptr) in C++.',
    // Integer Overflow
    'CAST-INT-001': 'Validate size arguments before malloc/new. Check for integer overflow with __builtin_mul_overflow or similar.',
    // SSRF
    'CSAST-SSRF-001': 'Validate and whitelist target URLs. Block private IP ranges. Use an allowlist instead of denylisting.',
    'JAST-URI-001':   'Validate URI scheme and host against an allowlist before passing to ContentResolver.',
    // Authorization
    'JAST-ANDROID-AUTHZ-001': 'Call enforceCallingPermission() or checkCallingPermission() at the start of Binder entry methods.',
    'JAST-ANDROID-AUTHZ-002': 'Do not write user-controlled data to Settings.Secure/System/Global without authorization check.',
};

function remediationFor(ruleId) {
    if (REMEDIATION[ruleId]) return REMEDIATION[ruleId];
    // Prefix match
    const prefix = Object.keys(REMEDIATION).find(k => ruleId.startsWith(k.split('-').slice(0, 2).join('-')));
    return prefix ? REMEDIATION[prefix] : null;
}

// ── Code Action Provider ──────────────────────────────────────────────────────

class VulnScannerCodeActionProvider {
    /**
     * @param {vscode.TextDocument} document
     * @param {vscode.Range} range
     * @param {vscode.CodeActionContext} context
     * @returns {vscode.CodeAction[]}
     */
    provideCodeActions(document, range, context) {
        const actions = [];
        for (const diag of context.diagnostics) {
            if (diag.source !== 'VulnScanner') continue;
            const ruleId = typeof diag.code === 'object' ? diag.code.value : String(diag.code || '');
            if (!ruleId) continue;

            // Action 1: Add suppress comment
            const suppressAction = new vscode.CodeAction(
                `Suppress: add '# vulnscanner: ignore' comment`,
                vscode.CodeActionKind.QuickFix,
            );
            suppressAction.command = {
                command: 'vulnscanner.addIgnoreComment',
                title: 'Add ignore comment',
                arguments: [document, diag.range.start.line, ruleId],
            };
            suppressAction.diagnostics = [diag];
            actions.push(suppressAction);

            // Action 2: Open CWE reference
            const cweLine = diag.relatedInformation && diag.relatedInformation[0]
                ? diag.relatedInformation[0].message : '';
            const cweMatch = cweLine.match(/CWE-(\d+)/);
            if (cweMatch) {
                const openCweAction = new vscode.CodeAction(
                    `View CWE-${cweMatch[1]} on MITRE`,
                    vscode.CodeActionKind.Empty,
                );
                openCweAction.command = {
                    command: 'vscode.open',
                    title: 'Open CWE',
                    arguments: [vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${cweMatch[1]}.html`)],
                };
                actions.push(openCweAction);
            }
        }
        return actions;
    }
}

// ── Hover Provider ────────────────────────────────────────────────────────────

class VulnScannerHoverProvider {
    /**
     * @param {vscode.TextDocument} document
     * @param {vscode.Position} position
     * @returns {vscode.Hover | undefined}
     */
    provideHover(document, position) {
        const diags = diagnosticCollection.get(document.uri);
        if (!diags || diags.length === 0) return;

        const diag = diags.find(d => d.range.contains(position) && d.source === 'VulnScanner');
        if (!diag) return;

        const ruleId = typeof diag.code === 'object' ? diag.code.value : String(diag.code || '');
        const remediation = remediationFor(ruleId);
        if (!remediation) return;

        const md = new vscode.MarkdownString();
        md.isTrusted = true;
        md.appendMarkdown(`**VulnScanner [${ruleId}]** — Remediation\n\n`);
        md.appendMarkdown(`${remediation}\n\n`);
        md.appendMarkdown(`*Add \`# vulnscanner: ignore\` on this line to suppress.*`);
        return new vscode.Hover(md);
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/**
 * Insert a '# vulnscanner: ignore' (or language-appropriate comment) on the finding's line.
 * @param {vscode.TextDocument} document
 * @param {number} lineIndex
 * @param {string} ruleId
 */
async function cmdAddIgnoreComment(document, lineIndex, ruleId) {
    const editor = vscode.window.visibleTextEditors.find(e => e.document === document);
    if (!editor) return;

    const lineText = document.lineAt(lineIndex).text;
    const indent = lineText.match(/^(\s*)/)[1];

    // Pick the right comment syntax
    const lang = document.languageId;
    let commentPrefix;
    if (['c', 'cpp', 'csharp', 'java', 'javascript', 'typescript',
         'javascriptreact', 'typescriptreact', 'go'].includes(lang)) {
        commentPrefix = '// vulnscanner: ignore';
    } else {
        commentPrefix = '# vulnscanner: ignore';
    }

    // If the line already has a vulnscanner: ignore, add the rule ID
    if (lineText.includes('vulnscanner: ignore')) {
        // Already suppressed — inform user
        vscode.window.showInformationMessage(`VulnScanner: line ${lineIndex + 1} is already suppressed.`);
        return;
    }

    await editor.edit(eb => {
        const eol = document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n';
        eb.insert(new vscode.Position(lineIndex, 0), `${indent}${commentPrefix}[${ruleId}]${eol}`);
    });
}

module.exports = { activate, deactivate };
