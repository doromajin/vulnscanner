# VulnScanner

> Static vulnerability scanner for public GitHub repositories and local codebases.
> Detects OWASP Top 10 patterns — SQL Injection, XSS, Command Injection, Path Traversal, and hardcoded secrets — across Python, Java, JavaScript, PHP, and more.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)](https://owasp.org/www-project-top-ten/)

---

## Why VulnScanner?

Most SAST tools require build pipelines, paid licenses, or cloud accounts.
VulnScanner runs **in one command** against any public GitHub repository or local clone:

```
vulnscan https://github.com/owner/repo
```

### Key appeal points for CVE research

| Capability | Details |
|------------|---------|
| **No build required** | Pure static analysis — reads source files directly, no compilation or runtime needed |
| **GitHub-native** | Scans any public repo by URL without cloning; uses the GitHub Contents API |
| **Multi-language** | Python, Java, JavaScript/TypeScript, PHP, Ruby, Go, Shell — in one pass |
| **CVE-class patterns** | Rules map to CWE/OWASP categories that underpin real CVEs (CWE-89, CWE-79, CWE-78, CWE-22, CWE-798) |
| **Low false-positive design** | Vendor files, minified bundles, and comment lines are automatically excluded |
| **CI/CD ready** | Exits with code `1` on findings; `--output` writes machine-readable JSON |
| **Auditable rules** | All 31 rules are plain Python — easy to extend, review, or disable |

---

## Detected vulnerability types

### SQL Injection (CWE-89)

| Rule | Severity | Description |
|------|----------|-------------|
| SQL-001 | HIGH | String concatenation inside `execute()` / `query()` |
| SQL-002 | HIGH | `%`-formatting used to build SQL queries |
| SQL-003 | HIGH | `.format()` used inside `execute()` |
| SQL-004 | HIGH | PHP SQL query built with string concatenation |
| SQL-005 | MEDIUM | Django ORM `raw()` / `extra()` — unsanitized input risk |

### Cross-Site Scripting — XSS (CWE-79)

| Rule | Severity | Description |
|------|----------|-------------|
| XSS-001 | HIGH | Direct `innerHTML` assignment |
| XSS-002 | HIGH | `document.write()` with unsanitized input |
| XSS-003 | HIGH | Direct `outerHTML` assignment |
| XSS-004 | MEDIUM | Django/Jinja2 template value marked `\| safe` or `mark_safe()` |
| XSS-005 | HIGH | PHP `echo $_GET` / `$_POST` / `$_REQUEST` direct output |
| XSS-006 | MEDIUM | `insertAdjacentHTML()` usage |
| XSS-007 | CRITICAL | `eval()` with browser-controlled input (`location`, `document.*`) |

### Command Injection (CWE-78)

| Rule | Severity | Description |
|------|----------|-------------|
| CMD-001 | HIGH | `os.system()` with variable argument |
| CMD-002 | HIGH | `subprocess` called with `shell=True` |
| CMD-003 | HIGH | `os.popen()` usage |
| CMD-004 | CRITICAL | Standalone `eval()` / `exec()` with non-literal argument |
| CMD-005 | CRITICAL | PHP `shell_exec()`, `passthru()`, `proc_open()` with `$` variable |
| CMD-006 | CRITICAL | PHP backtick operator with `$_GET` / `$_POST` |
| CMD-007 | HIGH | Java `Runtime.getRuntime().exec()` |

### Path Traversal (CWE-22)

| Rule | Severity | Description |
|------|----------|-------------|
| PATH-001 | HIGH | `open()` with a request/param variable as path (Python/Ruby) |
| PATH-002 | MEDIUM | `open()` with string concatenation (Python/PHP/Ruby) |
| PATH-003 | MEDIUM | `send_file()` / `send_from_directory()` without path validation |
| PATH-004 | CRITICAL | PHP `file_get_contents()`, `include`, `require` with `$_GET`/`$_POST` |
| PATH-005 | INFO | Literal `../` path traversal sequence in source |

### Hardcoded Secrets (CWE-798)

| Rule | Severity | Description |
|------|----------|-------------|
| SEC-001 | HIGH | Hardcoded `password` / `passwd` literal |
| SEC-002 | HIGH | Hardcoded `api_key` / `api_secret` |
| SEC-003 | HIGH | Hardcoded `secret_key` / `SECRET_KEY` |
| SEC-004 | CRITICAL | AWS access key ID (`AKIA…`) pattern |
| SEC-005 | CRITICAL | Private key material (`-----BEGIN PRIVATE KEY-----`) |
| SEC-006 | HIGH | Hardcoded `token` / `access_token` value |
| SEC-007 | HIGH | Database connection string with embedded credentials |

---

## Supported languages

| Language | Extensions |
|----------|-----------|
| Python | `.py` |
| Java | `.java` |
| JavaScript / TypeScript | `.js` `.ts` `.jsx` `.tsx` |
| PHP | `.php` |
| Ruby | `.rb` |
| Go | `.go` |
| Shell | `.sh` |
| Config / Secrets | `.env` `.yml` `.yaml` `.json` `.config` |
| Templates | `.html` `.htm` |

---

## Installation

**Prerequisites:** Python 3.10+

```bash
# Clone and install
git clone https://github.com/your-username/vulnscanner.git
cd vulnscanner
pip install -r requirements.txt
pip install -e .
```

For GitHub API access (recommended — avoids the 60 req/hr unauthenticated limit):

```bash
export GITHUB_TOKEN=ghp_your_personal_access_token
```

---

## Quick start

```bash
# Scan a GitHub repository by URL
vulnscan https://github.com/WebGoat/WebGoat

# Scan a local clone
git clone --depth=1 https://github.com/WebGoat/WebGoat
vulnscan ./WebGoat

# Show only HIGH and above
vulnscan owner/repo --min-severity HIGH

# Write a JSON report
vulnscan owner/repo --output report.json

# Print code snippets alongside each finding
vulnscan owner/repo --detail
```

---

## Usage

```
Usage: vulnscan [OPTIONS] TARGET

  Scan a GitHub repository or local directory for vulnerability patterns.

  TARGET can be:
    https://github.com/owner/repo   (full GitHub URL)
    owner/repo                      (short slug)
    /path/to/cloned/repo            (local directory)

Options:
  --token TEXT                    GitHub personal access token
                                  (or set GITHUB_TOKEN env var)
  -o, --output TEXT               Write JSON report to this file
  --detail                        Print code snippets for each finding
  --min-severity [CRITICAL|HIGH|MEDIUM|LOW|INFO]
                                  Only show findings at or above this level
  --help                          Show this message and exit.
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings (at or above `--min-severity`) |
| `1` | One or more findings detected |

This makes `vulnscan` composable in CI pipelines:

```yaml
# GitHub Actions example
- name: Run VulnScanner
  run: vulnscan ${{ github.repository }} --min-severity HIGH --output report.json
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Output examples

### Console (default)

```
╭──────────────────────────────────────────────────────────────────╮
│ CRITICAL (2 findings)                                            │
├─────────┬──────────────────────┬──────────────────┬──────┬──────┤
│ Rule    │ Type                 │ File             │ Line │ ...  │
├─────────┼──────────────────────┼──────────────────┼──────┼──────┤
│ SEC-005 │ Hardcoded Secret     │ src/.../Crypto.. │   49 │ ...  │
│ CMD-007 │ Command Injection    │ src/.../Vulnera..│   67 │ ...  │
╰─────────┴──────────────────────┴──────────────────┴──────┴──────╯

Summary  CRITICAL: 2  HIGH: 21  MEDIUM: 0  LOW: 0  INFO: 1
         Scanned 554 files / 36,899 lines
```

### Code snippets (`--detail`)

```
┌─ [CMD-007] HIGH — Command Injection ─────────────────────────────┐
│ Java Runtime.exec() — verify arguments are not user-controlled   │
│                                                                  │
│ File: src/main/java/.../VulnerableTaskHolder.java:67             │
│                                                                  │
│   65 |     try {
│   66 |         logger.debug("Running: {}", taskAction);
│   67 |         Process p = Runtime.getRuntime().exec(taskAction);
│   68 |         p.waitFor();
│   69 |     } catch (Exception e) {
└──────────────────────────────────────────────────────────────────┘
```

### JSON report (`--output report.json`)

```json
{
  "repo_url": "https://github.com/WebGoat/WebGoat",
  "summary": {
    "total_findings": 24,
    "scanned_files": 554,
    "scanned_lines": 36899,
    "by_severity": {
      "CRITICAL": 2, "HIGH": 21, "MEDIUM": 0, "LOW": 0, "INFO": 1
    }
  },
  "findings": [
    {
      "vuln_type": "Command Injection",
      "severity": "HIGH",
      "rule_id": "CMD-007",
      "file_path": "src/main/.../VulnerableTaskHolder.java",
      "line_number": 67,
      "line_content": "Process p = Runtime.getRuntime().exec(taskAction);",
      "description": "Java Runtime.exec() — verify arguments are not user-controlled",
      "repo_url": "https://github.com/WebGoat/WebGoat",
      "snippet": "  65 |     try {\n  66 |         ...\n  67 |     Process p = ..."
    }
  ]
}
```

---

## False positive reduction

VulnScanner applies several heuristics to minimize noise:

| Technique | What it suppresses |
|-----------|--------------------|
| **Vendor directory exclusion** | `node_modules/`, `plugins/`, `libs/`, `bower_components/`, `.min.js` bundles |
| **Comment line filtering** | Lines starting with `//`, `*`, `/*`, `#`, `<!--` |
| **Method-chain exclusion** | `.exec()`, `.open()` calls on objects (regex negative lookbehind) |
| **Language-aware rules** | PATH-002 skips `.js`/`.ts` where `open()` means XHR; PATH-005 skips test directories |
| **Secret allowlist** | Values containing `example`, `placeholder`, `dummy`, `your-`, `***`, etc. |

---

## Tested against real CVE-class targets

| Repository | Findings | Notable detections |
|------------|----------|--------------------|
| [WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) | 24 | JWT hardcoded secret, `Runtime.exec()` RCE, SQL injection, private key in source |

> WebGoat is OWASP's intentionally vulnerable training application — an ideal ground-truth target for validating scanner accuracy.

---

## Project structure

```
vulnscanner/
├── analyzers/
│   ├── base.py              # BaseAnalyzer with comment detection, snippet extraction
│   ├── sql_injection.py     # SQL-001..005
│   ├── xss.py               # XSS-001..007
│   ├── command_injection.py # CMD-001..007
│   ├── path_traversal.py    # PATH-001..005
│   └── hardcoded_secrets.py # SEC-001..007
├── fetcher/
│   ├── github.py            # GitHub Contents API traversal
│   └── local.py             # Local directory traversal with vendor exclusion
├── reporters/
│   ├── console.py           # Rich terminal output
│   └── json_reporter.py     # Machine-readable JSON
├── scanner.py               # Orchestration: auto-detects GitHub URL vs local path
├── cli.py                   # Click CLI entry point
└── models.py                # Finding, ScanResult, Severity, VulnType dataclasses
```

---

## Adding custom rules

Each analyzer exposes a plain `_RULES` list. To add a rule, append a tuple:

```python
# vulnscanner/analyzers/sql_injection.py
_RULES = [
    ...
    (
        "SQL-006",                          # Rule ID
        r'cursor\.execute\s*\(.*format\b',  # Regex pattern
        "SQL query uses .format() via cursor.execute()",  # Description
        Severity.HIGH,                      # Severity
    ),
]
```

No subclassing or registration required — the rule is picked up automatically.

---

## Roadmap

- [ ] AST-based analysis for Python (reduce regex false positives further)
- [ ] HTML report output (Jinja2 template)
- [ ] Parallel file fetching with `asyncio` + `httpx`
- [ ] YAML-based rule configuration (enable/disable rules per project)
- [ ] SARIF output for GitHub Code Scanning integration
- [ ] `--ignore-file` support (`.vulnignore` like `.gitignore`)

---

## Limitations

- **Regex-based**: taint tracking and data-flow analysis are out of scope. Some patterns require context to confirm exploitability.
- **GitHub API rate limit**: unauthenticated scans are limited to 60 requests/hour. Use `--token` or `GITHUB_TOKEN` for large repositories.
- **Large repos**: files over 500 KB and minified bundles are intentionally skipped.
- **Scope**: detects vulnerability *patterns*, not confirmed vulnerabilities. All findings require manual verification before being reported as CVEs.

---

## Ethical use

This tool is intended for:

- Security research on **your own code** or **explicitly authorized** repositories
- CTF challenges and security training (e.g., WebGoat, DVWA, Juice Shop)
- Open-source contribution — finding and responsibly disclosing vulnerabilities in public projects

Do not use VulnScanner to scan repositories without authorization from the owner.
If you discover a genuine vulnerability, follow the project's responsible disclosure policy.

---

## Running tests

```bash
pytest tests/ -v
pytest tests/ --cov=vulnscanner --cov-report=term-missing
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

Pull requests are welcome. To add a new vulnerability pattern:

1. Add your rule to the appropriate `analyzers/*.py` file
2. Add a fixture in `tests/fixtures/` with a sample vulnerable snippet
3. Add a test case in `tests/test_analyzers.py`
4. Verify false-positive behaviour with a "safe" counterexample test
