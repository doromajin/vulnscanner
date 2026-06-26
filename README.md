# VulnScanner

Static vulnerability scanner for OSS repositories (GitHub URLs or local paths).
Identifies exploitable patterns using a hybrid **AST taint-tracking + multi-language
regex** engine across 11 vulnerability categories.

**Ethical use only.** Results are intended for responsible disclosure.
No active exploitation, no network attacks.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)](https://owasp.org/www-project-top-ten/)

---

## Supported languages

| Language | Analysis method |
|---|---|
| Python | AST taint analysis + regex fallback |
| PHP | Regex + 1-hop taint tracking (XSS-008) |
| JavaScript / TypeScript | Regex |
| Java | Regex |
| Ruby | Regex |
| HTML | Regex |

---

## Architecture

```
Target (GitHub URL / local path)
        │
        ▼
  Fetcher  (GitHub Contents API  or  LocalFetcher)
        │  iter_files()
        ▼
  ThreadPoolExecutor  ──── worker × N (auto, max 16) ────► _analyze_file_pure()
        │                                                          │
        │                                             ┌────────────┴────────────┐
        │                                             │                        │
        │                                   PythonASTAnalyzer         Regex Analyzers
        │                                   (ast_python.py)           (sql, cmd, xss…)
        │                                             │
        │                                    3-state taint engine
        │                                    ┌──────────────────────┐
        │                                    │  _taint_of(node)      │
        │                                    │  TAINTED → HIGH/CRIT  │
        │                                    │  UNKNOWN → MEDIUM     │
        │                                    │  CLEAN   → suppress   │
        │                                    └──────────────────────┘
        ▼
  Suppression pipeline (per finding, in priority order)
    1. inline comment  — # vulnscanner: ignore
    2. clean taint source  — AST proven safe (CLEAN status)
    3. test / fixture / vendor path  — file_context.py (57 path rules)
        │
        ▼
  Deduplication
    same (file, line, vuln_type) → AST finding preferred over regex finding
        │
        ▼
  Reporters:  console (Rich)  ·  JSON  ·  SARIF 2.1.0
```

### Python taint sources

| Source | Taint status |
|---|---|
| `request.args`, `request.form`, `request.json` | TAINTED |
| `request.get_json()`, `request.data` | TAINTED |
| `input()` | TAINTED |
| String / numeric / boolean literals | CLEAN |
| `self.attr = literal` in `__init__` | CLEAN |
| `int()`, `float()`, `bool()` wrapping any input | CLEAN (type coercion) |
| Function parameters (unknown provenance) | UNKNOWN |
| `os.environ` | UNKNOWN (server config, not user input) |

### Context-specific sanitizers

`html.escape()`, `bleach.clean()`, `urllib.parse.quote()` and similar functions
**preserve the original taint status** — they protect only their own sink context
(HTML/URL) and must not suppress findings at SQL, CMD, or SSRF sinks.
Sanitizer names are recorded in `TaintInfo.sanitizers` for audit trails.

`int()`, `float()`, `bool()` are universal sanitizers and always produce CLEAN.

---

## Detection rules (100 total)

### AST rules — Python only (24 rules)

| Category | Rule IDs | Severity |
|---|---|---|
| SQL Injection | AST-SQL-001 to 005 | HIGH |
| Command Injection | AST-CMD-001 to 004 | HIGH / CRITICAL |
| Path Traversal | AST-PATH-001 to 003 | HIGH / MEDIUM / LOW |
| XSS | AST-XSS-001 | MEDIUM |
| Insecure Deserialization | AST-DESER-001 to 004 | CRITICAL / HIGH |
| SSRF | AST-SSRF-001 to 002 | HIGH / MEDIUM |
| Open Redirect | AST-REDIR-001 to 002 | HIGH / MEDIUM |
| SSTI | AST-SSTI-001 to 002 | CRITICAL / HIGH |
| Hardcoded Secrets | AST-SEC-001 | HIGH |

### Regex rules — all languages (76 rules)

| Category | Rule IDs | Languages |
|---|---|---|
| SQL Injection | SQL-001 to 005 | Python, PHP |
| Command Injection | CMD-001 to 007 | Python, PHP, Java, Ruby |
| XSS | XSS-001 to 008 | JS/TS/HTML, PHP |
| Path Traversal | PATH-001 to 005 | Python, PHP, Java, Ruby |
| SSRF | SSRF-001 to 008 | Python, JS, Java, Ruby |
| SSTI | SSTI-001 to 009 | Python, JS, PHP, Ruby |
| Open Redirect | REDIR-001 to 008 | Python, PHP, JS, Ruby |
| Insecure Deserialization | DESER-001 to 008 | Python, PHP, Java, Ruby, Node.js |
| Prototype Pollution | PROTO-001 to 005 | JavaScript |
| Hardcoded Secrets | SEC-001 to 007 | all languages |
| Dependency CVE | DEP-001 | Python (via OSV.dev) |

---

## Validation

### Test suite

```
276 tests passing  (pytest tests/)
```

### Recall check — detection rate + precision

`recall/` contains deliberately vulnerable code covering every major category.
`recall_check.py` validates **both directions simultaneously**:

- **Recall** — all 18 expected findings are detected with the correct severity
- **Precision** — zero unexpected findings anywhere in `recall/`

```
$ python recall_check.py
recall 18/18  |  unexpected 0
All 18 recall + precision checks passed.
```

| File | Expected rule | Severity |
|---|---|---|
| `python/eval_injection.py` | AST-CMD-003 | CRITICAL |
| `python/exec_injection.py` | AST-CMD-004 | CRITICAL |
| `python/deserialization.py` | AST-DESER-001 | CRITICAL |
| `python/ssti.py` | AST-SSTI-002 | HIGH |
| `python/sql_injection.py` | AST-SQL-001, AST-SQL-002 | HIGH |
| `python/command_injection.py` | AST-CMD-001, AST-CMD-002 | HIGH |
| `python/path_traversal.py` | AST-PATH-001, AST-PATH-002 | HIGH |
| `python/ssrf.py` | AST-SSRF-001 | HIGH |
| `python/deserialization.py` | AST-DESER-004 | HIGH |
| `python/sanitizer_bypass.py` | AST-SQL-002 | HIGH (`html.escape()` must not suppress SQL) |
| `php/sqli.php` | SQL-004 | HIGH |
| `php/xss.php` | XSS-005 | HIGH |
| `php/deser.php` | DESER-004 | CRITICAL |
| `php/xss_1hop.php` | XSS-008 | HIGH |
| `js/xss.js` | XSS-001 | HIGH |

### Self-scan

```
$ vulnscan scan .
No vulnerabilities found.
Scanned 31 files / 4,537 lines in 0.2s
2 finding(s) suppressed (inline comment: 2)
```

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/doromajin/vulnscanner.git
cd vulnscanner
pip install -e .
```

---

## Usage

### Scan a local repository

```bash
vulnscan scan /path/to/repo
```

### Scan a GitHub repository

```bash
export GITHUB_TOKEN=ghp_...
vulnscan scan owner/repo
vulnscan scan https://github.com/owner/repo
```

### Common scan options

```bash
# Show code snippets for each finding
vulnscan scan owner/repo --detail

# Only report HIGH and above
vulnscan scan owner/repo --min-severity HIGH

# Exit 1 if any CRITICAL finding exists (CI gate)
vulnscan scan owner/repo --fail-on CRITICAL

# SARIF output for GitHub Code Scanning
vulnscan scan owner/repo --sarif results.sarif

# JSON report
vulnscan scan owner/repo -o report.json

# Parallel workers (default: CPU cores × 2, max 16)
vulnscan scan owner/repo --workers 8

# Exclude paths
vulnscan scan owner/repo -e "tests/" -e "vendor/"
```

### Suppress a false positive inline

```python
# vulnscanner: ignore
cursor.execute(self.placeholder)          # proven-safe literal set in __init__

# vulnscanner: ignore[AST-CMD-001]
os.system(HARDCODED_DEPLOY_COMMAND)
```

### Rank multiple repositories by risk score

```bash
vulnscan rank owner/repo1 owner/repo2 owner/repo3 --top 5
```

### Manage the knowledge base

```bash
# Confirm a true positive
vulnscan confirm owner/repo worker/worker.py:103 AST-CMD-002 \
  --note "shell=True with user-controlled command"

# Record a false positive
vulnscan fp owner/repo app/db.py:45 AST-SQL-005 \
  --reason "self.placeholder is a literal set in __init__"

# View statistics
vulnscan knowledge stats
vulnscan knowledge list
```

---

## Limitations

| Area | Detail |
|---|---|
| **PHP taint (XSS-008)** | 1-hop only: `$_GET/$_POST → $var → echo`. Multi-hop chains and function-call boundaries are not tracked. |
| **Interprocedural analysis** | Taint does not follow values across function call boundaries in any language. A tainted argument passed to a helper function is not tracked inside the callee. |
| **AST analysis scope** | Python only. PHP, Java, Ruby, and JavaScript use regex rules with no data-flow awareness. |
| **PHP sanitizers** | `intval()`, `floatval()` are not recognized as PHP sanitizers; only Python's `int()`, `float()`, `bool()` guarantee CLEAN status. |
| **Multi-line PHP statements** | The PHP assignment regex matches single-line statements only. |
| **Taint recursion depth** | `_taint_of()` recurses to a maximum depth of 4; deeply nested expressions fall back to UNKNOWN (→ MEDIUM severity). |
| **No runtime context** | Static analysis only. Cannot detect issues that depend on runtime configuration or dynamic code generation. |
| **GitHub API rate limits** | Unauthenticated: 60 requests/hour. Set `GITHUB_TOKEN` for 5,000/hour. |

---

## Project layout

```
vulnscanner/
  analyzers/
    ast_python.py        # Python AST taint engine (24 AST rules)
    xss.py               # XSS detection incl. PHP 1-hop taint (XSS-008)
    sql_injection.py
    command_injection.py
    path_traversal.py
    ssrf.py / ssti.py / open_redirect.py
    deserialization.py / prototype_pollution.py
    hardcoded_secrets.py / dependencies.py
    file_context.py      # test/fixture/vendor path classifier (57 rules)
  taint.py               # TaintStatus enum + TaintInfo dataclass
  scanner.py             # parallel orchestrator + suppression pipeline
  models.py              # Finding, ScanResult dataclasses
  cli.py                 # Click CLI  (scan, rank, confirm, fp, knowledge)
  knowledge.py           # KnowledgeStore (~/.vulnscanner/knowledge.json)
  reporters/             # console (Rich), json_reporter, sarif

recall/                  # deliberately vulnerable snippets
recall_check.py          # strict two-sided recall + precision validation
```

---

## Ethical use

This tool is intended for:

- Security research on **your own code** or **explicitly authorized** repositories
- CTF challenges and intentionally vulnerable training applications (WebGoat, DVWA, Juice Shop)
- Responsible disclosure of vulnerabilities in open-source projects

Do not scan repositories without authorization from the owner.
If you discover a genuine vulnerability, follow the project's responsible disclosure policy.

---

## Running tests

```bash
pytest tests/ -v
pytest tests/ --cov=vulnscanner --cov-report=term-missing
```

---

## License

MIT — see [LICENSE](LICENSE) for details.
