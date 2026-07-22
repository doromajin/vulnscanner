import os
import sys

import click
from rich.console import Console

from vulnscanner.reporters.console import print_results, print_finding_detail, print_rank_table
from vulnscanner.reporters.json_reporter import write_json, to_json_str
from vulnscanner.reporters.sarif import write_sarif
from vulnscanner.scanner import VulnScanner

console = Console(stderr=True)

_SEVERITY_CHOICES = click.Choice(
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False
)


@click.group()
def main() -> None:
    """VulnScanner - static vulnerability scanner for OSS repositories."""


# ── scan ──────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--token", envvar="GITHUB_TOKEN", help="GitHub personal access token")
@click.option("--output", "-o", default=None, help="Write JSON report to this file")
@click.option("--sarif", default=None, help="Write SARIF 2.1.0 report to this file")
@click.option("--html", "html_out", default=None, help="Write self-contained HTML report to this file")
@click.option("--baseline", default=None, metavar="FILE",
              help="Previous JSON scan: suppress known findings, report only NEW ones")
@click.option("--detail", is_flag=True, help="Print code snippets for each finding")
@click.option("--min-severity", default="INFO", type=_SEVERITY_CHOICES,
              help="Only show findings at or above this severity")
@click.option("--fail-on", default=None, type=_SEVERITY_CHOICES,
              help="Exit 1 only when a finding at or above this severity exists")
@click.option("--exclude", "-e", multiple=True, metavar="GLOB",
              help="Glob pattern to skip (can be repeated)")
@click.option("--workers", "-w", default=0, type=int, metavar="N",
              help="Parallel worker threads (0 = auto-detect)")
@click.option("--since", default=None, metavar="REF",
              help="Incremental scan: only analyse files changed since this git ref (e.g. HEAD~1, main)")
@click.option("--stdout-json", "stdout_json", is_flag=True, default=False,
              help="Print JSON to stdout instead of the rich table (for IDE integrations)")
@click.option("--rules", "-r", multiple=True, metavar="PATH",
              help="Custom rule file or directory (YAML). Can be repeated. "
                   "Use --rules builtin to load only built-in rules.")
@click.option("--no-builtin-rules", is_flag=True, default=False,
              help="Disable built-in YAML rules (custom rules only)")
@click.option("--filter", "filter_mode", default=None,
              type=click.Choice(["exploitable"], case_sensitive=False),
              help="'exploitable': show only findings with confirmed taint path from user input")
def scan(
    target: str,
    token: str | None,
    output: str | None,
    sarif: str | None,
    html_out: str | None,
    baseline: str | None,
    detail: bool,
    min_severity: str,
    fail_on: str | None,
    exclude: tuple[str, ...],
    workers: int,
    since: str | None,
    stdout_json: bool,
    rules: tuple[str, ...],
    no_builtin_rules: bool,
    filter_mode: str | None,
) -> None:
    """Scan a single GitHub repository or local directory.

    TARGET can be:
      https://github.com/owner/repo  (full GitHub URL)\n
      owner/repo                     (short GitHub slug)\n
      C:\\path\\to\\cloned\\repo     (local directory)
    """
    import subprocess
    from vulnscanner.models import Severity

    severity_order = list(Severity)
    min_sev = Severity(min_severity.upper())
    cutoff = severity_order.index(min_sev)

    # Incremental scan: resolve changed files from git diff
    changed_files: set[str] | None = None
    if since:
        if not os.path.isdir(target):
            console.print("[yellow]--since requires a local directory target; ignoring.[/yellow]")
        else:
            try:
                proc = subprocess.run(
                    ["git", "diff", "--name-only", since, "--"],
                    cwd=target, capture_output=True, text=True, check=True,
                )
                changed_files = {ln.strip() for ln in proc.stdout.splitlines() if ln.strip()}
                console.print(
                    f"[dim]Incremental scan: {len(changed_files)} file(s) changed since {since}[/dim]"
                )
                if not changed_files:
                    console.print("[yellow]No changed files detected — nothing to scan.[/yellow]")
                    sys.exit(0)
            except subprocess.CalledProcessError as exc:
                console.print(f"[yellow]--since failed ({exc.stderr.strip()}); scanning all files.[/yellow]")

    # Load custom / built-in YAML rules
    from vulnscanner.rules.loader import load_rules
    from pathlib import Path as _Path
    rule_paths: list[str] = []
    if not no_builtin_rules:
        _builtin_dir = _Path(__file__).parent / "rules" / "builtin"
        rule_paths.append(str(_builtin_dir))
    for r in rules:
        rule_paths.append(r)
    custom_rules = load_rules(rule_paths) if rule_paths else []
    if custom_rules and not stdout_json:
        console.print(f"[dim]Custom rules: {len(custom_rules)} rule(s) loaded[/dim]")

    scanner = VulnScanner(github_token=token, exclude=exclude, workers=workers,
                          custom_rules=custom_rules)

    try:
        result = scanner.scan(target, changed_files=changed_files)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(1)

    all_findings = result.findings
    result.findings = [
        f for f in all_findings
        if severity_order.index(f.severity) <= cutoff
    ]

    # Exploitability filter: keep only findings with a confirmed taint path.
    # Drops UNKNOWN-taint findings (taint_status == "unknown") which represent
    # unverified "needs_review" / "low_reach" cases.
    # Findings with no taint tracking (secrets, YAML, unconditional sinks) are kept.
    if filter_mode == "exploitable":
        result.findings = [
            f for f in result.findings
            if f.taint_status != "unknown"
        ]

    # Baseline comparison: split into new vs. already-known findings
    baseline_keys: set | None = None
    new_finding_keys: set | None = None
    if baseline:
        from vulnscanner.reporters.baseline import load_baseline, split_findings
        try:
            baseline_keys = load_baseline(baseline)
            new_findings, known_findings = split_findings(result.findings, baseline_keys)
            new_finding_keys = {(f.file_path, f.line_number, f.rule_id) for f in new_findings}
            n_known = len(known_findings)
            console.print(
                f"[dim]Baseline: {len(baseline_keys)} known finding(s) loaded from {baseline} "
                f"— {n_known} suppressed, {len(new_findings)} new[/dim]"
            )
        except Exception as exc:
            console.print(f"[yellow]Baseline load failed ({exc}); showing all findings.[/yellow]")

    # Load confirmed pattern keys from knowledge base for annotation
    try:
        from vulnscanner.knowledge import KnowledgeStore
        confirmed_keys = KnowledgeStore().get_confirmed_pattern_keys()
    except Exception:
        confirmed_keys = set()

    # --stdout-json: emit JSON to stdout and exit (used by IDE integrations)
    if stdout_json:
        print(to_json_str(result))
        sys.exit(0)

    # Write persistent artifacts first so they exist even if display crashes
    if output:
        write_json(result, output)
        console.print(f"[green]JSON report written to {output}[/green]")

    if sarif:
        write_sarif(result, sarif)
        console.print(f"[green]SARIF report written to {sarif}[/green]")

    if html_out:
        from vulnscanner.reporters.html_reporter import write_html
        write_html(result, html_out, new_finding_keys=new_finding_keys)
        console.print(f"[green]HTML report written to {html_out}[/green]")

    if detail:
        print_finding_detail(result)
    else:
        print_results(result, confirmed_keys=confirmed_keys)

    # When baseline is active, fail-on only applies to NEW findings
    if fail_on:
        fail_sev = Severity(fail_on.upper())
        fail_cutoff = severity_order.index(fail_sev)
        findings_for_fail = (
            [f for f in result.findings if (f.file_path, f.line_number, f.rule_id) in new_finding_keys]
            if new_finding_keys is not None else all_findings
        )
        should_fail = any(
            severity_order.index(f.severity) <= fail_cutoff for f in findings_for_fail
        )
    else:
        should_fail = bool(all_findings)
    sys.exit(1 if should_fail else 0)


# ── rank ──────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("repos", nargs=-1, required=True)
@click.option("--token", envvar="GITHUB_TOKEN", help="GitHub personal access token")
@click.option("--top", default=None, type=int,
              help="Show only the top N repositories by risk score")
@click.option("--min-score", default=0, type=int,
              help="Exclude repos with a risk score below this threshold (0–100)")
@click.option("--output", "-o", default=None,
              help="Write full JSON results to this directory (one file per repo)")
@click.option("--quick", is_flag=True,
              help="Skip dependency CVE lookups for faster ranking")
@click.option("--workers", "-w", default=0, type=int, metavar="N",
              help="Parallel worker threads per repo (0 = auto-detect)")
def rank(
    repos: tuple[str, ...],
    token: str | None,
    top: int | None,
    min_score: int,
    output: str | None,
    quick: bool,
    workers: int,
) -> None:
    """Scan multiple repositories and rank them by vulnerability risk.

    REPOS can be GitHub slugs, URLs, or local directory paths.

    Example:\n
      vulnscan rank repos/ytdlp2STRM repos/fugu-chat repos/betanin --top 3
    """
    from vulnscanner.profiler import profile as build_profile
    from vulnscanner.analyzers import ALL_ANALYZERS
    from vulnscanner.analyzers.dependencies import DependencyAnalyzer

    analyzers = (
        [a for a in ALL_ANALYZERS if not isinstance(a, DependencyAnalyzer)]
        if quick else ALL_ANALYZERS
    )

    profiles = []
    total = len(repos)

    for i, repo in enumerate(repos, start=1):
        short = repo.rstrip("/").split("/")[-1]
        console.print(
            f"[dim]({i}/{total})[/dim] Scanning [bold]{short}[/bold]...",
            end="",
        )
        try:
            result = VulnScanner(github_token=token, analyzers=analyzers, workers=workers).scan(repo)
            p = build_profile(result)
            profiles.append(p)
            console.print(
                f" [green]done[/green] "
                f"[dim]{p.finding_count} findings, {p.elapsed_seconds:.1f}s[/dim]"
            )

            if output:
                os.makedirs(output, exist_ok=True)
                out_path = os.path.join(output, f"{short}.json")
                write_json(result, out_path)

        except KeyboardInterrupt:
            console.print("\n[yellow]Ranking interrupted.[/yellow]")
            break
        except Exception as exc:
            console.print(f" [red]error:[/red] {exc}")

    if not profiles:
        console.print("[yellow]No results to rank.[/yellow]")
        sys.exit(1)

    # Apply filters
    if min_score > 0:
        profiles = [p for p in profiles if p.score >= min_score]
    if top:
        profiles = sorted(profiles, key=lambda p: p.score, reverse=True)[:top]

    print_rank_table(profiles)


# ── confirm ───────────────────────────────────────────────────────────────────

@main.command()
@click.argument("repo")
@click.argument("location", metavar="FILE:LINE")
@click.argument("rule_id")
@click.option("--note", default="", help="Notes about the vulnerability and why it is real")
def confirm(repo: str, location: str, rule_id: str, note: str) -> None:
    """Record a confirmed true-positive vulnerability finding.

    REPO is the repository path or slug.\n
    FILE:LINE is e.g. worker/worker.py:103\n
    RULE_ID is e.g. AST-CMD-002

    Example:\n
      vulnscan confirm repos/ytdlp2STRM worker/worker.py:103 AST-CMD-002
        --note "self.command flows from user config, shell=True enables injection"
    """
    from vulnscanner.knowledge import KnowledgeStore

    # Parse FILE:LINE
    if ":" not in location:
        console.print("[red]Error: LOCATION must be FILE:LINE, e.g. worker/worker.py:103[/red]")
        sys.exit(1)
    parts = location.rsplit(":", 1)
    file_path, line_str = parts[0], parts[1]
    try:
        line = int(line_str)
    except ValueError:
        console.print(f"[red]Error: LINE must be an integer, got {line_str!r}[/red]")
        sys.exit(1)

    # Try to read the code snippet from a local path
    snippet = ""
    import os
    candidate = os.path.join(repo, file_path)
    if os.path.isfile(candidate):  # vulnscanner: ignore
        try:
            lines = open(candidate, encoding="utf-8", errors="replace").readlines()  # vulnscanner: ignore
            start = max(0, line - 3)
            end = min(len(lines), line + 2)
            snippet = "".join(lines[start:end]).strip()
        except Exception:
            pass

    store = KnowledgeStore()
    entry_id = store.add_confirmed(
        repo=repo,
        file=file_path,
        line=line,
        rule_id=rule_id,
        code_snippet=snippet,
        notes=note,
    )

    hist = store.lookup_rule_history(rule_id)
    suggestion = store.suggest_rule_improvement(rule_id)

    console.print(f"\n[green]Confirmed vulnerability recorded as {entry_id}[/green]")
    console.print(f"  Rule    : {rule_id}")
    console.print(f"  Location: {repo} / {file_path}:{line}")
    if note:
        console.print(f"  Notes   : {note}")
    console.print(
        f"\n[dim]Rule {rule_id} history: "
        f"{hist['confirmed']} confirmed, {hist['false_positives']} FP  "
        f"(precision {hist['precision']:.0%})[/dim]"
    )
    if suggestion:
        console.print(f"\n[yellow]Learning suggestion:[/yellow] {suggestion}")
    console.print(
        f"\n[dim]Knowledge base: {store.path}[/dim]"
    )


# ── false-positive ────────────────────────────────────────────────────────────

@main.command("fp")
@click.argument("repo")
@click.argument("location", metavar="FILE:LINE")
@click.argument("rule_id")
@click.option("--reason", required=True, help="Why this is a false positive")
@click.option("--fix", "fix_applied", default="", help="Rule fix that was applied")
def false_positive(repo: str, location: str, rule_id: str, reason: str, fix_applied: str) -> None:
    """Record a confirmed false-positive finding.

    Example:\n
      vulnscan fp repos/ytdlp2STRM ui/ui.py:104 AST-PATH-001
        --reason "config_file is server-constructed, not user input"
        --fix "Removed data from _USER_INPUT_NAMES"
    """
    from vulnscanner.knowledge import KnowledgeStore

    if ":" not in location:
        console.print("[red]Error: LOCATION must be FILE:LINE[/red]")
        sys.exit(1)
    parts = location.rsplit(":", 1)
    file_path, line_str = parts[0], parts[1]
    try:
        line = int(line_str)
    except ValueError:
        console.print(f"[red]Error: LINE must be an integer, got {line_str!r}[/red]")
        sys.exit(1)

    store = KnowledgeStore()
    entry_id = store.add_false_positive(
        repo=repo, file=file_path, line=line, rule_id=rule_id,
        reason=reason, fix_applied=fix_applied,
    )

    suggestion = store.suggest_rule_improvement(rule_id)
    console.print(f"\n[cyan]False positive recorded as {entry_id}[/cyan]")
    console.print(f"  Rule   : {rule_id}")
    console.print(f"  Reason : {reason}")
    if fix_applied:
        console.print(f"  Fix    : {fix_applied}")
    if suggestion:
        console.print(f"\n[yellow]Learning suggestion:[/yellow] {suggestion}")


# ── fuzz ──────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("target")
@click.option("--payloads-only", is_flag=True,
              help="Generate payloads without executing any code")
@click.option("--max-seconds", default=30, type=int, show_default=True,
              help="Per-function execution time limit (seconds)")
@click.option("--max-examples", default=300, type=int, show_default=True,
              help="Hypothesis max_examples per function")
@click.option("--output", "-o", default=None,
              help="Write JSON report to this file")
@click.option("--yes", "-y", is_flag=True,
              help="Skip the legal confirmation prompt")
def fuzz(
    target: str,
    payloads_only: bool,
    max_seconds: int,
    max_examples: int,
    output: str | None,
    yes: bool,
) -> None:
    """Fuzz a LOCAL repository using static-analysis-guided payload generation.

    TARGET must be a local directory path.
    Network URLs are rejected — clone the repo first.

    Two-layer approach:\n
      Layer 1 (always) -- generate concrete payloads from static findings\n
      Layer 2 (Python) -- run Hypothesis against importable functions

    Example:\n
      vulnscan fuzz ./repos/my-app\n
      vulnscan fuzz ./repos/my-app --payloads-only\n
      vulnscan fuzz ./repos/my-app --max-seconds 60 --output fuzz_report.json
    """
    from vulnscanner.fuzzer import run_fuzz, FuzzTarget, LEGAL_NOTICE
    from vulnscanner.fuzzer.malware_check import BLOCK
    from vulnscanner.models import VulnType
    import json

    # Validate target (also enforces local-only)
    try:
        FuzzTarget(target)
    except (ValueError, FileNotFoundError) as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    execute = not payloads_only

    # Legal confirmation before any execution
    if execute and not yes:
        console.print(LEGAL_NOTICE)
        if not click.confirm("Proceed with dynamic execution?"):
            console.print("[yellow]Switching to --payloads-only mode.[/yellow]")
            execute = False

    console.print(f"\n[bold]VulnScanner Fuzz[/bold] — target: [cyan]{target}[/cyan]")
    console.print("[dim]Step 0/3: Malware pre-flight scan...[/dim]")
    console.print("[dim]Step 1/3: Static analysis...[/dim]")

    result = run_fuzz(
        target,
        execute=execute,
        max_seconds=max_seconds,
        max_examples=max_examples,
    )

    # ── Malware warnings ───────────────────────────────────────────────────────

    if result.malware_warnings:
        console.print()
        blocks = [w for w in result.malware_warnings if w.severity == BLOCK]
        warns  = [w for w in result.malware_warnings if w.severity != BLOCK]

        if blocks:
            console.print(f"[bold red]⛔  Malware scan: {len(blocks)} BLOCK finding(s) — dynamic execution suppressed[/bold red]")
            for w in blocks:
                console.print(w.to_display())
        if warns:
            console.print(f"[bold yellow]⚠   Malware scan: {len(warns)} warning(s)[/bold yellow]")
            for w in warns:
                console.print(w.to_display())
        console.print()
    elif execute:
        console.print("[dim]  Malware scan: clean[/dim]")

    # ── Report ─────────────────────────────────────────────────────────────────

    console.print(f"[dim]Step 2/3: Payload generation... {len(result.payloads)} payloads generated[/dim]")
    if not result.execution_blocked and execute:
        console.print(f"[dim]Step 3/3: Dynamic execution complete[/dim]")
    elif result.execution_blocked:
        console.print(f"[dim]Step 3/3: Dynamic execution skipped (malware detected)[/dim]")

    console.print()
    console.print(f"[bold]Static findings:[/bold] {len(result.static_findings)} total, "
                  f"{sum(1 for f in result.static_findings if f.severity.value in ('CRITICAL','HIGH'))} critical/high")
    console.print()

    # Group payloads by vuln_type
    by_type: dict = {}
    for p in result.payloads:
        by_type.setdefault(p.vuln_type, []).append(p)

    if by_type:
        console.print("[bold]Generated Payloads (for manual testing):[/bold]")
        for vt, payloads in by_type.items():
            console.print(f"\n  [yellow]{vt.value}[/yellow] ({len(payloads)} payloads)")
            for p in payloads[:5]:
                console.print(f"    {p.value!r:<50}  [dim]{p.description}[/dim]")
            if len(payloads) > 5:
                console.print(f"    [dim]... and {len(payloads)-5} more[/dim]")

    if result.fuzz_findings:
        console.print()
        console.print(f"[bold red]Dynamic Fuzz Findings: {len(result.fuzz_findings)}[/bold red]")
        for ff in result.fuzz_findings:
            console.print(ff.to_display())
    elif execute:
        console.print()
        console.print("[green]Dynamic fuzzing: no unexpected exceptions found.[/green]")

    if result.skipped_functions:
        console.print()
        console.print(f"[dim]Skipped ({len(result.skipped_functions)}):[/dim]")
        for s in result.skipped_functions[:5]:
            console.print(f"  [dim]{s}[/dim]")

    if output:
        report = {
            "target": str(result.target_path),
            "execution_blocked": result.execution_blocked,
            "malware_warnings": [
                {
                    "file": w.file_path,
                    "line": w.line,
                    "category": w.category,
                    "severity": w.severity,
                    "description": w.description,
                }
                for w in result.malware_warnings
            ],
            "static_findings": len(result.static_findings),
            "payloads": [
                {"value": p.value, "type": p.vuln_type.value, "description": p.description}
                for p in result.payloads
            ],
            "fuzz_findings": [
                {
                    "payload": ff.payload,
                    "exception": ff.exception_type,
                    "message": ff.exception_msg,
                    "file": ff.file_path,
                    "function": ff.function_name,
                    "confirmed": ff.confirmed,
                }
                for ff in result.fuzz_findings
            ],
            "skipped": result.skipped_functions,
        }
        Path(output).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"\n[green]JSON report written to {output}[/green]")

    sys.exit(0)


# ── knowledge ─────────────────────────────────────────────────────────────────

@main.group()
def knowledge() -> None:
    """Inspect the confirmed vulnerability knowledge base."""


@knowledge.command("list")
@click.option("--type", "kind",
              type=click.Choice(["all", "confirmed", "fp", "improvements"]),
              default="all")
def knowledge_list(kind: str) -> None:
    """List knowledge base entries."""
    from vulnscanner.knowledge import KnowledgeStore
    from rich.table import Table
    from rich import box
    from rich.console import Console as RC

    rc = RC()
    store = KnowledgeStore()

    if kind in ("all", "confirmed"):
        entries = store.list_confirmed()
        if entries:
            t = Table(title="Confirmed Vulnerabilities", box=box.ROUNDED, show_lines=True)
            t.add_column("ID", width=10)
            t.add_column("Repo", overflow="fold")
            t.add_column("File:Line", overflow="fold")
            t.add_column("Rule", width=14)
            t.add_column("Severity", width=9)
            t.add_column("Confirmed", width=12)
            for e in entries:
                t.add_row(
                    e["id"], e["repo"],
                    f"{e['file']}:{e['line']}",
                    e["rule_id"], e["severity"], e["confirmed_at"],
                )
            rc.print(t)

    if kind in ("all", "fp"):
        entries = store.list_false_positives()
        if entries:
            t = Table(title="False Positives", box=box.ROUNDED, show_lines=True)
            t.add_column("ID", width=8)
            t.add_column("Rule", width=14)
            t.add_column("File:Line", overflow="fold")
            t.add_column("Reason", overflow="fold")
            for e in entries:
                t.add_row(
                    e["id"], e["rule_id"],
                    f"{e['file']}:{e['line']}",
                    e["reason"],
                )
            rc.print(t)

    if kind in ("all", "improvements"):
        entries = store.list_rule_improvements()
        if entries:
            t = Table(title="Rule Improvements", box=box.ROUNDED, show_lines=True)
            t.add_column("Rule", width=14)
            t.add_column("Change", overflow="fold")
            t.add_column("Triggered By", width=12)
            t.add_column("Date")
            for e in entries:
                t.add_row(
                    e["rule_id"], e["change"],
                    e.get("triggered_by", ""), e["implemented_at"],
                )
            rc.print(t)

    if not store.list_confirmed() and not store.list_false_positives():
        rc.print("[dim]Knowledge base is empty. Use `vulnscan confirm` to add entries.[/dim]")


@knowledge.command("stats")
def knowledge_stats() -> None:
    """Show knowledge base statistics and rule effectiveness."""
    from vulnscanner.knowledge import KnowledgeStore
    from rich.console import Console as RC
    from rich.table import Table
    from rich import box

    rc = RC()
    store = KnowledgeStore()
    s = store.stats()

    rc.print()
    rc.print(f"[bold]Knowledge Base Stats[/bold]  ({store.path})")
    rc.print(f"  Confirmed vulns   : [green]{s['confirmed_count']}[/green]")
    rc.print(f"  False positives   : [yellow]{s['false_positive_count']}[/yellow]")
    rc.print(f"  Rule improvements : [cyan]{s['rule_improvement_count']}[/cyan]")
    if s["confirmed_count"] + s["false_positive_count"] > 0:
        rc.print(f"  Overall precision : [bold]{s['precision']:.0%}[/bold]")

    if s["by_severity"]:
        rc.print()
        rc.print("[bold]Confirmed by severity:[/bold]")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            n = s["by_severity"].get(sev, 0)
            if n:
                rc.print(f"  {sev:<10} {n}")

    if s["by_rule"]:
        rc.print()
        t = Table(title="Rule Effectiveness", box=box.SIMPLE)
        t.add_column("Rule ID", width=18)
        t.add_column("TP", justify="right", width=5)
        t.add_column("FP", justify="right", width=5)
        t.add_column("Precision", justify="right", width=10)
        t.add_column("Suggestion", overflow="fold")

        all_rule_ids = set(s["by_rule"]) | {
            fp["rule_id"] for fp in store.list_false_positives()
        }
        for rule_id in sorted(all_rule_ids):
            hist = store.lookup_rule_history(rule_id)
            prec = f"{hist['precision']:.0%}"
            sugg = store.suggest_rule_improvement(rule_id) or ""
            t.add_row(
                rule_id,
                str(hist["confirmed"]),
                str(hist["false_positives"]),
                prec,
                sugg[:60] + "..." if len(sugg) > 60 else sugg,
            )
        rc.print(t)
    rc.print()


# ── init ──────────────────────────────────────────────────────────────────────

_GHA_WORKFLOW = """\
name: VulnScanner

on:
  push:
    branches: [main, master]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF to GitHub Code Scanning

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install VulnScanner
        run: pip install vulnscanner

      - name: Run VulnScanner (baseline diff)
        run: |
          # First scan: save results as baseline on the default branch,
          # then compare on every PR so only NEW findings fail the build.
          vulnscan scan . \\
            --output vulnscanner_results.json \\
            --sarif  vulnscanner.sarif \\
            --html   vulnscanner_report.html \\
            --fail-on HIGH

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vulnscanner.sarif

      - name: Upload HTML report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vulnscanner-report
          path: vulnscanner_report.html
"""

_CONFIG_YAML = """\
# vulnscanner.yml — project-level configuration
# See: https://github.com/doromajin/vulnscanner

scan:
  # Glob patterns to exclude from scanning (relative to repo root)
  exclude:
    - "tests/**"
    - "vendor/**"
    - "node_modules/**"
    - "*.min.js"

  # Minimum severity to report (INFO | LOW | MEDIUM | HIGH | CRITICAL)
  min_severity: LOW

  # Fail CI when any finding at or above this severity is found
  fail_on: HIGH

  # Worker threads (0 = auto-detect based on CPU count)
  workers: 0
"""


@main.command("init")
@click.option("--dir", "target_dir", default=".", help="Target directory (default: current directory)")
@click.option("--force", is_flag=True, help="Overwrite existing files")
def init(target_dir: str, force: bool) -> None:
    """Scaffold GitHub Actions workflow and config file for VulnScanner.

    Creates:\n
      .github/workflows/vulnscanner.yml  — CI workflow\n
      vulnscanner.yml                    — project config
    """
    import os
    from pathlib import Path

    base = Path(target_dir).resolve()

    files = {
        base / ".github" / "workflows" / "vulnscanner.yml": _GHA_WORKFLOW,
        base / "vulnscanner.yml": _CONFIG_YAML,
    }

    created: list[str] = []
    skipped: list[str] = []

    for path, content in files.items():
        rel = path.relative_to(base)
        if path.exists() and not force:
            skipped.append(str(rel))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        created.append(str(rel))

    if created:
        console.print("\n[green]Created:[/green]")
        for f in created:
            console.print(f"  [cyan]{f}[/cyan]")
    if skipped:
        console.print("\n[yellow]Skipped (already exist — use --force to overwrite):[/yellow]")
        for f in skipped:
            console.print(f"  [dim]{f}[/dim]")

    if not created and not skipped:
        console.print("[yellow]Nothing to do.[/yellow]")
        return

    console.print(
        "\n[dim]Next steps:\n"
        "  1. Commit these files to your repository\n"
        "  2. Push to GitHub — the workflow runs automatically on every push/PR\n"
        "  3. Optionally: run `vulnscan scan . --output baseline.json` on your main branch\n"
        "     and use `--baseline baseline.json` in CI to suppress pre-existing findings[/dim]\n"
    )


# ── pr-comment ────────────────────────────────────────────────────────────────

@main.command("pr-comment")
@click.argument("repo", metavar="OWNER/REPO")
@click.option("--pr", "pr_number", required=True, type=int, metavar="NUMBER",
              envvar="GITHUB_PR_NUMBER",
              help="Pull request number (or set GITHUB_PR_NUMBER env var)")
@click.option("--token", envvar="GITHUB_TOKEN", help="GitHub personal access token")
@click.option("--min-severity", default="MEDIUM", type=_SEVERITY_CHOICES,
              help="Only comment on findings at or above this severity (default: MEDIUM)")
@click.option("--fail-on", default=None, type=_SEVERITY_CHOICES,
              help="Exit 1 if any finding at or above this severity exists in the PR")
@click.option("--dry-run", is_flag=True,
              help="Print what would be posted without actually posting")
@click.option("--workers", "-w", default=0, type=int, metavar="N",
              help="Parallel worker threads (0 = auto-detect)")
def pr_comment(
    repo: str,
    pr_number: int,
    token: str | None,
    min_severity: str,
    fail_on: str | None,
    dry_run: bool,
    workers: int,
) -> None:
    """Scan a GitHub PR and post inline review comments for security findings.

    Requires the GitHub CLI (gh) with PR write permissions, or GITHUB_TOKEN
    with repo scope.  Only findings in PR-changed files are posted.

    Example (in CI):\n
        vulnscan pr-comment owner/repo --pr $PR_NUMBER --fail-on HIGH
    """
    import json
    import subprocess
    from vulnscanner.models import Severity

    severity_order = list(Severity)
    min_sev = Severity(min_severity.upper())
    cutoff = severity_order.index(min_sev)

    # ── Step 1: get PR metadata (head SHA + changed file list) ────────────────
    def _gh_api(path: str) -> dict | list:
        env = os.environ.copy()
        if token:
            env["GITHUB_TOKEN"] = token
        result = subprocess.run(
            ["gh", "api", path],
            capture_output=True, text=True, env=env,
        )
        if result.returncode != 0:
            console.print(f"[red]gh api error ({path}): {result.stderr.strip()}[/red]")
            sys.exit(1)
        return json.loads(result.stdout)

    console.print(f"[dim]Fetching PR #{pr_number} metadata from {repo}...[/dim]")
    pr_meta = _gh_api(f"repos/{repo}/pulls/{pr_number}")
    head_sha: str = pr_meta["head"]["sha"]

    pr_files_raw = _gh_api(f"repos/{repo}/pulls/{pr_number}/files")
    pr_changed: set[str] = {f["filename"] for f in pr_files_raw}
    console.print(f"[dim]PR #{pr_number} — {len(pr_changed)} changed file(s), head SHA: {head_sha[:8]}[/dim]")

    # ── Step 2: scan the repo, filter to PR-changed files ─────────────────────
    console.print(f"[dim]Scanning {repo}...[/dim]")
    scanner = VulnScanner(github_token=token, workers=workers)
    result_obj = scanner.scan(repo)

    findings = [
        f for f in result_obj.findings
        if (f.file_path in pr_changed
            and severity_order.index(f.severity) <= cutoff)
    ]
    console.print(
        f"[dim]Scan complete — {len(result_obj.findings)} total finding(s), "
        f"{len(findings)} in PR-changed files at {min_severity}+[/dim]"
    )

    if not findings:
        console.print("[green]No findings to post for this PR.[/green]")
        sys.exit(0)

    # ── Step 3: build review payload ─────────────────────────────────────────
    sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

    def _finding_body(f) -> str:
        emoji = sev_emoji.get(f.severity.value if hasattr(f.severity, "value") else f.severity, "⚠️")
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        lines = [
            f"{emoji} **{sev} — {f.rule_id}** {f.vuln_type.value if hasattr(f.vuln_type, 'value') else f.vuln_type}",
            f"> {f.description}",
        ]
        if f.cwe_id:
            lines.append(f"**CWE**: [CWE-{f.cwe_id}](https://cwe.mitre.org/data/definitions/{f.cwe_id}.html)")
        return "\n".join(lines)

    review_comments = [
        {
            "path": f.file_path,
            "line": f.line_number,
            "body": _finding_body(f),
        }
        for f in findings
    ]

    crit = sum(1 for f in findings if (f.severity.value if hasattr(f.severity, "value") else f.severity) == "CRITICAL")
    high = sum(1 for f in findings if (f.severity.value if hasattr(f.severity, "value") else f.severity) == "HIGH")
    summary_body = (
        f"## VulnScanner found {len(findings)} finding(s) in this PR\n\n"
        f"| Severity | Count |\n|----------|-------|\n"
        + "\n".join(
            f"| {sev_emoji.get(sev, '⚠️')} {sev} | {sum(1 for f in findings if (f.severity.value if hasattr(f.severity,'value') else f.severity)==sev)} |"
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            if any((f.severity.value if hasattr(f.severity, "value") else f.severity) == sev for f in findings)
        )
        + f"\n\n*Scanned by [VulnScanner](https://github.com/doromajin/vulnscanner) — "
          f"`vulnscan pr-comment {repo} --pr {pr_number}`*"
    )

    # ── Step 4: post or dry-run ───────────────────────────────────────────────
    if dry_run:
        console.print("\n[yellow]Dry run — review that would be posted:[/yellow]")
        console.print(f"\n[bold]Summary:[/bold]\n{summary_body}\n")
        for c in review_comments:
            console.print(f"  [cyan]{c['path']}:{c['line']}[/cyan] — {c['body'][:80]}...")
    else:
        payload = {
            "commit_id": head_sha,
            "body": summary_body,
            "event": "COMMENT",
            "comments": review_comments,
        }
        env = os.environ.copy()
        if token:
            env["GITHUB_TOKEN"] = token
        post_result = subprocess.run(
            ["gh", "api", "--method", "POST",
             f"repos/{repo}/pulls/{pr_number}/reviews",
             "--input", "-"],
            input=json.dumps(payload),
            capture_output=True, text=True, env=env,
        )
        if post_result.returncode != 0:
            console.print(f"[red]Failed to post review: {post_result.stderr.strip()}[/red]")
            sys.exit(1)
        review_url = json.loads(post_result.stdout).get("html_url", "")
        console.print(f"[green]Posted {len(review_comments)} inline comment(s) to PR #{pr_number}[/green]")
        if review_url:
            console.print(f"[dim]{review_url}[/dim]")

    # ── Step 5: fail-on exit code ─────────────────────────────────────────────
    if fail_on:
        fail_sev = Severity(fail_on.upper())
        fail_cutoff = severity_order.index(fail_sev)
        if any(severity_order.index(f.severity) <= fail_cutoff for f in findings):
            sys.exit(1)


if __name__ == "__main__":
    main()
