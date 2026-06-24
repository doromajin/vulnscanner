import os
import sys

import click
from rich.console import Console

from vulnscanner.reporters.console import print_results, print_finding_detail, print_rank_table
from vulnscanner.reporters.json_reporter import write_json
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
@click.option("--detail", is_flag=True, help="Print code snippets for each finding")
@click.option("--min-severity", default="INFO", type=_SEVERITY_CHOICES,
              help="Only show findings at or above this severity")
@click.option("--fail-on", default=None, type=_SEVERITY_CHOICES,
              help="Exit 1 only when a finding at or above this severity exists")
@click.option("--exclude", "-e", multiple=True, metavar="GLOB",
              help="Glob pattern to skip (can be repeated)")
def scan(
    target: str,
    token: str | None,
    output: str | None,
    sarif: str | None,
    detail: bool,
    min_severity: str,
    fail_on: str | None,
    exclude: tuple[str, ...],
) -> None:
    """Scan a single GitHub repository or local directory.

    TARGET can be:
      https://github.com/owner/repo  (full GitHub URL)\n
      owner/repo                     (short GitHub slug)\n
      C:\\path\\to\\cloned\\repo     (local directory)
    """
    from vulnscanner.models import Severity

    severity_order = list(Severity)
    min_sev = Severity(min_severity.upper())
    cutoff = severity_order.index(min_sev)

    scanner = VulnScanner(github_token=token, exclude=exclude)

    try:
        result = scanner.scan(target)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(1)

    all_findings = result.findings
    result.findings = [
        f for f in all_findings
        if severity_order.index(f.severity) <= cutoff
    ]

    # Load confirmed pattern keys from knowledge base for annotation
    try:
        from vulnscanner.knowledge import KnowledgeStore
        confirmed_keys = KnowledgeStore().get_confirmed_pattern_keys()
    except Exception:
        confirmed_keys = set()

    if detail:
        print_finding_detail(result)
    else:
        print_results(result, confirmed_keys=confirmed_keys)

    if output:
        write_json(result, output)
        console.print(f"[green]JSON report written to {output}[/green]")

    if sarif:
        write_sarif(result, sarif)
        console.print(f"[green]SARIF report written to {sarif}[/green]")

    if fail_on:
        fail_sev = Severity(fail_on.upper())
        fail_cutoff = severity_order.index(fail_sev)
        should_fail = any(
            severity_order.index(f.severity) <= fail_cutoff for f in all_findings
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
def rank(
    repos: tuple[str, ...],
    token: str | None,
    top: int | None,
    min_score: int,
    output: str | None,
    quick: bool,
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
            result = VulnScanner(github_token=token, analyzers=analyzers).scan(repo)
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
    if os.path.isfile(candidate):
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
