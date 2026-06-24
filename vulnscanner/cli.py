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
    """VulnScanner — static vulnerability scanner for OSS repositories."""


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

    if detail:
        print_finding_detail(result)
    else:
        print_results(result)

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
