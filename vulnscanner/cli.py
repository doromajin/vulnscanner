import os
import sys

import click
from rich.console import Console

from vulnscanner.reporters.console import print_results, print_finding_detail
from vulnscanner.reporters.json_reporter import write_json
from vulnscanner.reporters.sarif import write_sarif
from vulnscanner.scanner import VulnScanner

console = Console(stderr=True)


@click.command()
@click.argument("target")
@click.option("--token", envvar="GITHUB_TOKEN", help="GitHub personal access token")
@click.option("--output", "-o", default=None, help="Write JSON report to this file")
@click.option("--sarif", default=None, help="Write SARIF 2.1.0 report to this file (for GitHub Code Scanning)")
@click.option("--detail", is_flag=True, help="Print code snippets for each finding")
@click.option(
    "--min-severity",
    default="INFO",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help="Only show findings at or above this severity",
)
@click.option(
    "--fail-on",
    default=None,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help="Exit 1 only when a finding at or above this severity exists (default: any finding)",
)
@click.option(
    "--exclude", "-e",
    multiple=True,
    metavar="GLOB",
    help="Glob pattern to skip, e.g. 'tests/**' (can be repeated)",
)
def main(
    target: str,
    token: str | None,
    output: str | None,
    sarif: str | None,
    detail: bool,
    min_severity: str,
    fail_on: str | None,
    exclude: tuple[str, ...],
) -> None:
    """Scan a GitHub repository or local directory for vulnerability patterns.

    TARGET can be:
      https://github.com/owner/repo  (full GitHub URL)
      owner/repo                     (short GitHub slug)
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

    # Filter by min severity for display (doesn't affect exit code calculation)
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

    # Determine exit code
    if fail_on:
        fail_sev = Severity(fail_on.upper())
        fail_cutoff = severity_order.index(fail_sev)
        should_fail = any(severity_order.index(f.severity) <= fail_cutoff for f in all_findings)
    else:
        should_fail = bool(all_findings)
    sys.exit(1 if should_fail else 0)
