import os
import sys

import click
from rich.console import Console

from vulnscanner.reporters.console import print_results, print_finding_detail
from vulnscanner.reporters.json_reporter import write_json
from vulnscanner.scanner import VulnScanner

console = Console(stderr=True)


@click.command()
@click.argument("target")
@click.option("--token", envvar="GITHUB_TOKEN", help="GitHub personal access token")
@click.option("--output", "-o", default=None, help="Write JSON report to this file")
@click.option("--detail", is_flag=True, help="Print code snippets for each finding")
@click.option(
    "--min-severity",
    default="INFO",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    help="Only show findings at or above this severity",
)
def main(target: str, token: str | None, output: str | None, detail: bool, min_severity: str) -> None:
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

    scanner = VulnScanner(github_token=token)

    try:
        result = scanner.scan(target)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(1)

    # Filter by min severity
    result.findings = [
        f for f in result.findings
        if severity_order.index(f.severity) <= cutoff
    ]

    if detail:
        print_finding_detail(result)
    else:
        print_results(result)

    if output:
        write_json(result, output)
        console.print(f"[green]JSON report written to {output}[/green]")

    sys.exit(1 if result.findings else 0)
