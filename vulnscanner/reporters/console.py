from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

from vulnscanner.models import ScanResult, Severity

console = Console()

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_results(result: ScanResult) -> None:
    console.print()
    console.rule(f"[bold]Scan results: {result.repo_url}")

    if not result.findings:
        console.print("\n[green]No vulnerabilities found.[/green]\n")
        _print_summary(result)
        return

    # Group by severity for ordered display
    for severity in Severity:
        group = result.by_severity(severity)
        if not group:
            continue

        color = _SEVERITY_COLORS[severity]
        table = Table(
            title=f"[{color}]{severity.value}[/{color}] ({len(group)} finding{'s' if len(group) != 1 else ''})",
            box=box.ROUNDED,
            show_lines=True,
            header_style="bold",
        )
        table.add_column("Rule", style="dim", width=9)
        table.add_column("Type", width=24)
        table.add_column("File", overflow="fold")
        table.add_column("Line", justify="right", width=6)
        table.add_column("Description")

        for f in group:
            table.add_row(
                f.rule_id,
                f.vuln_type.value,
                f.file_path,
                str(f.line_number),
                f.description,
            )

        console.print(table)
        console.print()

    _print_summary(result)


def print_finding_detail(result: ScanResult) -> None:
    """Print each finding with its code snippet."""
    for finding in result.findings:
        color = _SEVERITY_COLORS[finding.severity]
        header = Text()
        header.append(f"[{finding.rule_id}] ", style="dim")
        header.append(f"{finding.severity.value} ", style=color)
        header.append(f"— {finding.vuln_type.value}")

        body = f"{finding.description}\n\n"
        body += f"File: {finding.file_path}:{finding.line_number}\n\n"
        if finding.snippet:
            body += finding.snippet

        console.print(Panel(body, title=header, border_style=color.replace("bold ", "")))
        console.print()


def _print_summary(result: ScanResult) -> None:
    counts = {s: len(result.by_severity(s)) for s in Severity}
    parts = [
        f"[bold red]CRITICAL: {counts[Severity.CRITICAL]}[/bold red]",
        f"[red]HIGH: {counts[Severity.HIGH]}[/red]",
        f"[yellow]MEDIUM: {counts[Severity.MEDIUM]}[/yellow]",
        f"[cyan]LOW: {counts[Severity.LOW]}[/cyan]",
        f"[dim]INFO: {counts[Severity.INFO]}[/dim]",
    ]
    console.print("Summary  " + "  ".join(parts))
    console.print(
        f"         Scanned [bold]{result.scanned_files}[/bold] files / "
        f"[bold]{result.scanned_lines:,}[/bold] lines"
    )
    if result.errors:
        console.print(f"[yellow]         {len(result.errors)} error(s) during scan[/yellow]")
    console.print()
