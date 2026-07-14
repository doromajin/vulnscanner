from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.text import Text

from vulnscanner.models import ScanResult, Severity

# Ensure stdout uses UTF-8 so Unicode characters in finding descriptions (e.g. em
# dashes) don't raise UnicodeEncodeError on Windows terminals with narrow encodings
# like cp932. reconfigure() modifies sys.stdout in-place (Python 3.7+).
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(width=120, legacy_windows=False)

_GRADE_BADGE = {
    "HIGH":    "[bold red][HIGH][/bold red]",
    "MEDIUM":  "[yellow][MEDIUM][/yellow]",
    "LOW":     "[cyan][LOW][/cyan]",
    "MINIMAL": "[dim][MINIMAL][/dim]",
    "CLEAN":   "[green][CLEAN][/green]",
}

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_results(
    result: ScanResult,
    confirmed_keys: set[tuple[str, str]] | None = None,
) -> None:
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
        table.add_column("Rule", style="dim", width=14)
        table.add_column("Type", width=24)
        table.add_column("File", overflow="fold")
        table.add_column("Line", justify="right", width=6)
        table.add_column("Description")

        for f in group:
            desc = f.description
            if confirmed_keys and (f.rule_id, Path(f.file_path).name) in confirmed_keys:
                desc = "[bold green][CONFIRMED PATTERN][/bold green] " + desc
            table.add_row(
                f.rule_id,
                f.vuln_type.value,
                f.file_path,
                str(f.line_number),
                desc,
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
        header.append(f"- {finding.vuln_type.value}")

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

    elapsed = result.elapsed_seconds
    elapsed_str = f"{elapsed:.1f}s" if elapsed < 60 else f"{int(elapsed // 60)}m {elapsed % 60:.0f}s"
    console.print(
        f"         Scanned [bold]{result.scanned_files}[/bold] files / "
        f"[bold]{result.scanned_lines:,}[/bold] lines in [bold]{elapsed_str}[/bold]"
    )
    if result.suppressed_count:
        msg = f"[dim]         {result.suppressed_count} finding(s) suppressed"
        if result.suppression_breakdown:
            bd = ", ".join(
                f"{k.replace('_', ' ')}: {v}"
                for k, v in sorted(result.suppression_breakdown.items())
            )
            msg += f" ({bd})"
        msg += "[/dim]"
        console.print(msg)
    if result.errors:
        console.print(f"[yellow]         {len(result.errors)} error(s) during scan[/yellow]")

    # Risk profile badge
    from vulnscanner.profiler import profile as build_profile
    p = build_profile(result)
    badge = _GRADE_BADGE[p.grade]
    bar = _score_bar(p.score)
    console.print(f"Risk     {badge}  Score {p.score}/100  {bar}")
    console.print()


def _score_bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "[green]" + "#" * filled + "[/green][dim]" + "-" * (width - filled) + "[/dim]"


def print_rank_table(profiles: list) -> None:
    """Display a ranked table of RiskProfile objects."""
    from vulnscanner.profiler import RiskProfile
    ranked = sorted(profiles, key=lambda p: p.score, reverse=True)

    console.print()
    console.rule("[bold]Vulnerability Risk Ranking")
    console.print()

    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold",
    )
    table.add_column("#", width=3, justify="right")
    table.add_column("Repository", overflow="fold")
    table.add_column("Score", width=7, justify="center")
    table.add_column("Level", width=10)
    table.add_column("Findings", width=18)
    table.add_column("Top Risk Categories")

    for rank, p in enumerate(ranked, start=1):
        # Severity breakdown string: "6H 4M 34L"
        sev_parts = []
        for label, short in [("CRITICAL","C"), ("HIGH","H"), ("MEDIUM","M"), ("LOW","L")]:
            n = p.by_severity.get(label, 0)
            if n:
                sev_parts.append(f"{n}{short}")
        sev_str = " ".join(sev_parts) if sev_parts else "-"

        bar = _score_bar(p.score, width=10)
        top = ", ".join(p.top_vuln_types[:2]) if p.top_vuln_types else "-"
        short_repo = p.repo.rstrip("/").split("/")[-1]

        table.add_row(
            str(rank),
            short_repo,
            f"{p.score}/100",
            _GRADE_BADGE[p.grade],
            sev_str,
            top,
        )

    console.print(table)
    console.print()
