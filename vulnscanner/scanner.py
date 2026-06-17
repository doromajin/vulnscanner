from __future__ import annotations

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from vulnscanner.analyzers import ALL_ANALYZERS, BaseAnalyzer
from vulnscanner.fetcher.github import GitHubFetcher
from vulnscanner.fetcher.local import LocalFetcher
from vulnscanner.models import ScanResult


class VulnScanner:
    def __init__(
        self,
        github_token: str | None = None,
        analyzers: list[BaseAnalyzer] | None = None,
    ) -> None:
        self._github_token = github_token
        self._analyzers = analyzers or ALL_ANALYZERS

    def scan(self, target: str) -> ScanResult:
        """Scan a GitHub repo URL/slug or a local directory path."""
        import os
        if os.path.isdir(target):
            return self._scan_local(target)
        return self._scan_github(target)

    def _scan_github(self, repo_url: str) -> ScanResult:
        result = ScanResult(repo_url=repo_url)
        fetcher = GitHubFetcher(token=self._github_token)

        try:
            repo = fetcher.get_repo(repo_url)
        except Exception as exc:
            result.errors.append(str(exc))
            return result

        with Progress(
            SpinnerColumn("line"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            redirect_stderr=False,
        ) as progress:
            task = progress.add_task(f"Scanning {repo.full_name}...", total=None)
            for file_path, content in fetcher.iter_files(repo):
                progress.update(task, description=f"[cyan]{file_path}")
                self._analyze_file(file_path, content, repo_url, result)

        return result

    def _scan_local(self, directory: str) -> ScanResult:
        result = ScanResult(repo_url=directory)
        fetcher = LocalFetcher(directory)

        with Progress(
            SpinnerColumn("line"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            redirect_stderr=False,
        ) as progress:
            task = progress.add_task(f"Scanning {directory}...", total=None)
            for file_path, content in fetcher.iter_files():
                progress.update(task, description=f"[cyan]{file_path}")
                self._analyze_file(file_path, content, directory, result)

        return result

    def _analyze_file(
        self, file_path: str, content: str, source: str, result: ScanResult
    ) -> None:
        result.scanned_files += 1
        result.scanned_lines += content.count("\n") + 1

        for analyzer in self._analyzers:
            if not analyzer.supports(file_path):
                continue
            try:
                findings = analyzer.analyze(file_path, content, source)
                result.findings.extend(findings)
            except Exception as exc:
                result.errors.append(f"{file_path}: {exc}")
