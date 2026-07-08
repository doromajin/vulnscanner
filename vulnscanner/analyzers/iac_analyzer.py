"""Infrastructure-as-Code (IaC) security analyzer.

Covers:
  - Terraform (.tf): AWS misconfigurations
  - Kubernetes YAML (.yaml, .yml with apiVersion/kind headers): pod-security misconfigs
"""
from __future__ import annotations

import re

from vulnscanner.analyzers.base import BaseAnalyzer
from vulnscanner.models import Finding, Severity, VulnType

_IAC = VulnType.IAC_MISCONFIGURATION

_TF_RULES: list[tuple[str, re.Pattern, str, Severity]] = [
    (
        "IAC-TF-001",
        re.compile(r'\bacl\s*=\s*"(?:public-read|public-read-write)"', re.IGNORECASE),
        "S3 bucket ACL allows public access — data exposure risk",
        Severity.HIGH,
    ),
    (
        "IAC-TF-002",
        re.compile(r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"', re.IGNORECASE),
        "Security group ingress open to 0.0.0.0/0 — unrestricted inbound access",
        Severity.HIGH,
    ),
    (
        "IAC-TF-003",
        re.compile(r'\bpublicly_accessible\s*=\s*true\b', re.IGNORECASE),
        "RDS/database instance publicly accessible — exposes database to the internet",
        Severity.CRITICAL,
    ),
    (
        "IAC-TF-004",
        re.compile(r'\bencrypted\s*=\s*false\b', re.IGNORECASE),
        "Storage volume encryption disabled — data at rest unprotected",
        Severity.MEDIUM,
    ),
    (
        "IAC-TF-005",
        re.compile(
            r'"Action"\s*:\s*(?:"\*"|\[(?:[^]]*,\s*)?"?\*"?\s*\])'
            r'|actions\s*=\s*\[[^\]]*"\*"[^\]]*\]',
            re.IGNORECASE,
        ),
        "IAM policy grants wildcard (*) Action — violates least-privilege principle",
        Severity.HIGH,
    ),
    (
        "IAC-TF-006",
        re.compile(r'\bforce_destroy\s*=\s*true\b', re.IGNORECASE),
        "S3 bucket has force_destroy=true — bucket and all objects can be deleted in one operation",
        Severity.MEDIUM,
    ),
    (
        "IAC-TF-007",
        re.compile(r'\bskip_final_snapshot\s*=\s*true\b', re.IGNORECASE),
        "RDS instance skips final snapshot on deletion — data loss risk",
        Severity.MEDIUM,
    ),
    (
        "IAC-TF-008",
        re.compile(r'\bdeletion_protection\s*=\s*false\b', re.IGNORECASE),
        "Database deletion protection disabled — database can be accidentally destroyed",
        Severity.LOW,
    ),
]

_TF_GUARD = re.compile(
    r'\bacl\s*=|cidr_blocks\s*=|publicly_accessible\s*=|encrypted\s*=\b'
    r'|force_destroy\s*=|skip_final_snapshot\s*=|deletion_protection\s*=\b'
    r'|"Action"\s*:|actions\s*=\s*\[',
    re.IGNORECASE,
)

_K8S_GUARD = re.compile(r'\bapiVersion\s*:', re.IGNORECASE)

_K8S_RULES: list[tuple[str, re.Pattern, str, Severity]] = [
    (
        "IAC-K8S-001",
        re.compile(r'\bprivileged\s*:\s*true\b', re.IGNORECASE),
        "Container runs in privileged mode — full host kernel access granted",
        Severity.CRITICAL,
    ),
    (
        "IAC-K8S-002",
        re.compile(r'\bhostNetwork\s*:\s*true\b', re.IGNORECASE),
        "Pod uses host network namespace — bypasses network isolation",
        Severity.HIGH,
    ),
    (
        "IAC-K8S-003",
        re.compile(r'\bhostPID\s*:\s*true\b', re.IGNORECASE),
        "Pod shares host PID namespace — can inspect/signal all host processes",
        Severity.HIGH,
    ),
    (
        "IAC-K8S-004",
        re.compile(r'\bhostIPC\s*:\s*true\b', re.IGNORECASE),
        "Pod shares host IPC namespace — can access host shared memory",
        Severity.HIGH,
    ),
    (
        "IAC-K8S-005",
        re.compile(r'\btype\s*:\s*NodePort\b', re.IGNORECASE),
        "Service type NodePort exposes a port on every cluster node — prefer ClusterIP + Ingress",
        Severity.MEDIUM,
    ),
    (
        "IAC-K8S-006",
        re.compile(
            r'\badd\s*:\s*\[?[^\]\n]*\b(?:SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL)\b',
            re.IGNORECASE,
        ),
        "Container adds dangerous Linux capability (SYS_ADMIN/NET_ADMIN/ALL) — privilege escalation risk",
        Severity.CRITICAL,
    ),
    (
        "IAC-K8S-007",
        re.compile(r'\ballowPrivilegeEscalation\s*:\s*true\b', re.IGNORECASE),
        "allowPrivilegeEscalation=true lets a process gain more privileges than its parent",
        Severity.HIGH,
    ),
    (
        "IAC-K8S-008",
        re.compile(r'\brunAsUser\s*:\s*0\b', re.IGNORECASE),
        "Container runs as UID 0 (root) — break-out leads to full node compromise",
        Severity.HIGH,
    ),
    (
        "IAC-K8S-009",
        re.compile(r'\breadOnlyRootFilesystem\s*:\s*false\b', re.IGNORECASE),
        "Root filesystem is writable — attacker can persist changes inside the container",
        Severity.MEDIUM,
    ),
]

_K8S_RULE_GUARD = re.compile(
    r'\bprivileged\s*:|hostNetwork\s*:|hostPID\s*:|hostIPC\s*:'
    r'|type\s*:\s*NodePort|\badd\s*:\s*\[?'
    r'|allowPrivilegeEscalation\s*:|runAsUser\s*:|readOnlyRootFilesystem\s*:',
    re.IGNORECASE,
)


class IaCAnalyzer(BaseAnalyzer):
    supported_extensions = (".tf", ".yaml", ".yml")

    def analyze(self, file_path: str, content: str, repo_url: str = "") -> list[Finding]:
        if file_path.endswith(".tf"):
            return self._scan_terraform(file_path, content, repo_url)
        if file_path.endswith((".yaml", ".yml")) and _K8S_GUARD.search(content):
            return self._scan_kubernetes(file_path, content, repo_url)
        return []

    def _scan_terraform(self, file_path: str, content: str, repo_url: str) -> list[Finding]:
        if not _TF_GUARD.search(content):
            return []
        lines = content.splitlines()
        findings: list[Finding] = []
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for rule_id, pattern_re, description, severity in _TF_RULES:
                if pattern_re.search(line):
                    findings.append(Finding(
                        vuln_type=_IAC,
                        severity=severity,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=stripped,
                        description=description,
                        rule_id=rule_id,
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    ))
        return findings

    def _scan_kubernetes(self, file_path: str, content: str, repo_url: str) -> list[Finding]:
        if not _K8S_RULE_GUARD.search(content):
            return []
        lines = content.splitlines()
        findings: list[Finding] = []
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for rule_id, pattern_re, description, severity in _K8S_RULES:
                if pattern_re.search(line):
                    findings.append(Finding(
                        vuln_type=_IAC,
                        severity=severity,
                        file_path=file_path,
                        line_number=lineno,
                        line_content=stripped,
                        description=description,
                        rule_id=rule_id,
                        repo_url=repo_url,
                        snippet=self._extract_snippet(lines, lineno),
                    ))
        return findings
