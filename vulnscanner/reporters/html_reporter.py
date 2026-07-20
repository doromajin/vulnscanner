"""Self-contained HTML report generator for VulnScanner."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from vulnscanner.models import ScanResult, Severity
from vulnscanner.reporters.fix_suggestions import get_fix

_SEV_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
    "INFO":     "#888888",
}

_SEV_BG = {
    "CRITICAL": "#3a0000",
    "HIGH":     "#2a1a00",
    "MEDIUM":   "#2a2200",
    "LOW":      "#001a2a",
    "INFO":     "#1a1a1a",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.5; }
a { color: #58a6ff; }
header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; align-items: center; gap: 16px; }
header h1 { font-size: 1.2rem; color: #f0f6fc; }
header .meta { font-size: 0.8rem; color: #8b949e; }
.summary { display: flex; gap: 12px; padding: 16px 24px; flex-wrap: wrap; }
.stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 20px; min-width: 110px; text-align: center; }
.stat-card .num { font-size: 1.8rem; font-weight: 700; }
.stat-card .label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: .05em; }
.filters { padding: 8px 24px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.filters label { font-size: 0.8rem; color: #8b949e; margin-right: 4px; }
.filter-btn { background: #21262d; border: 1px solid #30363d; border-radius: 20px; color: #c9d1d9; cursor: pointer; font-size: 0.8rem; padding: 4px 14px; transition: all .15s; }
.filter-btn.active { border-color: #388bfd; background: #1f3a5f; color: #c9d1d9; }
.filter-btn:hover { border-color: #58a6ff; }
.search-box { margin-left: auto; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 0.85rem; padding: 5px 10px; width: 220px; }
.search-box:focus { border-color: #388bfd; outline: none; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
thead tr { background: #161b22; border-bottom: 2px solid #30363d; }
thead th { color: #8b949e; font-weight: 600; padding: 10px 12px; text-align: left; cursor: pointer; user-select: none; white-space: nowrap; }
thead th:hover { color: #c9d1d9; }
tbody tr.finding-row { border-bottom: 1px solid #21262d; transition: background .1s; cursor: pointer; }
tbody tr.finding-row:hover { background: #161b22; }
tbody tr.finding-row.hidden { display: none; }
tbody td { padding: 9px 12px; vertical-align: middle; }
.sev-badge { border-radius: 4px; display: inline-block; font-size: 0.7rem; font-weight: 700; letter-spacing: .05em; padding: 2px 7px; text-transform: uppercase; white-space: nowrap; }
.rule-id { font-family: monospace; font-size: 0.8rem; color: #8b949e; }
.file-path { color: #58a6ff; font-family: monospace; font-size: 0.8rem; white-space: nowrap; }
.conf { color: #8b949e; font-size: 0.8rem; }
.detail-row { background: #0d1117; display: none; }
.detail-row.open { display: table-row; }
.detail-cell { padding: 0 12px 12px 36px; }
.code-block { background: #161b22; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-family: monospace; font-size: 0.8rem; margin: 8px 0; overflow-x: auto; padding: 10px 14px; white-space: pre; }
.fix-box { background: #0e2630; border: 1px solid #1b6a7a; border-radius: 6px; color: #8be0ec; font-size: 0.8rem; margin-top: 8px; padding: 10px 14px; }
.fix-box strong { color: #56d3e8; display: block; margin-bottom: 4px; }
.new-badge { background: #1a7f37; border-radius: 3px; color: #fff; font-size: 0.65rem; font-weight: 700; margin-left: 6px; padding: 1px 5px; vertical-align: middle; }
.no-findings { color: #8b949e; padding: 40px; text-align: center; }
.table-wrap { overflow-x: auto; padding: 0 24px 24px; }
"""

_JS = """
const rows = document.querySelectorAll('.finding-row');
const details = document.querySelectorAll('.detail-row');

// Toggle detail row
rows.forEach((row, i) => {
  row.addEventListener('click', () => {
    const d = details[i];
    const open = d.classList.toggle('open');
    row.classList.toggle('expanded', open);
  });
});

// Severity filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const sev = btn.dataset.sev;
    const active = btn.classList.toggle('active');
    applyFilters();
  });
});

// Search
document.getElementById('search').addEventListener('input', applyFilters);

function applyFilters() {
  const activeSevs = [...document.querySelectorAll('.filter-btn.active')].map(b => b.dataset.sev);
  const q = document.getElementById('search').value.toLowerCase();
  let visible = 0;
  rows.forEach((row, i) => {
    const sev = row.dataset.sev;
    const text = row.textContent.toLowerCase();
    const sevOk = activeSevs.length === 0 || activeSevs.includes(sev);
    const qOk = !q || text.includes(q);
    const hide = !sevOk || !qOk;
    row.classList.toggle('hidden', hide);
    details[i].classList.toggle('hidden', hide);
    if (!hide) visible++;
  });
  document.getElementById('visible-count').textContent = visible;
}

// Sort
let sortCol = -1, sortAsc = true;
document.querySelectorAll('thead th[data-col]').forEach(th => {
  th.addEventListener('click', () => {
    const col = +th.dataset.col;
    if (sortCol === col) sortAsc = !sortAsc; else { sortCol = col; sortAsc = true; }
    sortTable(col, sortAsc);
  });
});

function sortTable(col, asc) {
  const tbody = document.querySelector('tbody');
  const pairs = [];
  for (let i = 0; i < rows.length; i++) pairs.push([rows[i], details[i]]);
  pairs.sort((a, b) => {
    const va = a[0].cells[col]?.textContent.trim() || '';
    const vb = b[0].cells[col]?.textContent.trim() || '';
    return asc ? va.localeCompare(vb, undefined, {numeric: true}) : vb.localeCompare(va, undefined, {numeric: true});
  });
  pairs.forEach(([r, d]) => { tbody.appendChild(r); tbody.appendChild(d); });
}
"""


def _sev_badge(severity: str) -> str:
    color = _SEV_COLOR.get(severity, "#888")
    bg = _SEV_BG.get(severity, "#1a1a1a")
    return f'<span class="sev-badge" style="color:{color};background:{bg}">{html.escape(severity)}</span>'


def _conf_str(confidence: float) -> str:
    if confidence >= 1.0:
        return "—"
    return f"{confidence:.0%}"


def write_html(
    result: ScanResult,
    output_path: str,
    new_finding_keys: set[tuple[str, int, str]] | None = None,
) -> None:
    """Write a self-contained HTML report to *output_path*."""
    findings = result.findings
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target = html.escape(result.repo_url)

    counts = {s: len(result.by_severity(s)) for s in Severity}
    total = sum(counts.values())

    # ── summary cards ────────────────────────────────────────────────────────
    cards_html = ""
    for sev in Severity:
        n = counts[sev]
        color = _SEV_COLOR[sev.value]
        cards_html += (
            f'<div class="stat-card">'
            f'<div class="num" style="color:{color}">{n}</div>'
            f'<div class="label">{sev.value}</div>'
            f'</div>\n'
        )
    cards_html += (
        f'<div class="stat-card">'
        f'<div class="num">{result.scanned_files}</div>'
        f'<div class="label">Files</div>'
        f'</div>\n'
        f'<div class="stat-card">'
        f'<div class="num">{result.scanned_lines:,}</div>'
        f'<div class="label">Lines</div>'
        f'</div>\n'
    )

    # ── filter buttons ───────────────────────────────────────────────────────
    filter_btns = ""
    for sev in Severity:
        if counts[sev] > 0:
            filter_btns += (
                f'<button class="filter-btn" data-sev="{sev.value}">'
                f'{sev.value} ({counts[sev]})</button>\n'
            )

    # ── findings rows ────────────────────────────────────────────────────────
    rows_html = ""
    if not findings:
        rows_html = '<tr><td colspan="7" class="no-findings">No findings to display.</td></tr>'
    else:
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            is_new = (
                new_finding_keys is not None
                and (f.file_path, f.line_number, f.rule_id) in new_finding_keys
            )
            new_badge = '<span class="new-badge">NEW</span>' if is_new else ""
            file_short = html.escape(Path(f.file_path).name)
            file_full  = html.escape(f.file_path)
            desc = html.escape(f.description or "")
            rule = html.escape(f.rule_id)
            vuln = html.escape(f.vuln_type.value if hasattr(f.vuln_type, "value") else str(f.vuln_type))

            rows_html += (
                f'<tr class="finding-row" data-sev="{sev}">'
                f'<td>{_sev_badge(sev)}{new_badge}</td>'
                f'<td><span class="rule-id">{rule}</span></td>'
                f'<td>{vuln}</td>'
                f'<td><span class="file-path" title="{file_full}">{file_short}</span></td>'
                f'<td>{f.line_number}</td>'
                f'<td class="conf">{_conf_str(f.confidence)}</td>'
                f'<td>{desc}</td>'
                f'</tr>\n'
            )

            # Detail row: code snippet + fix
            code_block = ""
            snippet = getattr(f, "snippet", None) or getattr(f, "line_content", None)
            if snippet:
                code_block = f'<div class="code-block">{html.escape(snippet)}</div>'

            fix_data = get_fix(f.vuln_type)
            fix_block = ""
            if fix_data.get("text"):
                fix_text = html.escape(fix_data["text"])
                fix_block = (
                    f'<div class="fix-box">'
                    f'<strong>Suggested Fix</strong>'
                    f'{fix_text}'
                    f'</div>'
                )

            rows_html += (
                f'<tr class="detail-row">'
                f'<td colspan="7" class="detail-cell">'
                f'<b>File:</b> <span class="file-path">{file_full}:{f.line_number}</span>'
                f'{code_block}{fix_block}'
                f'</td>'
                f'</tr>\n'
            )

    baseline_note = ""
    if new_finding_keys is not None:
        new_count = len(new_finding_keys)
        baseline_note = (
            f'<div style="padding:8px 24px;font-size:0.8rem;color:#8b949e;">'
            f'Baseline comparison active — '
            f'<b style="color:#1a7f37">{new_count} new</b> finding(s) vs. baseline'
            f'</div>'
        )

    elapsed = f"{result.elapsed_seconds:.1f}s"
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnScanner Report — {target}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <div>
    <h1>VulnScanner Report</h1>
    <div class="meta">{target} &nbsp;·&nbsp; {now} &nbsp;·&nbsp; scanned in {elapsed}</div>
  </div>
</header>
<div class="summary">{cards_html}</div>
{baseline_note}
<div class="filters">
  <label>Filter:</label>
  {filter_btns}
  <input id="search" class="search-box" placeholder="Search rule / file / description…" type="text">
  <span style="font-size:0.8rem;color:#8b949e;margin-left:8px">
    Showing <b id="visible-count">{total}</b> finding(s)
  </span>
</div>
<div class="table-wrap">
<table>
<thead>
  <tr>
    <th data-col="0">Severity</th>
    <th data-col="1">Rule</th>
    <th data-col="2">Type</th>
    <th data-col="3">File</th>
    <th data-col="4">Line</th>
    <th data-col="5">Conf</th>
    <th data-col="6">Description</th>
  </tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
</div>
<script>{_JS}</script>
</body>
</html>
"""
    Path(output_path).write_text(page, encoding="utf-8")
