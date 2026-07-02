from vulnscanner.scanner import VulnScanner

result = VulnScanner().scan("C:/VulnScanner/recall")
for f in sorted(result.findings, key=lambda x: (x.file_path, x.line_number)):
    rel = f.file_path.replace("\\", "/").split("/recall/")[-1]
    print(f"{f.rule_id:<18} {f.severity.value:<10} {rel}:{f.line_number}")
print()
print(f"Total: {len(result.findings)} findings, {result.suppressed_count} suppressed")
print("Suppression:", result.suppression_breakdown)
