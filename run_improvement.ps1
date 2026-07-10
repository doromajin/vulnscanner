# VulnScanner 改善ループ 手動起動スクリプト
# 使い方: .\run_improvement.ps1 [-MaxHours 4] [-StopAt "05:00"]

param(
    [double]$MaxHours = 4.0,
    [string]$StopAt   = ""
)

$VulnDir = "C:\VulnScanner"
$LogDir  = "$VulnDir\improvement_runs\logs"

New-Item -ItemType Directory -Force $LogDir | Out-Null
$LogFile = Join-Path $LogDir ("run_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

$Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path $LogFile -Value "=== 起動: $Stamp ==="

$PyArgs = @("$VulnDir\improvement_loop.py", "--max-hours", $MaxHours)
if ($StopAt -ne "") { $PyArgs += @("--stop-at", $StopAt) }

Set-Location $VulnDir
python @PyArgs 2>&1 | Tee-Object -FilePath $LogFile -Append

$Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content -Path $LogFile -Value "=== 終了: $Stamp ==="
Write-Host "ログ: $LogFile"
