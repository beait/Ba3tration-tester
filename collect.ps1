# Windows version of the collect step (PowerShell 5.1 or 7). Run it from the repo folder:
#   powershell -ExecutionPolicy Bypass -File .\collect.ps1 <run id>
# It runs scripts/collect.sh with the bash of Git for Windows. A plain `bash` in PowerShell is
# often the one of WSL, which sees neither gh nor the key in your user folder.
param([Parameter(Mandatory = $true)][string]$RunId, [string]$Key = "", [string]$Out = "")
$ErrorActionPreference = "Continue"
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { Write-Host "Install the GitHub CLI: winget install --id GitHub.cli"; exit 1 }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Host "Install Git: winget install --id Git.Git"; exit 1 }

$gitDir = Split-Path (Split-Path (Get-Command git).Source)
$bash = @("$gitDir\bin\bash.exe", "$env:ProgramFiles\Git\bin\bash.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $bash) { Write-Host "The bash of Git for Windows was not found: install it (winget install --id Git.Git)"; exit 1 }

# several remotes (the template next to your repo): gh must be told which repo is yours, once
gh repo view --json nameWithOwner -q .nameWithOwner *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "Tell gh which repo this is, once:  gh repo set-default <owner>/<name>"; exit 1 }

$collectArgs = @("scripts/collect.sh", $RunId)
if ($Key -ne "") { $collectArgs += $Key.Replace("\", "/") }
if ($Out -ne "") { if ($Key -eq "") { Write-Host "Give the key path before the output folder"; exit 1 }; $collectArgs += $Out.Replace("\", "/") }
Push-Location $PSScriptRoot
& $bash @collectArgs
$code = $LASTEXITCODE
Pop-Location
if ($code -ne 0) { exit $code }

$dir = if ($Out -ne "") { $Out } else { Join-Path "runs" $RunId }
Write-Host ""
$text = Join-Path $dir "BA3TRATION-REPORT.txt"
if (Test-Path (Join-Path $PSScriptRoot $text)) {
  Write-Host "The report as a text file: $text"
  Write-Host "  notepad $text"
} elseif (Test-Path (Join-Path $PSScriptRoot (Join-Path $dir "SUMMARY.md"))) {
  Write-Host "The summary (read it as UTF-8, or Windows PowerShell shows Arabic as symbols):"
  Write-Host "  Get-Content $(Join-Path $dir "SUMMARY.md") -Encoding UTF8"
}
