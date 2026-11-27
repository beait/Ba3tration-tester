# Windows version of check.sh (PowerShell 5.1 or 7). Run it from the repo folder:
#   powershell -ExecutionPolicy Bypass -File .\check.ps1
# Checks that this computer and this repo have what Ba3tration-tester needs, and installs the
# programs that are missing with winget, after asking once.
#   -NoInstall   only say what is missing
#   -Programs    the programs only, not the repo (what setup.ps1 runs first)
#   -Yes         install without asking
# It reads no secret: it asks GitHub for the names of the secrets, and looks whether your key file exists.
param([switch]$NoInstall, [switch]$Programs, [switch]$Yes)
$ErrorActionPreference = "Continue"
$script:problems = 0
function Say-Ok($text) { Write-Host "  ok       $text" }
function Say-Missing($text) { Write-Host "  MISSING  $text"; $script:problems++ }
function Say-Todo($text) { Write-Host "  TO DO    $text"; $script:problems++ }
function Say-Info($text) { Write-Host "  -        $text" }

# The python3 that Windows ships is a shortcut to the Store that runs nothing: each name is tried, not trusted
function Find-Python {
  foreach ($name in @("python", "py", "python3")) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { continue }
    if ($name -eq "py") { & py -3 -c "pass" *> $null } else { & $name -c "pass" *> $null }
    if ($LASTEXITCODE -eq 0) { if ($name -eq "py") { return "py -3" } else { return $name } }
  }
  return ""
}

function Test-Programs {
  $missing = @()
  Write-Host "Programs on this computer:"
  if (Get-Command git -ErrorAction SilentlyContinue) {
    Say-Ok "Git"
    $gitDir = Split-Path (Split-Path (Get-Command git).Source)
    if (Test-Path "$gitDir\bin\bash.exe") { Say-Ok "bash and OpenSSL of Git for Windows (the key, the collect step)" }
    else { Say-Missing "bash of Git for Windows (this Git has none)"; $missing += "Git.Git" }
  } else { Say-Missing "Git (with its bash and OpenSSL)"; $missing += "Git.Git" }
  if (Get-Command gh -ErrorAction SilentlyContinue) { Say-Ok "GitHub CLI (starts the runs, stores the secrets, downloads the results)" }
  else { Say-Missing "GitHub CLI (starts the runs, stores the secrets, downloads the results)"; $missing += "GitHub.cli" }
  if ((Find-Python) -ne "") { Say-Ok "Python 3 (the reports, the test accounts)" }
  else { Say-Missing "Python 3 (the reports, the test accounts)"; $missing += "Python.Python.3.13" }
  return , $missing
}

$missing = Test-Programs
if (($missing.Count -gt 0) -and (-not $NoInstall)) {
  Write-Host ""
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "winget is not on this computer: install 'App Installer' from the Microsoft Store, then run this again."
  } else {
    Write-Host "To install what is missing:"
    foreach ($id in $missing) { Write-Host "  winget install --id $id -e" }
    $answer = "y"
    if (-not $Yes) { $answer = Read-Host "Run it now? [Y/n]" }
    if ($answer -match "^(n|no)$") { Write-Host "Not installed." }
    else {
      foreach ($id in $missing) { winget install --id $id -e --accept-source-agreements --accept-package-agreements }
      # what was just installed is not on this window's PATH yet: read the PATH again
      $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
      Write-Host ""
      $missing = Test-Programs
    }
  }
}
if ($missing.Count -gt 0) {
  Write-Host ""
  Write-Host "Still missing: $($missing -join ', '). Install them, open a new PowerShell window and run .\check.ps1 again."
  exit 1
}
if ($Programs) { exit 0 }

Write-Host ""
Write-Host "Your GitHub account and this repo:"
$script:problems = 0
gh auth status *> $null
if ($LASTEXITCODE -ne 0) {
  Say-Todo "log in to GitHub:  gh auth login"
  Write-Host ""; Write-Host "Then run .\check.ps1 again."; exit 1
}
Say-Ok "logged in to GitHub"
$repo = gh repo view --json nameWithOwner -q .nameWithOwner 2> $null
if (-not $repo) {
  Say-Todo "this folder is not a GitHub repo that gh can name. Make yours from the template, or, with several remotes:  gh repo set-default <owner>/<name>"
  Write-Host ""; Write-Host "Then run .\check.ps1 again."; exit 1
}
Say-Ok "repo $repo"
$priv = Join-Path (Join-Path $HOME ".mobile-agent-testers") (($repo -replace "/", "_") + ".pem")
if ((Test-Path $priv) -and (Test-Path "results_public.pem")) { Say-Ok "encryption key (the private half is on this computer)" }
else { Say-Todo "encryption key:  .\setup.ps1" }
$secrets = @((gh secret list --json name -q ".[].name" 2> $null) -split "`n" | ForEach-Object { "$_".Trim() })
if ($secrets -contains "ARTIFACT_PASSPHRASE") { Say-Ok "secret ARTIFACT_PASSPHRASE" } else { Say-Todo "secret ARTIFACT_PASSPHRASE:  .\setup.ps1" }
if (($secrets -contains "CLAUDE_CODE_OAUTH_TOKEN") -or ($secrets -contains "ANTHROPIC_API_KEY") -or ($secrets -contains "LLM_API_KEY")) { Say-Ok "a model key for the testers" }
else { Say-Todo "a model key for the testers (Claude token or API key):  .\setup.ps1" }
if ($secrets -contains "TEST_ACCOUNTS") { Say-Ok "test accounts (secret TEST_ACCOUNTS)" }
else { Say-Info "no test accounts: the testers start signed out. To give them some:  python scripts\accounts.py set" }
if ($secrets -contains "STAGING_URL") { Say-Ok "live scan target (secret STAGING_URL)" }
else { Say-Info "no live scan target: the live scan is skipped (docs\security-scan.md)" }

Write-Host ""
if ($script:problems -eq 0) { Write-Host "Everything the tool needs is here. Start a run:  gh workflow run ba3tration.yml" }
else { Write-Host "$($script:problems) thing(s) left to do, listed above as TO DO."; exit 1 }
