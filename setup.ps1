# Windows version of setup.sh (PowerShell 5.1 or 7). Run it from the repo folder:
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1
# 1. creates the key pair that encrypts results (private half stays on this PC)
# 2. sets the ARTIFACT_PASSPHRASE secret
# 3. asks for your Claude token (subscription) or API key and stores it as a secret
# 4. commits and pushes the public key
# 5. asks whether the testers must sign in to the app, and if so for one test account per role
# The programs it needs are checked first, and installed if you agree (check.ps1).
$ErrorActionPreference = "Continue"
if (Test-Path (Join-Path $PSScriptRoot "check.ps1")) {
  & (Join-Path $PSScriptRoot "check.ps1") -Programs
  if ($LASTEXITCODE -ne 0) { exit 1 }
  Write-Host ""
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { Write-Host "Install the GitHub CLI: winget install --id GitHub.cli"; exit 1 }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Host "Install Git: winget install --id Git.Git"; exit 1 }
gh auth status *> $null; if ($LASTEXITCODE -ne 0) { Write-Host "Run: gh auth login"; exit 1 }

# openssl ships with Git for Windows
$openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
if (-not $openssl) {
  $gitDir = Split-Path (Split-Path (Get-Command git).Source)
  $openssl = @("$gitDir\usr\bin\openssl.exe", "$env:ProgramFiles\Git\usr\bin\openssl.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $openssl) { Write-Host "openssl not found: install Git for Windows (winget install --id Git.Git)"; exit 1 }

$repo = gh repo view --json nameWithOwner -q .nameWithOwner
Write-Host "Setting up agent testers for $repo"
if ((gh repo view --json visibility -q .visibility) -eq "PRIVATE") {
  Write-Host "Note: $repo is private. GitHub's runners are only free for public repos: here each macOS minute counts ten times against your Actions minutes."
}
$keyDir = Join-Path $HOME ".mobile-agent-testers"
New-Item -ItemType Directory -Force -Path $keyDir | Out-Null
$priv = Join-Path $keyDir (($repo -replace "/", "_") + ".pem")
if (-not (Test-Path $priv)) {
  & $openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out $priv
  Write-Host "Private key created: $priv (keep it safe, never commit it)"
}
& $openssl pkey -in $priv -pubout -out results_public.pem

$secrets = (gh secret list --json name -q ".[].name") -split "`n"
if ($secrets -notcontains "ARTIFACT_PASSPHRASE") {
  $bytes = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  gh secret set ARTIFACT_PASSPHRASE --body (($bytes | ForEach-Object { $_.ToString("x2") }) -join "")
  Write-Host "Secret ARTIFACT_PASSPHRASE set"
}
if (($secrets -notcontains "CLAUDE_CODE_OAUTH_TOKEN") -and ($secrets -notcontains "ANTHROPIC_API_KEY")) {
  Write-Host ""
  Write-Host "Claude access. Either:"
  Write-Host "  1) a Claude Pro/Max subscription: run 'claude setup-token' in another terminal and paste the token"
  Write-Host "  2) an Anthropic API key (pay per token)"
  do { $choice = Read-Host "Choose 1 or 2" } while (($choice -ne "1") -and ($choice -ne "2"))
  $name = if ($choice -eq "2") { "ANTHROPIC_API_KEY" } else { "CLAUDE_CODE_OAUTH_TOKEN" }
  $prefix = if ($choice -eq "2") { "sk-ant-api" } else { "sk-ant-oat" }
  do {
    $secure = Read-Host "Paste it (hidden)" -AsSecureString
    $plain = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))).Trim()
    if (-not $plain) { Write-Host "Nothing pasted, try again." }
  } while (-not $plain)
  if (-not $plain.StartsWith($prefix)) { Write-Host "Warning: it does not start with $prefix." }
  gh secret set $name --body $plain
  Remove-Variable plain
  Write-Host "Secret $name set"
}

git add results_public.pem
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) { git commit -qm "Add results public key"; git push -q; Write-Host "Public key committed and pushed" }

# 5. Test accounts, when the testers must sign in (scripts/accounts.py)
if (Test-Path "scripts\accounts.py") {
  Write-Host ""
  if ($secrets -contains "TEST_ACCOUNTS") {
    Write-Host "Test accounts are already saved. To change them: python scripts\accounts.py set"
  } else {
    $answer = Read-Host "Do your testers need to sign in to the app with test accounts? [y/N]"
    if ($answer -match "^(y|yes)$") {
      $env:BA3TRATION_SETUP = "1"
      $python = ""
      foreach ($name in @("python", "py", "python3")) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { continue }
        if ($name -eq "py") { & py -3 -c "pass" *> $null } else { & $name -c "pass" *> $null }
        if ($LASTEXITCODE -eq 0) { $python = $name; break }
      }
      if ($python -eq "") { Write-Host "Python 3 was not found: run .\check.ps1, then python scripts\accounts.py set" }
      elseif ($python -eq "py") { & py -3 scripts/accounts.py set }
      else { & $python scripts/accounts.py set }
      Remove-Item Env:BA3TRATION_SETUP
      git add personas.json
      git diff --cached --quiet
      if ($LASTEXITCODE -ne 0) { git commit -qm "Personas: test account roles"; git push -q; Write-Host "personas.json committed and pushed" }
    } else { Write-Host "Later, if they do: python scripts\accounts.py set" }
  }
}
Write-Host ""
Write-Host "Done. Run the demo (2 Android + 2 iOS testers on the demo app, about 20 min):"
Write-Host "  gh workflow run agent-testers.yml"
Write-Host "Follow it:"
Write-Host "  gh run watch"
Write-Host "Then download and decrypt the reports:"
Write-Host "  .\collect.ps1 <run id>"
Write-Host "Is everything in place? At any time:"
Write-Host "  .\check.ps1"
