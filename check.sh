#!/usr/bin/env bash
# Checks that this machine and this repo have what Ba3tration-tester needs, and installs
# the programs that are missing (Homebrew on a Mac, apt on Debian or Ubuntu), after asking once.
#   ./check.sh               check, offer to install what is missing, then say what is left to do
#   ./check.sh --no-install  only say what is missing
#   ./check.sh --programs    the programs only, not the repo (what setup.sh runs first)
#   ./check.sh --yes         install without asking (it never installs unasked when no one is at the keyboard)
# It reads no secret: it asks GitHub for the names of the secrets, and looks whether your key file exists.
# Windows: .\check.ps1
set -uo pipefail
INSTALL=1; REPO_CHECKS=1; YES=0
for arg in "$@"; do
  case "$arg" in
    --no-install) INSTALL=0 ;;
    --programs) REPO_CHECKS=0 ;;
    --yes) YES=1 ;;
    *) echo "Usage: ./check.sh [--no-install] [--programs] [--yes]"; exit 2 ;;
  esac
done
have() {   # BA3TRATION_CHECK_MISSING: programs to take for missing (the tests)
  case " ${BA3TRATION_CHECK_MISSING:-} " in *" $1 "*) return 1 ;; esac
  command -v "$1" >/dev/null 2>&1
}
ok()   { echo "  ok       $1"; }
miss() { echo "  MISSING  $1"; PROBLEMS=$((PROBLEMS + 1)); }
todo() { echo "  TO DO    $1"; PROBLEMS=$((PROBLEMS + 1)); }
info() { echo "  -        $1"; }

# program, what it is for, Homebrew package, apt package
PROGRAMS="git|Git|git|git
gh|GitHub CLI (starts the runs, stores the secrets, downloads the results)|gh|gh
openssl|OpenSSL (the key that encrypts your results)|openssl|openssl
python3|Python 3 (the reports, the test accounts)|python|python3"

programs() {
  PROBLEMS=0; MISSING=""
  echo "Programs on this machine:"
  while IFS='|' read -r cmd what _ _; do
    if have "$cmd"; then ok "$what"; else miss "$what"; MISSING="$MISSING $cmd"; fi
  done <<<"$PROGRAMS"
}

programs
if [ -n "$MISSING" ] && [ "$INSTALL" = 1 ]; then
  if have brew; then tool=brew; elif have apt-get; then tool=apt; else tool=""; fi
  pkgs=""
  for cmd in $MISSING; do
    line=$(grep "^$cmd|" <<<"$PROGRAMS")
    brew=$(cut -d'|' -f3 <<<"$line"); apt=$(cut -d'|' -f4 <<<"$line")
    if [ "$tool" = brew ]; then pkgs="$pkgs $brew"; elif [ "$tool" = apt ]; then pkgs="$pkgs $apt"; fi
  done
  if [ -z "$tool" ]; then
    echo
    echo "Neither Homebrew nor apt here: install what is missing yourself (a Mac: https://brew.sh first), then run this again."
  else
    if [ "$tool" = brew ]; then command="brew install$pkgs"; else command="sudo apt-get update && sudo apt-get install -y$pkgs"; fi
    echo
    echo "To install what is missing:  $command"
    answer=n
    if [ "$YES" = 1 ]; then answer=y
    elif [ -t 0 ]; then read -rp "Run it now? [Y/n] " answer || answer=n; answer=${answer:-y}
    fi
    case "$answer" in
      y|Y|yes|Yes)
        # shellcheck disable=SC2086  # several package names, one word each
        if [ "$tool" = brew ]; then brew install $pkgs; else sudo apt-get update && sudo apt-get install -y $pkgs; fi
        echo; programs ;;
      *) echo "Not installed." ;;
    esac
  fi
fi
if [ -n "$MISSING" ]; then
  echo
  echo "Still missing:$MISSING. Install them, open a new terminal and run ./check.sh again."
  exit 1
fi
[ "$REPO_CHECKS" = 1 ] || exit 0

echo
echo "Your GitHub account and this repo:"
PROBLEMS=0
if ! gh auth status >/dev/null 2>&1; then
  todo "log in to GitHub:  gh auth login"
  echo; echo "Then run ./check.sh again."; exit 1
fi
ok "logged in to GitHub"
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)
if [ -z "$REPO" ]; then
  todo "this folder is not a GitHub repo that gh can name. Make yours from the template, or, with several remotes:  gh repo set-default <owner>/<name>"
  echo; echo "Then run ./check.sh again."; exit 1
fi
ok "repo $REPO"
if [ -f "$HOME/.mobile-agent-testers/${REPO//\//_}.pem" ] && [ -s results_public.pem ]; then
  ok "encryption key (the private half is on this machine)"
else
  todo "encryption key:  ./setup.sh"
fi
SECRETS=$(gh secret list --json name -q '.[].name' 2>/dev/null || true)
has() { grep -qx "$1" <<<"$SECRETS"; }
if has ARTIFACT_PASSPHRASE; then ok "secret ARTIFACT_PASSPHRASE"; else todo "secret ARTIFACT_PASSPHRASE:  ./setup.sh"; fi
if has CLAUDE_CODE_OAUTH_TOKEN || has ANTHROPIC_API_KEY || has LLM_API_KEY; then
  ok "a model key for the testers"
else
  todo "a model key for the testers (Claude token or API key):  ./setup.sh"
fi
if has TEST_ACCOUNTS; then ok "test accounts (secret TEST_ACCOUNTS)"
else info "no test accounts: the testers start signed out. To give them some:  python3 scripts/accounts.py set"; fi
if has STAGING_URL; then ok "live scan target (secret STAGING_URL)"
else info "no live scan target: the live scan is skipped (docs/security-scan.md)"; fi

echo
if [ "$PROBLEMS" = 0 ]; then
  echo "Everything the tool needs is here. Start a run:  gh workflow run ba3tration.yml"
else
  echo "$PROBLEMS thing(s) left to do, listed above as TO DO."
  exit 1
fi
