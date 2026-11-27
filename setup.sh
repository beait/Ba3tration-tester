#!/usr/bin/env bash
# One-time setup of a testers repo (run it from the repo you created from this template):
#  1. creates the key pair that encrypts results (private half stays on this machine)
#  2. sets the ARTIFACT_PASSPHRASE secret
#  3. asks for your Claude token (subscription) or API key and stores it as a secret
#  4. commits and pushes the public key
#  5. asks whether the testers must sign in to the app, and if so for one test account per role
# The programs it needs are checked first, and installed if you agree (check.sh).
set -euo pipefail
if [ -f check.sh ]; then bash check.sh --programs || exit 1; echo; fi
command -v gh >/dev/null || { echo "Install the GitHub CLI first: https://cli.github.com"; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Run: gh auth login"; exit 1; }
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
echo "Setting up agent testers for $REPO"
if [ "$(gh repo view --json visibility -q .visibility 2>/dev/null)" = PRIVATE ]; then
  echo "Note: $REPO is private. GitHub's runners are only free for public repos: here each macOS minute counts ten times against your Actions minutes."
fi

KEYDIR="$HOME/.mobile-agent-testers"; mkdir -p "$KEYDIR"; chmod 700 "$KEYDIR"
PRIV="$KEYDIR/${REPO//\//_}.pem"
if [ ! -f "$PRIV" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$PRIV" 2>/dev/null
  chmod 600 "$PRIV"
  echo "Private key created: $PRIV (keep it safe, never commit it)"
fi
openssl pkey -in "$PRIV" -pubout -out results_public.pem

SECRETS=$(gh secret list --json name -q '.[].name' 2>/dev/null || true)
if ! grep -qx ARTIFACT_PASSPHRASE <<<"$SECRETS"; then
  openssl rand -hex 32 | gh secret set ARTIFACT_PASSPHRASE
  echo "Secret ARTIFACT_PASSPHRASE set"
fi
if ! grep -qxE 'CLAUDE_CODE_OAUTH_TOKEN|ANTHROPIC_API_KEY' <<<"$SECRETS"; then
  echo
  echo "Claude access. Either:"
  echo "  1) a Claude Pro/Max subscription: run 'claude setup-token' in another terminal and paste the token"
  echo "  2) an Anthropic API key (pay per token)"
  CHOICE=""
  while [ "$CHOICE" != 1 ] && [ "$CHOICE" != 2 ]; do read -rp "Choose 1 or 2: " CHOICE; done
  if [ "$CHOICE" = 1 ]; then
    NAME=CLAUDE_CODE_OAUTH_TOKEN PREFIX=sk-ant-oat KIND="token from claude setup-token"
    command -v claude >/dev/null || echo "Claude Code is not installed here: npm install -g @anthropic-ai/claude-code, then claude setup-token"
  else
    NAME=ANTHROPIC_API_KEY PREFIX=sk-ant-api KIND="Anthropic API key"
  fi
  while :; do
    read -rsp "Paste it (hidden): " VALUE; echo
    VALUE=$(printf '%s' "$VALUE" | tr -d '[:space:]')
    if [ -z "$VALUE" ]; then echo "Nothing pasted, try again."; continue; fi
    case "$VALUE" in "$PREFIX"*) ;; *) echo "Warning: it does not start with $PREFIX, like a $KIND does." ;; esac
    if [ "$CHOICE" = 2 ] && command -v curl >/dev/null; then
      # free endpoint, no tokens used; the key goes through stdin, not the command line
      STATUS=$(printf 'x-api-key: %s\nanthropic-version: 2023-06-01\n' "$VALUE" |
        curl -s -m 15 -o /dev/null -w '%{http_code}' -H @- https://api.anthropic.com/v1/models || true)
      if [ "$STATUS" = 401 ] || [ "$STATUS" = 403 ]; then echo "Anthropic refused this key ($STATUS): paste another one."; continue; fi
      [ "$STATUS" = 200 ] && echo "Key checked with Anthropic."
    fi
    break
  done
  printf '%s' "$VALUE" | gh secret set "$NAME"
  unset VALUE
  echo "Secret $NAME set"
fi

if ! git diff --quiet -- results_public.pem 2>/dev/null || ! git ls-files --error-unmatch results_public.pem >/dev/null 2>&1; then
  git add results_public.pem && git commit -qm "Add results public key" && git push -q
  echo "Public key committed and pushed"
fi
# 5. Test accounts, when the testers must sign in (scripts/accounts.py). Only with someone at the keyboard.
if [ -f scripts/accounts.py ] && [ -t 0 ]; then
  echo
  if grep -qx TEST_ACCOUNTS <<<"$SECRETS"; then
    echo "Test accounts are already saved. To change them: python3 scripts/accounts.py set"
  else
    read -rp "Do your testers need to sign in to the app with test accounts? [y/N] " ANSWER || ANSWER=""
    case "$ANSWER" in
      y|Y|yes|Yes)
        BA3TRATION_SETUP=1 python3 scripts/accounts.py set || true
        if ! git diff --quiet -- personas.json 2>/dev/null; then
          git add personas.json && git commit -qm "Personas: test account roles" && git push -q && echo "personas.json committed and pushed"
        fi ;;
      *) echo "Later, if they do: python3 scripts/accounts.py set" ;;
    esac
  fi
fi
cat <<MSG

Done. Run the demo (2 Android + 2 iOS testers on the demo app, about 20 min):
  gh workflow run agent-testers.yml
Follow it:
  gh run watch
Then download and decrypt the reports:
  bash scripts/collect.sh \$(gh run list --workflow agent-testers.yml -L 1 --json databaseId -q '.[0].databaseId')
Is everything in place? At any time:
  ./check.sh
MSG
