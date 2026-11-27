#!/usr/bin/env bash
# The gate in front of the live scan (OWASP ZAP). It refuses to go on unless:
#   1. the target is an https origin, with no path, query or credentials
#   2. the target publishes a proof that names THIS repository:
#        https://<target>/.well-known/ba3tration.txt
#        containing the line   ba3tration-site-verification=<owner>/<repo>
#      Only someone who can publish on the site can write that line, and a copy of
#      this repo under another name does not match it.
#   3. for an active scan (SCAN_TYPE=full): the person who started the run typed yes,
#      and the host name carries a test-environment label (staging, dev, test, qa...).
#      Set the repository variable BA3TRATION_ALLOW_ANY_HOST=1 to lift the label rule.
# Env: URL, REPO (owner/name), SCAN_TYPE (baseline|full), AUTHORIZED, ALLOW_ANY_HOST
set -euo pipefail
fail() { echo "::error::$1"; exit 1; }

URL=${URL:-}; REPO=${REPO:-}; SCAN_TYPE=${SCAN_TYPE:-baseline}
[ -n "$URL" ] || fail "STAGING_URL is not set"
[ -n "$REPO" ] || fail "REPO is not set"
case "$SCAN_TYPE" in baseline|full) ;; *) fail "scan_type must be baseline or full" ;; esac
case "$URL" in https://*) ;; *) fail "STAGING_URL must start with https://" ;; esac
base=${URL%/}
host=${base#https://}
case "$host" in */*|*@*|*\?*|*\#*|"") fail "STAGING_URL must be an origin only, like https://staging.example.com" ;; esac
host=${host%%:*}

if [ "$SCAN_TYPE" = full ]; then
  [ "${AUTHORIZED:-no}" = yes ] || fail "A full scan sends attack traffic. Run it again with i_am_authorized = yes, only on a site you own."
  if [ "${ALLOW_ANY_HOST:-}" != 1 ]; then
    labels=${host%.*}   # the last label is the TLD: example.dev is not a dev environment
    printf '%s\n' "$labels" | grep -qiE '(^|[.-])(staging|stage|stg|dev|test|testing|qa|uat|sandbox|preview)([.-]|$)' \
      || fail "A full scan only runs on a test environment (staging, dev, test, qa, uat, sandbox, preview in the host name). This host has no such label."
  fi
fi

want="ba3tration-site-verification=$(printf '%s' "$REPO" | tr '[:upper:]' '[:lower:]')"
proof=$(curl -fsS --proto '=https' --max-redirs 0 --max-time 20 "$base/.well-known/ba3tration.txt") \
  || fail "No ownership proof on the target: publish /.well-known/ba3tration.txt (see docs/security-scan.md)"
printf '%s\n' "$proof" | tr -d '\r' | sed 's/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]' | grep -qxF -- "$want" \
  || fail "The ownership proof on the target does not name this repository. Not scanning a site that has not authorized it."
echo "Ownership verified: the target authorizes this repository ($SCAN_TYPE scan)."
