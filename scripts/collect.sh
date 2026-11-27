#!/usr/bin/env bash
# Run on YOUR machine: downloads every encrypted artifact of a run and decrypts it.
# Usage: bash scripts/collect.sh <run_id> [private_key.pem] [out_dir]
# Default key: the one setup.sh created in ~/.mobile-agent-testers/
set -euo pipefail
export PYTHONUTF8=1   # Python on Windows writes cp1252 otherwise: titles in Arabic or Turkish would stop it
RUN=$1
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
PRIV=${2:-$HOME/.mobile-agent-testers/${REPO//\//_}.pem}; OUT=${3:-runs/$1}
# python3, or what a Windows install calls it. The Microsoft Store's python3 stub runs nothing: it is tried, not trusted.
PY=""
for c in python3 python "py -3"; do
  if $c -c "" 2>/dev/null; then PY=$c; break; fi
done
# a clean start: what an earlier try left there makes gh refuse to extract ("file exists")
rm -rf "$OUT/enc"; mkdir -p "$OUT/enc"
# only the testers' results, one folder each (not the app, which is large, nor the build log)
for art in $(gh api "repos/$REPO/actions/runs/$RUN/artifacts" --paginate -q '.artifacts[] | select(.expired | not) | .name | select(startswith("results-"))'); do
  gh run download "$RUN" -n "$art" -D "$OUT/enc/$art"
done
for key in "$OUT"/enc/*/*.key.bin; do
  [ -f "$key" ] || { echo "No results to decrypt in run $RUN (expired after 14 days, or the run is still going)"; exit 1; }
  name=$(basename "$key" .key.bin); dir=$(dirname "$key")
  pass=$(openssl pkeyutl -decrypt -inkey "$PRIV" -pkeyopt rsa_padding_mode:oaep -in "$key")
  mkdir -p "$OUT/$name"
  openssl enc -d -aes-256-cbc -pbkdf2 -in "$dir/$name.tgz.enc" -pass "pass:$pass" | tar xz -C "$OUT/$name"
  # no agent-output.json: no agent ran (map=robot, the map maker with no model)
  [ -f "$OUT/$name/results/agent-output.json" ] && [ -n "$PY" ] && $PY "$(dirname "$0")/agent_status.py" "$OUT/$name/results/agent-output.json" "$OUT/$name/results/agent-errors.txt" "$name" || true
done
echo "Decrypted into $OUT"
if [ -n "$PY" ]; then
  $PY "$(dirname "$0")/summarize.py" "$OUT" > "$OUT/SUMMARY.md" && echo "Summary: $OUT/SUMMARY.md"
  # Ba3tration-tester: when the run has security results, one report for the three engines
  $PY "$(dirname "$0")/ba3tration_report.py" --run "$OUT" || echo "The unified report could not be written (the summary above is complete)."
  # opt-in: a short version to your Slack or Discord webhook, from this machine only
  [ -n "${SUMMARY_WEBHOOK_URL:-}" ] && $PY "$(dirname "$0")/notify.py" "$OUT" || true
else   # the results are there, only the reports are missing
  echo "Python 3 was not found: no SUMMARY.md and no BA3TRATION-REPORT.md. Install it (Windows: winget install Python.Python.3.13), open a new terminal and run this again."
fi
echo "How did it go? Tell us what it found, or where it got in the way: https://github.com/beait/Ba3tration-tester/issues/new?template=usage-feedback.yml"
