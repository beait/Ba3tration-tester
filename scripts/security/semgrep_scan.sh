#!/usr/bin/env bash
# Scans the source in $TARGET with Semgrep: the SemSec rules plus Semgrep's OWASP Top 10 pack.
# Nothing Semgrep prints reaches the job log (public on a public repo): its console and
# findings go to results/sast/, encrypted afterwards with the rest of the results.
# Env: TARGET (folder to scan, default code)
set -uo pipefail
TARGET=${TARGET:-code}
[ -d "$TARGET" ] || { echo "::error::nothing to scan: $TARGET is not a folder"; exit 1; }
mkdir -p results/sast
rules=$(mktemp -d)
git clone -q --depth 1 https://github.com/RobustaStudio/semsec "$rules/semsec" \
  || { echo "::error::could not fetch the SemSec rules"; exit 1; }
rules_commit=$(git -C "$rules/semsec" rev-parse HEAD)
docker run --rm -v "$(cd "$TARGET" && pwd):/src:ro" -v "$rules/semsec:/rules:ro" -v "$PWD/results/sast:/out" \
  semgrep/semgrep semgrep scan --config /rules --config p/owasp-top-ten --metrics off --quiet \
  --json --output /out/sast.json /src > results/sast/console.log 2>&1
code=$?
printf '{"engine": "sast", "semgrep_exit": %d, "semsec_commit": "%s"}\n' "$code" "$rules_commit" > results/sast/meta.json
if [ ! -s results/sast/sast.json ]; then
  echo "::error::Semgrep wrote no report (exit $code). Its console is in the encrypted results: results/sast/console.log"
  exit 1
fi
echo "Code scan finished. The report is in the encrypted results."
