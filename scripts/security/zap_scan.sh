#!/usr/bin/env bash
# Runs OWASP ZAP against $URL after scripts/security/verify_target.sh passed.
# baseline = spider + passive rules, no attack. full = active scan (attack traffic).
# Nothing ZAP prints reaches the job log (public on a public repo): its console and
# reports go to results/dast/, encrypted afterwards with the rest of the results.
# Env: URL, SCAN_TYPE (baseline|full), SPIDER_MINUTES (optional)
set -uo pipefail
SCAN_TYPE=${SCAN_TYPE:-baseline}
script=zap-baseline.py
[ "$SCAN_TYPE" = full ] && script=zap-full-scan.py
mkdir -p results/dast zapwrk
chmod 777 zapwrk   # the zap user of the image writes the reports here
docker run --rm -v "$PWD/zapwrk:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  "$script" -t "$URL" -m "${SPIDER_MINUTES:-3}" -I -J report.json -r report.html -w report.md \
  > results/dast/console.log 2>&1
code=$?
cp zapwrk/report.json zapwrk/report.html zapwrk/report.md results/dast/ 2>/dev/null
printf '{"engine": "dast", "scan_type": "%s", "zap_exit": %d}\n' "$SCAN_TYPE" "$code" > results/dast/meta.json
if [ ! -s results/dast/report.json ]; then
  echo "::error::ZAP wrote no report (exit $code). Its console is in the encrypted results: results/dast/console.log"
  exit 1
fi
echo "ZAP $SCAN_TYPE scan finished. The report is in the encrypted results."
