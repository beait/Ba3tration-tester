#!/usr/bin/env bash
# Scans the source in $TARGET with Semgrep: the SemSec rules plus Semgrep's OWASP Top 10 pack.
# Nothing Semgrep prints reaches the job log (public on a public repo): its console and
# findings go to results/sast/, encrypted afterwards with the rest of the results. The log
# only gets what holds no finding: which rule files were used and how many files were read.
# The job fails when Semgrep fails: a scan that did not run must not look like a clean one.
# Env: TARGET (folder to scan, default code)
set -uo pipefail
TARGET=${TARGET:-code}
IMAGE=semgrep/semgrep
[ -d "$TARGET" ] || { echo "::error::nothing to scan: $TARGET is not a folder"; exit 1; }
mkdir -p results/sast
work=$(mktemp -d)
git clone -q --depth 1 https://github.com/RobustaStudio/semsec "$work/semsec" \
  || { echo "::error::could not fetch the SemSec rules"; exit 1; }
rules_commit=$(git -C "$work/semsec" rev-parse HEAD)
# The rule files are the .yaml files at the top of the SemSec repo. Its other YAML (its own
# CI workflow) is not a rule: given the whole folder, Semgrep stops on it (exit 7).
mkdir -p "$work/rules"
cp "$work/semsec"/*.yaml "$work/rules/" 2>/dev/null
[ -n "$(ls "$work/rules")" ] || { echo "::error::no rule file found in SemSec"; exit 1; }

# Keep the rule files this Semgrep version accepts; one rejected file must not stop the scan.
# What Semgrep says about a rule file is about SemSec's public rules, never about the code scanned:
# it can go to the job log, and it is the only way to see why a file was left out.
mkdir -p "$work/validate"
docker run --rm -v "$work/rules:/rules:ro" -v "$work/validate:/validate" "$IMAGE" sh -c '
  semgrep --version > /validate/version.txt 2>&1
  for f in /rules/*.yaml; do
    if semgrep --validate --metrics off --config "$f" > "/validate/$(basename "$f").log" 2>&1; then echo "$f"; fi
  done' > "$work/valid.txt" 2>> results/sast/console.log
echo "Semgrep $(tail -n 1 "$work/validate/version.txt" 2>/dev/null || echo "did not start: is Docker running?")"
configs=(); used=(); skipped=()
for f in "$work"/rules/*.yaml; do
  name=$(basename "$f")
  if grep -qxF "/rules/$name" "$work/valid.txt"; then configs+=(--config "/rules/$name"); used+=("$name"); else skipped+=("$name"); fi
done
for name in ${skipped[@]+"${skipped[@]}"}; do
  echo "::group::Why Semgrep rejected $name"
  tail -n 25 "$work/validate/$name.log" 2>/dev/null || echo "(Semgrep wrote nothing)"
  echo "::endgroup::"
done
[ ${#used[@]} -gt 0 ] || { echo "::error::Semgrep accepted none of the SemSec rule files: its reasons are just above"; exit 1; }
echo "SemSec rule files used: ${used[*]}"
[ ${#skipped[@]} -eq 0 ] || echo "::warning::SemSec rule files this Semgrep version rejected, left out: ${skipped[*]}"

scan() {   # scan <extra config arguments...>
  rm -f results/sast/sast.json
  docker run --rm -v "$(cd "$TARGET" && pwd):/src:ro" -v "$work/rules:/rules:ro" -v "$PWD/results/sast:/out" \
    "$IMAGE" semgrep scan "${configs[@]}" "$@" --metrics off --quiet --json --output /out/sast.json /src \
    >> results/sast/console.log 2>&1
}
pack=true
scan --config p/owasp-top-ten; code=$?
if [ "$code" -ne 0 ]; then   # the registry pack is the only part that needs semgrep.dev: once more without it
  pack=false
  scan; code=$?
  [ "$code" -ne 0 ] || echo "::warning::Semgrep's OWASP Top 10 pack could not be used: scanned with the SemSec rules only"
fi
files=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("paths", {}).get("scanned", [])))' results/sast/sast.json 2>/dev/null || echo 0)
python3 - "$code" "$rules_commit" "$pack" "$files" "${skipped[*]:-}" > results/sast/meta.json <<'PY'
import json, sys
code, commit, pack, files, skipped = sys.argv[1:6]
print(json.dumps({"engine": "sast", "semgrep_exit": int(code), "semsec_commit": commit,
                  "owasp_pack": pack == "true", "files_scanned": int(files), "rule_files_left_out": skipped.split()}))
PY
if [ "$code" -ne 0 ] || [ ! -s results/sast/sast.json ]; then
  echo "::error::Semgrep stopped with exit $code: no code scan. Its console is in the encrypted results: results/sast/console.log"
  exit 1
fi
[ "$files" -gt 0 ] || { echo "::error::Semgrep read no file in $TARGET: check code_repo and code_dir"; exit 1; }
echo "Code scan finished: $files files read. The findings are in the encrypted results."
