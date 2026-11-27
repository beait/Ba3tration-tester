"""Ba3tration-tester: the unified report, the gate in front of the live scan, and the
workflows that tie the three engines together. Offline: no scanner, no network, no secret."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import ba3tration_report as report  # noqa: E402

WORKFLOWS = ROOT / ".github/workflows"
SAST = {"results": [
    {"check_id": "semsec.js.sql-injection", "path": "/src/api/users.js", "start": {"line": 42},
     "extra": {"severity": "ERROR", "metadata": {"owasp": ["A03:2021 - Injection"], "cwe": ["CWE-89"]}}},
    {"check_id": "semsec.js.sql-injection", "path": "/src/api/orders.js", "start": {"line": 7},
     "extra": {"severity": "ERROR", "metadata": {"owasp": ["A03:2021 - Injection"], "cwe": ["CWE-89"]}}},
    {"check_id": "semsec.secrets.aws-key", "path": "/src/config.js", "start": {"line": 3},
     "extra": {"severity": "WARNING", "metadata": {"cwe": "CWE-798: Use of Hard-coded Credentials"}}},
]}
DAST = {"site": [{"alerts": [
    {"alert": "Missing Anti-clickjacking Header", "riskdesc": "Medium (Medium)", "cweid": "1021",
     "instances": [{"uri": "https://staging.example.com/"}, {"uri": "https://staging.example.com/login"}]},
    {"alert": "Cross Site Scripting (Reflected)", "riskdesc": "High (Medium)", "cweid": "79",
     "tags": {"OWASP_2021_A03": "https://owasp.org/Top10/A03_2021-Injection/"},
     "instances": [{"uri": "https://staging.example.com/search?q=x"}]},
]}]}


class Category(unittest.TestCase):
    def test_a_2025_tag_is_kept(self):
        self.assertEqual(report.category(["A05:2025 - Injection"]), "A05")

    def test_a_2021_tag_moves_to_its_2025_category(self):
        self.assertEqual(report.category(["A03:2021 - Injection"]), "A05")
        self.assertEqual(report.category(["A05:2021 - Security Misconfiguration"]), "A02")
        self.assertEqual(report.category(["A10:2021 - Server-Side Request Forgery"]), "A01")

    def test_a_2025_tag_wins_over_an_older_one(self):
        self.assertEqual(report.category(["A03:2021 - Injection", "A05:2025 - Injection"]), "A05")

    def test_zap_tag_spelling(self):
        self.assertEqual(report.category(["OWASP_2021_A05", "WSTG-v42-CLNT-09"]), "A02")
        self.assertEqual(report.category(["OWASP_2017_A07"]), "A05")

    def test_cwe_when_there_is_no_tag(self):
        self.assertEqual(report.category([], ["CWE-89: SQL Injection"]), "A05")
        self.assertEqual(report.category([], ["918"]), "A01")
        self.assertEqual(report.category([], ["CWE-798"]), "A07")

    def test_words_of_the_title_as_a_last_resort(self):
        self.assertEqual(report.category([], [], "Content Security Policy (CSP) Header Not Set"), "A02")
        self.assertEqual(report.category([], ["CWE-99999"], "Vulnerable JS Library"), "A03")

    def test_nothing_fits(self):
        self.assertEqual(report.category([], [], "Modern Web Application"), report.NONE)


class Report(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def write(self, rel, data):
        path = self.tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return path

    def test_one_line_per_rule_with_every_place(self):
        found = report.load_sast(self.write("sast.json", SAST))
        self.assertEqual(len(found), 2)
        injection = next(f for f in found if f["rule"].endswith("sql-injection"))
        self.assertEqual(injection["places"], ["/src/api/users.js:42", "/src/api/orders.js:7"])
        self.assertEqual((injection["severity"], injection["category"]), ("high", "A05"))

    def test_zap_alerts(self):
        found = {f["title"]: f for f in report.load_dast(self.write("report.json", DAST))}
        self.assertEqual(found["Missing Anti-clickjacking Header"]["category"], "A02")
        self.assertEqual(found["Missing Anti-clickjacking Header"]["severity"], "medium")
        self.assertEqual(len(found["Missing Anti-clickjacking Header"]["places"]), 2)
        self.assertEqual(found["Cross Site Scripting (Reflected)"]["category"], "A05")

    def test_a_broken_file_is_no_finding(self):
        self.assertEqual(report.load_sast(self.write("sast.json", "{not json")), [])
        self.assertEqual(report.load_dast(self.write("report.json", '{"site": "x"}')), [])

    def test_run_directory_gets_one_report(self):
        self.write("security-sast/results/sast/sast.json", SAST)
        self.write("security-dast/results/dast/report.json", DAST)
        self.write("noah/results/noah/findings.json", {"issues": []})
        self.write("SUMMARY.md", "| minor | Device name cut | 1 (noah) | Settings |\n")
        self.assertEqual(report.main(["--run", str(self.tmp)]), 0)
        text = (self.tmp / "BA3TRATION-REPORT.md").read_text(encoding="utf-8")
        self.assertIn("A05:2025 — Injection (2)", text)
        self.assertIn("A02:2025 — Security Misconfiguration (1)", text)
        self.assertIn("A07:2025 — Authentication Failures (1)", text)
        self.assertIn("Device name cut", text)
        # most severe first inside a category
        self.assertLess(text.index("Cross Site Scripting"), text.index("sql-injection"))
        self.assertLess(text.index("| عالية | 2 |"), text.index("| متوسطة | 2 |"))

    def test_no_security_result_no_report(self):
        self.write("SUMMARY.md", "nothing\n")
        self.assertEqual(report.main(["--run", str(self.tmp)]), 0)
        self.assertFalse((self.tmp / "BA3TRATION-REPORT.md").exists())

    def test_security_only_run_leaves_the_functional_part_out(self):
        self.write("security-sast/results/sast/sast.json", {"results": []})
        self.write("SUMMARY.md", "No report found.\n")
        report.main(["--run", str(self.tmp)])
        text = (self.tmp / "BA3TRATION-REPORT.md").read_text(encoding="utf-8")
        self.assertNotIn("No report found.", text)
        self.assertIn("لم تُسجَّل نتائج أمنية", text)


FAKE_CURL = """#!/usr/bin/env bash
# Stands in for curl: logs the call, then answers with $FAKE_PROOF or fails like a 404
printf '%s\\n' "$*" >> "$CURL_LOG"
[ -n "${FAKE_PROOF+x}" ] || exit 22
printf '%b' "$FAKE_PROOF"
"""


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class Gate(unittest.TestCase):
    """scripts/security/verify_target.sh: no proof naming this repo, no scan."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "curl").write_text(FAKE_CURL)
        (self.tmp / "curl").chmod(0o755)

    def gate(self, url="https://staging.example.com", proof="ba3tration-site-verification=Someone/App\n", **env):
        e = dict(os.environ, PATH="%s%s%s" % (self.tmp, os.pathsep, os.environ["PATH"]),
                 CURL_LOG=str(self.tmp / "curl.log"), URL=url, REPO="someone/app")
        e.pop("FAKE_PROOF", None)
        if proof is not None:
            e["FAKE_PROOF"] = proof
        e.update(env)
        return subprocess.run(["bash", str(ROOT / "scripts/security/verify_target.sh")], env=e,
                              capture_output=True, text=True)

    def calls(self):
        log = self.tmp / "curl.log"
        return log.read_text() if log.exists() else ""

    def test_proof_that_names_this_repo_opens_the_gate(self):
        res = self.gate()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("https://staging.example.com/.well-known/ba3tration.txt", self.calls())
        self.assertIn("--max-redirs 0", self.calls())

    def test_proof_among_other_lines_and_windows_line_ends(self):
        proof = "# sites allowed to scan us\\r\\nba3tration-site-verification=other/repo\\r\\nba3tration-site-verification=someone/app  \\r\\n"
        self.assertEqual(self.gate(proof=proof).returncode, 0)

    def test_proof_for_another_repo_is_refused(self):
        res = self.gate(proof="ba3tration-site-verification=someone/app-fork\n")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("does not name this repository", res.stdout)

    def test_a_page_that_only_contains_the_line_inside_text_is_refused(self):
        self.assertNotEqual(self.gate(proof="<p>ba3tration-site-verification=someone/app</p>\n").returncode, 0)

    def test_no_proof_file_is_refused(self):
        res = self.gate(proof=None)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("No ownership proof", res.stdout)

    def test_only_an_https_origin(self):
        for url in ("http://staging.example.com", "https://staging.example.com/app", "https://user@staging.example.com",
                    "https://staging.example.com?x=1", "staging.example.com", ""):
            res = self.gate(url=url)
            self.assertNotEqual(res.returncode, 0, url)
            self.assertEqual(self.calls(), "", "no request may leave before the URL is accepted: %s" % url)

    def test_full_scan_needs_a_yes(self):
        self.assertNotEqual(self.gate(SCAN_TYPE="full").returncode, 0)
        self.assertNotEqual(self.gate(SCAN_TYPE="full", AUTHORIZED="no").returncode, 0)
        self.assertEqual(self.calls(), "")
        self.assertEqual(self.gate(SCAN_TYPE="full", AUTHORIZED="yes").returncode, 0)

    def test_full_scan_only_on_a_test_environment(self):
        for url in ("https://www.example.com", "https://example.com", "https://example.dev", "https://app.example.test",
                    "https://latest.example.com", "https://contest.example.com"):
            res = self.gate(url=url, SCAN_TYPE="full", AUTHORIZED="yes")
            self.assertNotEqual(res.returncode, 0, url)
            self.assertIn("test environment", res.stdout)
        for url in ("https://staging.example.com", "https://app-dev.example.com", "https://qa.app.example.com:8443",
                    "https://preview-12.example.dev"):
            self.assertEqual(self.gate(url=url, SCAN_TYPE="full", AUTHORIZED="yes").returncode, 0, url)

    def test_the_label_rule_can_be_lifted_but_not_the_proof(self):
        self.assertEqual(self.gate(url="https://www.example.com", SCAN_TYPE="full", AUTHORIZED="yes",
                                   ALLOW_ANY_HOST="1").returncode, 0)
        self.assertNotEqual(self.gate(url="https://www.example.com", SCAN_TYPE="full", AUTHORIZED="yes",
                                      ALLOW_ANY_HOST="1", proof=None).returncode, 0)

    def test_a_passive_scan_may_run_on_any_owned_host(self):
        self.assertEqual(self.gate(url="https://www.example.com").returncode, 0)

    def test_unknown_scan_type(self):
        self.assertNotEqual(self.gate(SCAN_TYPE="aggressive").returncode, 0)


def dispatch_inputs(text, trigger="workflow_dispatch"):
    """{input: default as text} of a trigger written one key per line (no YAML parser on the runners' python)."""
    block = re.search(r"^  %s:\n    inputs:\n((?:      .*\n|\n)+)" % trigger, text, re.M).group(1)
    out, name = {}, None
    for line in block.splitlines():
        m = re.match(r"^      (\w+):\s*$", line)
        if m:
            name = m.group(1)
            out[name] = ""
            continue
        m = re.match(r"^        default:\s*(.*)$", line)
        if m and name:
            raw = m.group(1).strip()
            out[name] = json.loads(raw) if raw.startswith('"') else raw
    return out


def run_scripts(text):
    """The scripts of a workflow's run: steps, one string each (no YAML library: the tests need none)."""
    lines, out, i = text.splitlines(), [], 0
    while i < len(lines):
        m = re.match(r"(\s*)(?:- )?run: (.*)$", lines[i])
        i += 1
        if not m:
            continue
        if m.group(2).strip() not in ("|", ">", "|-", ">-"):
            out.append(m.group(2))
            continue
        block = []
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > len(m.group(1))):
            block.append(lines[i])
            i += 1
        out.append("\n".join(block))
    return out


def call_inputs(text):
    """{input: default as text} of a workflow_call written as  name: { type: x, default: y }"""
    block = re.search(r"^  workflow_call:\n    inputs:\n((?:      .*\n)+)", text, re.M).group(1)
    out = {}
    for line in block.splitlines():
        m = re.match(r"^      (\w+): \{ type: (\w+), default: (.*) \}(?:\s+#.*)?$", line)
        if not m:
            raise AssertionError("workflow_call input not on one line: %r" % line)
        value = json.loads(m.group(3)) if m.group(3).startswith('"') else m.group(3)
        out[m.group(1)] = value
    return out


class Workflows(unittest.TestCase):
    def read(self, name):
        return (WORKFLOWS / name).read_text(encoding="utf-8")

    def test_called_testers_have_the_inputs_and_defaults_of_a_manual_run(self):
        text = self.read("agent-testers.yml")
        manual, called = dispatch_inputs(text), call_inputs(text)
        self.assertGreater(len(manual), 10)
        self.assertEqual(list(called), list(manual))
        self.assertEqual(called, manual)

    def test_the_one_button_workflow_keeps_the_testers_defaults(self):
        testers = dispatch_inputs(self.read("agent-testers.yml"))
        button = dispatch_inputs(self.read("ba3tration.yml"))
        shared = sorted(set(testers) & set(button))
        self.assertEqual(shared, ["android_personas", "brief", "ios_personas", "model"])
        for name in shared:
            self.assertEqual(button[name], testers[name], name)

    def test_the_one_button_workflow_calls_the_three_engines(self):
        text = self.read("ba3tration.yml")
        for engine in ("agent-testers.yml", "security-sast.yml", "security-dast.yml"):
            self.assertIn("uses: ./.github/workflows/%s" % engine, text)

    def test_each_engine_gets_its_secrets_by_name(self):
        """No `secrets: inherit`: what an engine reads is declared by it and handed over by name, nothing else."""
        button = self.read("ba3tration.yml")
        self.assertNotIn("secrets: inherit", button)
        for engine in ("agent-testers.yml", "security-sast.yml", "security-dast.yml"):
            text = self.read(engine)
            read = set(re.findall(r"secrets\.([A-Z][A-Z0-9_]*)", text))
            call = text[text.index("  workflow_call:"):text.index("\npermissions:")]
            declared = set(re.findall(r"^      ([A-Z][A-Z0-9_]*): \{ required: false \}$", call, re.M))
            self.assertEqual(declared, read, engine)
            job = button[button.index("uses: ./.github/workflows/%s" % engine):].split("\n\n")[0]
            passed = dict(re.findall(r"^      ([A-Z][A-Z0-9_]*): \$\{\{ secrets\.([A-Z0-9_]+) \}\}$", job, re.M))
            self.assertEqual(set(passed), read, engine)
            for name, source in passed.items():
                self.assertEqual(name, source, engine)

    def test_actions_are_pinned_to_a_commit(self):
        """A tag can be moved to other code after the fact; a full commit SHA cannot."""
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            for line in path.read_text(encoding="utf-8").splitlines():
                m = re.match(r"\s*(?:- )?uses: (\S+)", line)
                if m and not m.group(1).startswith("./"):
                    self.assertRegex(m.group(1), r"@[0-9a-f]{40}$", "%s: %s" % (path.name, line.strip()))
                    self.assertRegex(line, r"#\s*v\d+", "%s: say which version that commit is: %s" % (path.name, line.strip()))

    def test_no_input_is_pasted_into_a_command(self):
        """${{ inputs.x }} inside run: becomes part of the script: a value with a quote in it runs as a command."""
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            for script in run_scripts(path.read_text(encoding="utf-8")):
                self.assertNotRegex(script, r"\$\{\{\s*(inputs|github\.event|github\.head_ref|matrix)\.", path.name)

    def test_nothing_fetched_is_piped_into_a_shell(self):
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            self.assertNotRegex(path.read_text(encoding="utf-8"), r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b", path.name)

    def test_security_results_leave_the_runner_encrypted_only(self):
        for name, label in (("security-sast.yml", "security-sast"), ("security-dast.yml", "security-dast")):
            text = self.read(name)
            self.assertIn("bash scripts/encrypt_results.sh %s" % label, text)
            uploads = re.findall(r"uses: actions/upload-artifact@\S+.*\n(?:.*\n)*?.*path: ([^,}\n]+)", text)
            self.assertEqual([u.strip() for u in uploads], ["results.enc/"], name)
            # a repo that has not run the setup has no key: nothing is encrypted or uploaded then
            for step in ("Encrypt results", "uses: actions/upload-artifact"):
                condition = text[text.index(step):].split("if: ", 1)[1].splitlines()[0]
                self.assertIn("always() && steps.", condition, "%s: %s" % (name, step))

    def test_scanners_print_nothing_to_the_public_log(self):
        zap = (ROOT / "scripts/security/zap_scan.sh").read_text()
        semgrep = (ROOT / "scripts/security/semgrep_scan.sh").read_text()
        self.assertIn("> results/dast/console.log 2>&1", zap)
        self.assertIn("> results/sast/console.log 2>&1", semgrep)

    def test_no_live_scan_without_the_gate(self):
        text = self.read("security-dast.yml")
        self.assertLess(text.index("scripts/security/verify_target.sh"), text.index("scripts/security/zap_scan.sh"))
        self.assertIn("REPO: ${{ github.repository }}", text)
        for other in WORKFLOWS.glob("*.yml"):
            if other.name != "security-dast.yml":
                self.assertNotIn("zap_scan.sh", other.read_text(encoding="utf-8"), other.name)
                self.assertNotIn("zaproxy", other.read_text(encoding="utf-8"), other.name)


FAKE_GIT = """#!/usr/bin/env bash
# Stands in for git: a SemSec checkout with two rule files and the repo's own CI workflow
if [ "$1" = clone ]; then
  dir="${@: -1}"; mkdir -p "$dir/.github/workflows"
  printf 'rules:\\n  - id: a\\n' > "$dir/a.yaml"; printf 'rules:\\n  - id: b\\n' > "$dir/b.yaml"
  printf 'name: rules\\non: push\\n' > "$dir/.github/workflows/rules.yml"
else echo 0123456789abcdef0123456789abcdef01234567; fi
"""
FAKE_DOCKER = """#!/usr/bin/env bash
# Stands in for docker run semgrep/semgrep: the validation pass, then the scan
printf '%s\\n' "$*" >> "$DOCKER_LOG"
out=""; val=""; for a in "$@"; do case "$a" in *:/out) out="${a%:/out}";; *:/validate) val="${a%:/validate}";; esac; done
case " $* " in
  *" sh -c "*)
    echo 1.99.0 > "$val/version.txt"
    for f in a.yaml b.yaml; do echo "Configuration is invalid: $f has an unknown key" > "$val/$f.log"; done
    for f in $FAKE_VALID; do echo "/rules/$f"; done ;;
  *" scan "*)
    echo "finding: semsec.js.sql-injection in /src/api/users.js"   # Semgrep's own console
    case " $* " in *" p/owasp-top-ten "*) [ -z "${FAKE_PACK_FAILS:-}" ] || exit 2 ;; esac
    [ "${FAKE_EXIT:-0}" = 0 ] || exit "$FAKE_EXIT"
    printf '{"results": [{"check_id": "semsec.js.sql-injection"}], "paths": {"scanned": %s}}' "${FAKE_SCANNED:-[\\"a.js\\", \\"b.js\\"]}" > "$out/sast.json" ;;
esac
"""


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class CodeScan(unittest.TestCase):
    """scripts/security/semgrep_scan.sh with stand-ins for git and docker."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "bin").mkdir()
        for name, body in (("git", FAKE_GIT), ("docker", FAKE_DOCKER)):
            (self.tmp / "bin" / name).write_text(body)
            (self.tmp / "bin" / name).chmod(0o755)
        (self.tmp / "work/code").mkdir(parents=True)

    def scan(self, **env):
        e = dict(os.environ, PATH="%s%s%s" % (self.tmp / "bin", os.pathsep, os.environ["PATH"]),
                 DOCKER_LOG=str(self.tmp / "docker.log"), FAKE_VALID="a.yaml b.yaml")
        e.update(env)
        res = subprocess.run(["bash", str(ROOT / "scripts/security/semgrep_scan.sh")], cwd=self.tmp / "work",
                             env=e, capture_output=True, text=True)
        meta = self.tmp / "work/results/sast/meta.json"
        return res, (json.loads(meta.read_text()) if meta.exists() else None)

    def scans(self):
        return [line for line in (self.tmp / "docker.log").read_text().splitlines() if " scan " in line]

    def test_a_scan_that_ran(self):
        res, meta = self.scan()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("SemSec rule files used: a.yaml b.yaml", res.stdout)
        self.assertIn("Semgrep 1.99.0", res.stdout)
        self.assertIn("2 files read", res.stdout)
        self.assertEqual((meta["semgrep_exit"], meta["owasp_pack"], meta["files_scanned"]), (0, True, 2))
        # each rule file by name: never the folder, never the rules repo's own workflow
        self.assertIn("--config /rules/a.yaml --config /rules/b.yaml --config p/owasp-top-ten", self.scans()[0])
        self.assertNotIn("rules.yml", (self.tmp / "docker.log").read_text())
        # lock files are package hashes, which a rule looking for keys takes for keys
        self.assertIn("--exclude package-lock.json", self.scans()[0])

    def test_no_finding_in_the_public_log(self):
        res, _ = self.scan()
        self.assertNotIn("sql-injection", res.stdout + res.stderr)
        self.assertIn("sql-injection", (self.tmp / "work/results/sast/console.log").read_text())

    def test_a_scan_that_failed_is_not_a_clean_scan(self):
        res, meta = self.scan(FAKE_EXIT="7")
        self.assertEqual(res.returncode, 1)
        self.assertIn("::error::Semgrep stopped with exit 7", res.stdout)
        self.assertEqual(meta["semgrep_exit"], 7)

    def test_without_the_registry_pack(self):
        res, meta = self.scan(FAKE_PACK_FAILS="1")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("::warning::Semgrep's OWASP Top 10 pack could not be used", res.stdout)
        self.assertFalse(meta["owasp_pack"])
        self.assertNotIn("p/owasp-top-ten", self.scans()[1])

    def test_a_rejected_rule_file_is_left_out_and_named(self):
        res, meta = self.scan(FAKE_VALID="a.yaml")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("left out: b.yaml", res.stdout)
        # why: Semgrep's words on a public rule file, the only thing of its console that reaches the log
        self.assertIn("::group::Why Semgrep rejected b.yaml", res.stdout)
        self.assertIn("b.yaml has an unknown key", res.stdout)
        self.assertNotIn("a.yaml has an unknown key", res.stdout)
        self.assertNotIn("/rules/b.yaml", self.scans()[0])
        self.assertEqual(meta["rule_files_left_out"], ["b.yaml"])

    def test_no_usable_rule_file(self):
        res, _ = self.scan(FAKE_VALID="")
        self.assertEqual(res.returncode, 1)
        self.assertEqual(self.scans(), [])

    def test_nothing_read_is_an_error(self):
        res, _ = self.scan(FAKE_SCANNED="[]")
        self.assertEqual(res.returncode, 1)
        self.assertIn("read no file", res.stdout)


FAKE_MAESTRO_CURL = """#!/usr/bin/env bash
# Stands in for curl: the release archive is the zip prepared by the test
printf '%s\n' "$*" >> "$CURL_LOG"
out=""; while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done
cp "$FAKE_ZIP" "$out"
"""


@unittest.skipUnless(shutil.which("bash") and shutil.which("unzip") and shutil.which("shasum"), "needs bash, unzip and shasum")
class Maestro(unittest.TestCase):
    """scripts/install_maestro.sh: one version, from its release, and only the archive expected."""

    def setUp(self):
        import hashlib
        import zipfile
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        (self.tmp / "bin").mkdir()
        (self.tmp / "bin/curl").write_text(FAKE_MAESTRO_CURL)
        (self.tmp / "bin/curl").chmod(0o755)
        with zipfile.ZipFile(self.tmp / "maestro.zip", "w") as z:
            z.writestr("maestro/bin/maestro", "#!/bin/sh\necho maestro\n")
            z.writestr("maestro/lib/cli.jar", "jar")
        self.sha = hashlib.sha256((self.tmp / "maestro.zip").read_bytes()).hexdigest()

    def install(self, sha):
        env = dict(os.environ, PATH="%s%s%s" % (self.tmp / "bin", os.pathsep, os.environ["PATH"]), HOME=str(self.tmp / "home"),
                   CURL_LOG=str(self.tmp / "curl.log"), FAKE_ZIP=str(self.tmp / "maestro.zip"),
                   GITHUB_PATH=str(self.tmp / "path"), MAESTRO_VERSION="2.12.1", MAESTRO_SHA256=sha)
        (self.tmp / "home").mkdir(exist_ok=True)
        return subprocess.run(["bash", str(ROOT / "scripts/install_maestro.sh")], env=env, capture_output=True, text=True)

    def test_the_expected_archive_is_installed(self):
        res = self.install(self.sha)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertTrue((self.tmp / "home/.maestro/bin/maestro").exists())
        self.assertTrue((self.tmp / "home/.maestro/lib/cli.jar").exists())
        self.assertEqual((self.tmp / "path").read_text().strip(), str(self.tmp / "home/.maestro/bin"))
        self.assertIn("releases/download/cli-2.12.1/maestro.zip", (self.tmp / "curl.log").read_text())

    def test_another_archive_is_refused(self):
        res = self.install("0" * 64)
        self.assertEqual(res.returncode, 1)
        self.assertIn("not the one expected", res.stdout)
        self.assertFalse((self.tmp / "home/.maestro").exists())

    def test_the_workflows_give_the_version_and_its_hash(self):
        for name in ("agent-testers.yml", "map-check.yml", "replay-check.yml"):
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            self.assertIn("bash scripts/install_maestro.sh", text, name)
            self.assertRegex(text, r"MAESTRO_VERSION: [\d.]+", name)
            self.assertRegex(text, r"MAESTRO_SHA256: [0-9a-f]{64}\b", name)


FAKE_GH = """#!/usr/bin/env bash
case "$1 $2" in
  "repo view") echo "someone/app" ;;
  "api repos/someone/app/actions/runs/123/artifacts") ls "$FAKE_ARTIFACTS" ;;
  "run download") mkdir -p "$7" && cp -R "$FAKE_ARTIFACTS/$5"/. "$7"/ ;;   # run download <run> -n <artifact> -D <dir>
  *) echo "unexpected gh call: $*" >&2; exit 1 ;;
esac
"""


@unittest.skipUnless(shutil.which("openssl") and shutil.which("bash"), "needs openssl and bash")
class Collect(unittest.TestCase):
    """A security engine's results travel like a persona's: encrypted on the runner, read by collect.sh."""

    def test_collect_writes_the_unified_report(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        key = tmp / "private.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                        "-out", str(key)], check=True, capture_output=True)
        runner = tmp / "runner"
        (runner / "results/sast").mkdir(parents=True)
        subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(runner / "results_public.pem")],
                       check=True, capture_output=True)
        (runner / "results/sast/sast.json").write_text(json.dumps(SAST))
        subprocess.run(["bash", str(ROOT / "scripts/encrypt_results.sh"), "security-sast"], cwd=runner,
                       check=True, capture_output=True)
        self.assertNotIn(b"sql-injection", (runner / "results.enc/security-sast.tgz.enc").read_bytes())
        shutil.copytree(runner / "results.enc", tmp / "artifacts/results-security-sast")
        (tmp / "bin").mkdir()
        (tmp / "bin/gh").write_text(FAKE_GH)
        (tmp / "bin/gh").chmod(0o755)
        env = dict(os.environ, PATH="%s%s%s" % (tmp / "bin", os.pathsep, os.environ["PATH"]),
                   FAKE_ARTIFACTS=str(tmp / "artifacts"), SUMMARY_GROUPING="0")
        out = tmp / "run"
        res = subprocess.run(["bash", str(ROOT / "scripts/collect.sh"), "123", str(key), str(out)],
                             cwd=tmp, env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertNotIn("security-sast", res.stdout.replace("BA3TRATION", ""), "no agent status for a scanner")
        text = (out / "BA3TRATION-REPORT.md").read_text(encoding="utf-8")
        self.assertIn("A05:2025 — Injection (1)", text)
        self.assertIn("`/src/api/users.js:42`", text)

        # Windows: python3 is the Store's stub that runs nothing, the real one is called python
        (tmp / "bin/python3").write_text("#!/usr/bin/env bash\nexit 9\n")
        (tmp / "bin/python3").chmod(0o755)
        os.symlink(sys.executable, tmp / "bin/python")
        out2 = tmp / "run2"
        res = subprocess.run(["bash", str(ROOT / "scripts/collect.sh"), "123", str(key), str(out2)],
                             cwd=tmp, env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertTrue((out2 / "BA3TRATION-REPORT.md").exists(), res.stdout + res.stderr)


SKILL = ROOT / "skills/ba3tration-tester/SKILL.md"


class Skill(unittest.TestCase):
    """One SKILL.md in the open agent-skills format, for any coding agent that reads it."""

    def setUp(self):
        self.text = SKILL.read_text(encoding="utf-8")
        self.front = re.match(r"^---\n(.*?)\n---\n", self.text, re.S).group(1)

    def test_front_matter(self):
        fields = dict(line.split(": ", 1) for line in self.front.splitlines())
        self.assertEqual(sorted(fields), ["description", "name"])
        self.assertEqual(fields["name"], SKILL.parent.name)
        self.assertRegex(fields["name"], r"^[a-z0-9]+(-[a-z0-9]+)*$")
        self.assertLessEqual(len(fields["description"]), 1024)

    def test_every_file_it_names_exists(self):
        for rel in ("scripts/collect.sh", "scripts/security/verify_target.sh", "scripts/build/detect.sh",
                    "docs/security-scan.md", "personas.json", "AGENT_BRIEF.md", "setup.sh", "setup.ps1"):
            self.assertIn(rel.split("/")[-1], self.text, rel)
            self.assertTrue((ROOT / rel).exists(), rel)
        for workflow in re.findall(r"`([\w-]+\.yml)`", self.text):
            self.assertTrue((WORKFLOWS / workflow).exists(), workflow)

    def test_it_keeps_the_agent_behind_the_gate(self):
        for rule in ("Never production", "Never edit `scripts/security/verify_target.sh`",
                     "You never read, print, store or ask for a credential"):
            self.assertIn(rule, self.text)

    @unittest.skipUnless(shutil.which("bash"), "needs bash")
    def test_installer_copies_the_same_file_for_each_agent(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home)
        env = dict(os.environ, HOME=str(home))
        env.pop("CODEX_SKILLS_DIR", None)
        script = str(ROOT / "scripts/install_skill.sh")
        subprocess.run(["bash", script], env=env, check=True, capture_output=True)
        for folder in (".claude/skills", ".agents/skills"):
            self.assertEqual((home / folder / "ba3tration-tester/SKILL.md").read_text(encoding="utf-8"), self.text)
        subprocess.run(["bash", script, "codex"], env=dict(env, CODEX_SKILLS_DIR=str(home / ".codex/skills")),
                       check=True, capture_output=True)
        self.assertTrue((home / ".codex/skills/ba3tration-tester/SKILL.md").exists())
        self.assertNotEqual(subprocess.run(["bash", script, "everything"], env=env, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
