"""Ba3tration-tester: one report for the three engines of a collected run.

Reads what scripts/collect.sh decrypted on your machine and writes
<run>/BA3TRATION-REPORT.md:
  - security findings of the code scan (Semgrep + SemSec) and of the live scan
    (OWASP ZAP), grouped by OWASP Top 10:2025 category, most severe first
  - the functional summary of the AI testers (SUMMARY.md), unchanged

The OWASP category of a finding is a best guess, in this order: the rule's own
OWASP tag (a 2021 or 2017 tag is translated to its 2025 category), then its CWE
number, then words of its title. A finding that fits nothing is listed under
"Not categorised". Every finding is a lead to check by hand, not a verdict.

Usage: python3 scripts/ba3tration_report.py --run <collected_run_dir>
   or: python3 scripts/ba3tration_report.py --sast sast.json --dast report.json
                                            --func SUMMARY.md --out REPORT.md"""
import argparse, json, re, sys
from collections import defaultdict
from pathlib import Path

OWASP_2025 = [
    ("A01", "Broken Access Control"),
    ("A02", "Security Misconfiguration"),
    ("A03", "Software Supply Chain Failures"),
    ("A04", "Cryptographic Failures"),
    ("A05", "Injection"),
    ("A06", "Insecure Design"),
    ("A07", "Authentication Failures"),
    ("A08", "Software or Data Integrity Failures"),
    ("A09", "Security Logging & Alerting Failures"),
    ("A10", "Mishandling of Exceptional Conditions"),
]
NONE = "A00"
NAMES = dict(OWASP_2025, **{NONE: "Not categorised"})

# Where each category of an older edition went in 2025
FROM_2021 = {1: "A01", 2: "A04", 3: "A05", 4: "A06", 5: "A02", 6: "A03", 7: "A07", 8: "A08", 9: "A09",
             10: "A01"}   # A10:2021 SSRF is now part of Broken Access Control
FROM_2017 = {1: "A05", 2: "A07", 3: "A04", 4: "A02", 5: "A01", 6: "A02", 7: "A05", 8: "A08", 9: "A03",
             10: "A09"}

CWE = {
    "A01": [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538,
            540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 918, 922, 1275],
    "A02": [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 693, 756, 776, 942, 1004, 1021,
            1032, 1174],
    "A03": [937, 1035, 1104, 1395],
    "A04": [261, 295, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337,
            338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
    "A05": [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138,
            184, 470, 471, 564, 610, 643, 644, 652, 917],
    "A06": [73, 183, 256, 257, 266, 269, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525,
            539, 579, 598, 602, 642, 645, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1173],
    "A07": [255, 259, 287, 288, 290, 294, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798,
            940, 1216],
    "A08": [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
    "A09": [117, 223, 532, 778],
    "A10": [209, 234, 248, 252, 274, 390, 391, 396, 397, 460, 544, 550, 636, 703, 754, 755],
}
CWE_TO_CAT = {n: cat for cat, numbers in CWE.items() for n in numbers}

WORDS = [   # last resort, first match wins
    ("A05", r"inject|sqli|xss|cross.site.scripting|command.exec|ssti|xpath|ldap"),
    ("A01", r"access.control|idor|authoriz|ssrf|path.traversal|directory.(?:browsing|listing)|csrf|open.redirect"),
    ("A07", r"authenticat|session|password|credential|hardcoded|secret|api.key|token|jwt"),
    ("A04", r"crypto|tls|ssl|cipher|weak.hash|md5|sha1|certificate|random"),
    ("A03", r"vulnerable.(?:js|library|component)|outdated|dependency|supply.chain"),
    ("A08", r"integrity|deserial|subresource"),
    ("A02", r"misconfig|header|cors|cookie|content.security.policy|csp|clickjack|debug|server.leaks|x-powered-by"),
    ("A10", r"error.(?:message|disclosure)|stack.trace|exception"),
    ("A09", r"logging|log.injection"),
]

SEVERITIES = ("high", "medium", "low", "info")
SEV_AR = {"high": "عالية", "medium": "متوسطة", "low": "منخفضة", "info": "معلوماتية"}
SEV_IN = {"critical": "high", "high": "high", "error": "high", "medium": "medium", "warning": "medium",
          "low": "low", "info": "info", "informational": "info", "note": "info"}
ENGINE_AR = {"SAST": "الكود", "DAST": "التطبيق الحي"}


def severity(raw):
    return SEV_IN.get(str(raw or "").strip().lower().split(" ")[0], "low")


def as_list(x):
    if x is None:
        return []
    return [str(v) for v in x] if isinstance(x, (list, tuple)) else [str(x)]


def category(owasp_tags=(), cwes=(), title=""):
    """The OWASP Top 10:2025 id of a finding (A01..A10), or A00 when nothing fits."""
    older = None
    for tag in owasp_tags:
        m = re.search(r"\bA(\d{1,2})\s*[:_\- ]\s*(20\d\d)", tag, re.I) or \
            re.search(r"(20\d\d)\s*[:_\- ]\s*A(\d{1,2})\b", tag, re.I)
        if not m:
            continue
        a, b = m.groups()
        n, year = (int(a), b) if len(a) <= 2 else (int(b), a)
        if not 1 <= n <= 10:
            continue
        if year == "2025":
            return "A%02d" % n
        if older is None:
            older = (FROM_2017 if year == "2017" else FROM_2021).get(n)
    if older:
        return older
    for c in cwes:
        m = re.search(r"(\d+)", c)
        if m and int(m.group(1)) in CWE_TO_CAT:
            return CWE_TO_CAT[int(m.group(1))]
    for cat, pattern in WORDS:
        if re.search(pattern, title, re.I):
            return cat
    return NONE


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def load_sast(path):
    """Semgrep --json: one entry per rule, with every place it matched."""
    data = read_json(path) if path else None
    if not isinstance(data, dict):
        return []
    rules = {}
    for r in data.get("results") or []:
        if not isinstance(r, dict):
            continue
        extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        rule = str(r.get("check_id") or "rule")
        start = r.get("start") if isinstance(r.get("start"), dict) else {}
        f = rules.setdefault(rule, {
            "engine": "SAST", "title": rule.split(".")[-1], "rule": rule,
            "severity": severity(extra.get("severity")),
            "category": category(as_list(meta.get("owasp")), as_list(meta.get("cwe")), rule),
            "places": []})
        f["places"].append("%s:%s" % (r.get("path", "?"), start.get("line", "?")))
    return list(rules.values())


def load_dast(path):
    """ZAP JSON report: one entry per alert, with how many URLs showed it."""
    data = read_json(path) if path else None
    if not isinstance(data, dict):
        return []
    alerts = {}
    sites = data.get("site") or []
    for site in sites if isinstance(sites, list) else [sites]:
        for a in (site.get("alerts") or []) if isinstance(site, dict) else []:
            if not isinstance(a, dict):
                continue
            title = str(a.get("alert") or a.get("name") or "alert")
            tags = a.get("tags")
            tags = list(tags) if isinstance(tags, (dict, list)) else as_list(tags)
            instances = a.get("instances") if isinstance(a.get("instances"), list) else []
            f = alerts.setdefault(title, {
                "engine": "DAST", "title": title, "rule": "ZAP %s" % a.get("alertRef", a.get("pluginid", "")),
                "severity": severity(a.get("riskdesc")),
                "category": category([str(t) for t in tags], as_list(a.get("cweid")), title),
                "places": []})
            f["places"] += [str(i.get("uri", "?")) for i in instances if isinstance(i, dict)]
    return list(alerts.values())


def places(f, limit=5):
    shown = ", ".join("`%s`" % p for p in f["places"][:limit])
    more = len(f["places"]) - limit
    return shown + (" (+%d)" % more if more > 0 else "")


def render(findings, functional, engines):
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1
    lines = ["# Ba3tration-tester — التقرير الموحّد", "",
             "المحركات في هذا التشغيل: %s." % (" · ".join(engines) or "لا يوجد"), ""]
    if "SAST" in engines or "DAST" in engines:
        lines += ["## ملخّص الأمان (OWASP Top 10:2025)", "",
                  "| الخطورة | العدد |", "|---|---|"]
        lines += ["| %s | %d |" % (SEV_AR[s], counts[s]) for s in SEVERITIES]
        lines += ["", "كل نتيجة هنا **خيط للمراجعة اليدوية** وليست حكمًا نهائيًا، وتصنيف OWASP تقريبي.", ""]
        by_cat = defaultdict(list)
        for f in findings:
            by_cat[f["category"]].append(f)
        for cat in [c for c, _ in OWASP_2025] + [NONE]:
            items = sorted(by_cat.get(cat, []), key=lambda f: (SEVERITIES.index(f["severity"]), f["title"]))
            if not items:
                continue
            head = NAMES[cat] if cat == NONE else "%s:2025 — %s" % (cat, NAMES[cat])
            lines += ["### %s (%d)" % (head, len(items)), ""]
            for f in items:
                lines.append("- **%s** · %s · %s — %s" % (
                    SEV_AR[f["severity"]], ENGINE_AR[f["engine"]], f["title"], places(f) or "—"))
            lines.append("")
        if not findings:
            lines += ["لم تُسجَّل نتائج أمنية في هذا التشغيل.", ""]
        lines += ["**ما لا يغطيه الفحص الأمني:** فحص التطبيق الحي يعمل بدون تسجيل دخول، فلا يرى ما خلف "
                  "شاشة الدخول؛ وعزل بيانات الشركات ومنطق الصلاحيات يحتاجان مراجعة يدوية.", ""]
    if functional:
        lines += ["---", "", "## الاختبار الوظيفي (المختبِرون الأذكياء)", "", functional.strip(), ""]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--run", help="a run directory written by scripts/collect.sh")
    ap.add_argument("--sast"); ap.add_argument("--dast"); ap.add_argument("--func"); ap.add_argument("--out")
    a = ap.parse_args(argv)
    if a.run:
        run = Path(a.run)
        a.sast = a.sast or run / "security-sast/results/sast/sast.json"
        a.dast = a.dast or run / "security-dast/results/dast/report.json"
        a.func = a.func or run / "SUMMARY.md"
        a.out = a.out or run / "BA3TRATION-REPORT.md"
    engines, findings = [], []
    for name, path, load in (("SAST", a.sast, load_sast), ("DAST", a.dast, load_dast)):
        if path and Path(path).is_file():
            engines.append(name)
            findings += load(path)
    if not engines:
        print("No security results in this run: no unified report written.")
        return 0
    functional = ""
    if a.func and Path(a.func).is_file():
        functional = Path(a.func).read_text(encoding="utf-8", errors="replace")
        if any(Path(a.run).glob("*/results/*/findings.json")) if a.run else functional.strip():
            engines.append("Functional")
        else:
            functional = ""
    out = Path(a.out or "BA3TRATION-REPORT.md")
    out.write_text(render(findings, functional, engines), encoding="utf-8")
    print("Unified report: %s (%d security findings)" % (out, len(findings)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
