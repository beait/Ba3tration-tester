# Security engines (Ba3tration-tester)

Two engines next to the AI testers. Both run on demand, and their findings are encrypted
with `results_public.pem` like the testers' reports: nothing readable reaches the job log.

| Engine | Workflow | What it reads | Tool |
|---|---|---|---|
| Code (SAST) | `security-sast.yml` | the source code of your app | Semgrep + [SemSec](https://github.com/RobustaStudio/semsec) rules + Semgrep's OWASP Top 10 pack |
| Live site (DAST) | `security-dast.yml` | your staging site, from outside | [OWASP ZAP](https://www.zaproxy.org/) |

`ba3tration.yml` runs them with the testers in one run. `bash scripts/collect.sh <run id>` then
writes `runs/<id>/BA3TRATION-REPORT.md`: every finding under its OWASP Top 10:2025 category.

## Code scan

Nothing to set up for a public app repo. For a private one, add a read-only token:

```bash
gh secret set SOURCE_REPO_TOKEN     # fine-grained token, Contents: read, on the app repo only
gh workflow run security-sast.yml -f code_repo=you/app
```

## Live scan: the site must authorize this repository first

ZAP scans nothing until the target proves that it accepts scans from **this** repository.

1. Tell the workflow where your staging site is (the origin only, no path):
   ```bash
   gh secret set STAGING_URL        # https://staging.example.com
   ```
2. Publish a text file on that site, at `/.well-known/ba3tration.txt`, with one line:
   ```
   ba3tration-site-verification=<owner>/<repo>
   ```
   `<owner>/<repo>` is the testers repo that runs the scan, as GitHub names it. Several repos: one line each.
3. Run it:
   ```bash
   gh workflow run security-dast.yml                                               # baseline
   gh workflow run security-dast.yml -f scan_type=full -f i_am_authorized=yes      # active
   ```

Why a file that names the repo, and not a secret token: the file is public, so a token in it
could be copied by anyone into their own copy of this tool. A repository name cannot: the
workflow compares the file with the name GitHub gives the running repo, and a fork has another name.
Only someone who can publish on the site can add a line for a repo.

| | baseline (default) | full |
|---|---|---|
| What ZAP does | follows links and reads the answers | also sends attack requests |
| Needs | the proof file | the proof file, `i_am_authorized=yes`, and a test-environment host |
| Side effects | none expected | can submit forms and leave junk data |

A full scan only runs when the host name carries a test-environment label (`staging`, `stage`,
`stg`, `dev`, `test`, `testing`, `qa`, `uat`, `sandbox`, `preview`). If your staging has another
name, set the repository variable `BA3TRATION_ALLOW_ANY_HOST=1`. The proof file is still required.

## Limits, said plainly

- ZAP is not signed in: it sees what an anonymous visitor sees, not the screens behind the sign-in.
- Neither engine understands your business rules. Who may read whose data (tenant isolation,
  roles) needs a review by hand.
- Findings are leads. Check each one before you call it a vulnerability; the OWASP category
  in the report is a best guess from the rule's tags and CWE.
- The gate stops this tool, as shipped, from being pointed at a site that did not agree. It is
  not a lock on ZAP itself, which is public software. Scan only what you own or may test.
