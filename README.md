<div align="center">

# 🛡️ Ba3tration-tester

**Test your app from every angle, in one GitHub Actions run.**

AI testers · code scan (SAST) · live scan (DAST) · one report by **OWASP Top 10:2025**

English · [العربية](README.ar.md)

</div>

## Three engines, one run

| Engine | Finds | Tool | Workflow |
|---|---|---|---|
| 🧭 Functional | crashes, broken flows, cut text at large sizes, dark mode, missing translations, right-to-left layout | AI testers, one per phone, on Android emulators and iOS Simulators | `agent-testers.yml` |
| 🧬 Code | injection, missing access checks, secrets left in the source | Semgrep + [SemSec](https://github.com/RobustaStudio/semsec) rules | `security-sast.yml` |
| 🛡️ Live site | missing security headers, misconfiguration, web flaws visible from outside | [OWASP ZAP](https://www.zaproxy.org/) | `security-dast.yml` |

`ba3tration.yml` runs the three together. Each engine also runs alone from its own workflow.

## Quick start

```bash
gh repo create my-tester --public --template beait/Ba3tration-tester --clone
cd my-tester && ./setup.sh             # Windows: .\setup.ps1
gh workflow run ba3tration.yml         # demo app: testers + code scan
gh run watch
bash scripts/collect.sh <run id>       # decrypts on your machine
```

On Windows, in PowerShell: `.\collect.ps1 <run id>` (a plain `bash` there is often the one of WSL, which cannot see `gh`).

`collect.sh` writes, in `runs/<id>/`:

- `SUMMARY.md`: what the testers found, grouped, with screenshots next to it.
- `BA3TRATION-REPORT.md`: security findings under their OWASP Top 10:2025 category, most severe first, then the testers' summary.
- `BA3TRATION-REPORT.txt`: the same report as plain text, for Notepad, an email or a ticket.

Point it at your own app with the inputs of each workflow: the testers' options are in [TESTERS.md](TESTERS.md) and [docs/configuration.md](docs/configuration.md), the security engines in [docs/security-scan.md](docs/security-scan.md).

```bash
gh workflow run ba3tration.yml -f engines=security -f code_repo=you/app     # security only
gh workflow run ba3tration.yml -f engines=functional                        # testers only
```

## The live scan needs the site's permission

ZAP scans nothing until your staging site names your testers repo:

1. `gh secret set STAGING_URL` (the origin of your staging site).
2. Publish `/.well-known/ba3tration.txt` on it with the line `ba3tration-site-verification=<owner>/<repo>`.

Without them, a full run skips the live scan with a warning. A passive scan is the default; an active scan also needs `i_am_authorized=yes` and a test-environment host. [Details](docs/security-scan.md).

## A skill for your coding agent

`skills/ba3tration-tester/SKILL.md` is one file in the open Agent Skills format. It lets Claude Code, Codex or any agent that reads `SKILL.md` set the tool up for your app, run it and read the report with you.

```bash
bash scripts/install_skill.sh          # both: ~/.claude/skills and ~/.agents/skills
```

The testers on the runners use Claude Code by default, or any Anthropic-compatible API (`llm_base_url`), whichever agent runs the skill.

## Rules

- **On demand only.** No schedule, nothing runs in the background.
- **No live scan without the site's proof**, and never on a site you do not own or may not test.
- **Encrypted results.** No finding reaches the job log; the private key stays on your machine.
- **Findings are leads.** Check each one by hand. The live scan is not signed in, and who may read whose data (tenant isolation, roles) needs a manual review.

## Built on

- [mobile-agent-testers](https://github.com/pierridotite/mobile-agent-testers) by Pierre Raffalli (MIT): the AI testers engine. Its README is [TESTERS.md](TESTERS.md).
- [SemSec](https://github.com/RobustaStudio/semsec) by Robusta Studio (MIT): security rules for Semgrep, fetched at run time.
- [Semgrep](https://semgrep.dev) and [OWASP ZAP](https://www.zaproxy.org/), run from their official container images.

MIT license: [LICENSE](LICENSE), [NOTICE](NOTICE).
