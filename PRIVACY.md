# Privacy

mobile-agent-testers collects no data. There is no server, no analytics and no
account.

- The plugin is one skill: instructions that Claude Code follows on your
  machine.
- The workflow runs in your own GitHub repository, on GitHub Actions, and calls
  the Claude API with your own credentials, under GitHub's and Anthropic's
  terms.
- Test results (reports, screenshots, logs, app builds) are encrypted with your
  public key before upload. Only you hold the private key.
- Analytics hosts listed in `block_hosts` are blocked inside the test phones.
- On your machine, `collect.sh` calls no model by default. Only with
  `SUMMARY_GROUPING=1` does it send the report titles, screens and severities
  to Claude through your own Claude Code login, to group duplicate reports.
- Only when you set `SUMMARY_WEBHOOK_URL` on your machine does `collect.sh`
  post a short summary (counts, the top bug titles and the personas that hit
  them, no screenshot) to that Slack or Discord webhook. Nothing is posted from
  the workflow.
- `scripts/merge_screens.py` runs only when you start it. It sends the titles
  and element names of the map's cards, with the testers' languages and devices,
  to Claude through your own Claude Code login. No screenshot is sent.
- `scripts/draft_issues.py` runs only on your machine after decryption. It
  previews draft issues without network calls by default, and runs
  `gh issue create` only when you pass `--create --repo OWNER/REPO` and confirm.

Questions: open an issue at
https://github.com/pierridotite/mobile-agent-testers/issues

## Security engines (Ba3tration-tester)

- The code scan runs Semgrep on the runner, with its metrics off. It downloads rules (SemSec
  from GitHub, the OWASP Top 10 pack from the Semgrep registry); the workflow uploads your
  source code nowhere.
- The live scan sends requests to one address only, the one in your `STAGING_URL` secret, and
  only after that site published a proof naming your repository.
- Their findings are encrypted with your public key before upload, like the testers' reports.
