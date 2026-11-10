# Threadscan backlog

Worked top to bottom. Each task lands as its own commit with tests; the box is ticked in
the same commit. Docker-dependent behaviour is unit-tested with fakes here and confirmed on
the lab machine (see LAB-TEST.md).

## Done

- [x] v1 scanner: config, components, diff mode, seeds, agents, gateway, verification gate, reports
- [x] Subscription mode with usage-limit safeguards
- [x] Wiz-style dashboard: Boards, Issues, Graph, Inventory, Gate, Trends, Compliance
- [x] Lifecycle across runs (resolved only after re-running the old reproducer), triage, OWASP mapping
- [x] `threadscan doctor` (+ `--live`), demo target, LAB-TEST.md
- [x] Findings (seeds) and Policies views, notifications, saved views, copy/download patches
- [x] Reports and exports: HTML, SARIF 2.1.0, CSV, JSON

## Next

- [x] **T1 `threadscan recheck`**: re-run the reproducers of open issues against the current
  code, with no agents and no API usage. Fixed (exit 0, no proof) → triage set to Resolved with
  the evidence; still reproducing → stays open (re-opened if it had been marked Resolved);
  cannot run → left alone and reported. Results in `runs/rechecks/`, visible in the issue's
  Activity.
- [x] **T2 Severity override and "Copy as GitHub issue"**: triage can adjust an issue's
  severity (the original is kept and shown); dashboard, exports and SARIF use the adjusted
  one. The drawer copies a ready Markdown issue body (never posts anything).
- [x] **T3 Verified-fixes patch bundle**: one `verified-fixes.patch` with every patch the gate
  verified, in file order, each with a header naming its issue; export format `patches`.
- [x] **T4 `threadscan init <repo>`**: scaffold `targets/<name>/` (project.yaml, Dockerfile,
  threat_model.md) by detecting Maven, Gradle, npm/pnpm/yarn, Python, Go, Rust, .NET; never
  overwrites, never touches the target repo.
- [x] **T5 `threadscan seeds <target>`**: fetch seed input: the latest CodeQL SARIF per
  language from GitHub code scanning (read-only `gh api`), plus gitleaks (`--redact`) and
  osv-scanner when installed, into `targets/<name>/seeds/`.
- [x] **T6 `threadscan watch <target>`**: poll the target repo; when HEAD moves, run a diff
  scan since the last scanned commit (one at a time; respects the usage-limit stop);
  optional `--recheck` after each scan.
- [x] **T7 `threadscan prune`**: keep the newest N finished runs per target (default 10);
  dry run unless `--yes`; never touches `triage.json`.

- [x] **Ask AI about an issue**: a drawer tab and top-bar pill that ask any configured model
  (local Claude Code CLI, Anthropic API, any OpenAI-compatible server, or local Ollama) about
  one issue, with no tools, keys only from env vars, and the destination shown before sending.

Also done along the way: dark mode is neutral graphite and the dashboard uses Rubik and
Fira Code, the fonts Wiz's product UI loads.

## Proposed, needs a decision

- **Notifications outside the machine** (Slack/Teams webhook). Sends data off the machine;
  waits for your go-ahead and a webhook you choose.

## Lab machine (owner)

- [ ] `threadscan doctor targets\demo --live` all OK
- [ ] Demo scan verifies at least one planted bug
- [ ] One component of a real target scanned end to end
