# Threadscan

<img src="threadscan/static/threadscan.svg" width="72" height="72" alt="Threadscan mark">

Part of the Thread ecosystem. A standalone AI vulnerability scanner for private code. It is modelled on the shape of
Anthropic's public [OSS Scanner](https://github.com/anthropics/oss-scanner) (a target
config of `project.yaml` + `Dockerfile` + `threat_model.md`; build online, analyse
offline; report with a reproducer and a proposed patch), but it runs on your own machine,
against repos that cannot be enrolled in a public service. No code is shared with it.

What it does:

1. Builds the target with `docker build` (network on: all dependencies are fetched here).
2. Splits the target into components and runs one headless Claude agent per component,
   inside the built image, with the Internet cut except for an Anthropic-API-only gateway.
   Agents get the threat model, the known-issues list and optional seed output from
   CodeQL (SARIF), gitleaks and OSV.
3. **Verification gate:** re-runs every candidate's reproducer itself, in fresh containers
   with no network at all, before and after the proposed patch. Only candidates that
   demonstrably reproduce, and stop reproducing with the patch, become findings. The rest
   are dropped and counted, never reported.
4. Writes per-finding JSON, a Markdown report and a run summary, and serves a local
   dashboard with live progress and the findings list.

Diff mode (only components touched since a git ref) is the default; a full scan is opt-in.

## Status of v1

| Part | State |
|---|---|
| Config parsing, component splitting, diff selection, seeds, prompts, gate logic, report, dashboard | Implemented, unit-tested (`pytest`), dry run against `targets/aegis` works end to end |
| Docker build, scan network, gateway, agent runs, verification containers | Implemented, **not yet exercised**: Docker and an API key were not available on the machine v1 was built on |
| Aegis scan image (`targets/aegis/Dockerfile`) | Written, **not yet built** |
| Subscription mode (`auth: subscription`) | Implemented and unit-tested, **not yet run against the real API**: whether Claude Code sends its OAuth token through `ANTHROPIC_BASE_URL` is unconfirmed |

Expect the first real run to need small fixes in those last three rows. Run it on one
component first (`--max-components 1`).

## Setup

Requirements: Python 3.10+, git, Docker (Docker Desktop on Windows/macOS), and either a
Claude subscription or an Anthropic API key. The host needs PyYAML only; the Claude Agent
SDK is installed inside the scan image, not on your machine.

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"     # Linux/macOS: .venv/bin/pip
```

### Credentials: subscription or API key

`scan.auth` in `project.yaml` (or `--auth`) picks one. Either credential comes from the
environment of the shell you scan from; never write it into a file in this repo.

**`subscription`** (your own Pro/Max plan, what `targets/aegis` uses). Create a one-year
Claude Code token and set it for the session:

```bash
claude setup-token
```

```powershell
$env:CLAUDE_CODE_OAUTH_TOKEN = "<token>"  # PowerShell, this session only
```

- Usage is not billed per token; it counts against the plan's 5-hour and weekly limits,
  which are shared with claude.ai and your own Claude Code use. Anthropic does not publish
  exact numbers.
- Safeguards in this mode: one agent at a time unless `scan.concurrency` is set; a `--full`
  scan is refused without `--max-components`, `--only` or `--allow-full`; when the API
  answers 429 (the usage limit), no further components start, and the report lists them
  with a ready `--only …` command to resume after the reset.
- Costs in the report are API-price equivalents, labelled "not billed".
- **Personal use only.** Anthropic does not allow offering claude.ai login or subscription
  limits to other users of a product built on the Agent SDK without approval. If Threadscan
  is ever shipped to others, they must use an API key.

**`api_key`** (Claude Console, pay per use; better for full scans):

```powershell
$env:ANTHROPIC_API_KEY = "<key>"          # PowerShell, this session only
```

```bash
export ANTHROPIC_API_KEY="<key>"          # bash
```

## Usage

```bash
threadscan validate targets/aegis                         # check the config
threadscan components targets/aegis                       # what diff mode would scan
threadscan components targets/aegis --full                # all components
threadscan scan targets/aegis --dry-run --max-components 1   # plan only: no build, no API calls
threadscan scan targets/aegis --max-components 1 --dashboard # real scan of one component, with dashboard
threadscan scan targets/aegis --since origin/main         # diff mode against another base
threadscan scan targets/aegis --full --concurrency 2      # full scan (expensive)
threadscan scan targets/aegis --seed codeql=codeql.sarif --seed osv=osv.json
threadscan dashboard                                      # http://127.0.0.1:8765/
```

Useful flags: `--only NAME` (repeatable) scans named components; `--repo PATH|URL`
overrides `project.yaml`; `--runs-dir` changes where output goes (default `runs/`, which
is gitignored).

### Dashboard

`threadscan dashboard` (or `scan --dashboard`) serves a read-only page on
`http://127.0.0.1:8765/`, laid out like a cloud-security console: navy side navigation
with the runs, a light work area, and four views.

- **Overview:** KPI cards (verified issues with a severity bar, components scanned,
  candidates, cost or subscription usage), the plan → build → scan → verify → report
  pipeline, the usage-limit banner with the resume command, top issues, issues by
  severity, the verification funnel.
- **Issues:** the verified issues table with severity filter pills and search. Clicking a
  row opens a detail drawer with Overview, Evidence (the gate's own runs), Reproducer and
  Remediation (the patch) tabs.
- **Components:** per-component state with live agent activity.
- **Verification gate:** every candidate's result and the drop reasons.

It refreshes every 2 s while a run is live, and follows the system light/dark setting
(toggle at the bottom of the navigation). Inter and JetBrains Mono are self-hosted under
`threadscan/static/fonts/` (SIL OFL), so the page works offline and never calls a font
CDN. Mark and accent: [docs/branding.md](docs/branding.md).

## How it works

```
host (threadscan)                                   Docker
───────────────                                   ──────
plan: split components, pick diff set, seeds
build: docker build target  ───────────────────▶  threadscan/<name>-target   (network on)
       docker build overlay ───────────────────▶  threadscan/<name>-scan     (+ Python, Agent SDK, driver)
scan:  N components, `concurrency` at a time
       ┌──────────────────────── internal network (no route out) ─────────┐
       │ scan container: agent_runner.py ── HTTP ──▶ gateway ──TLS──▶ api.anthropic.com
       │   tools: Read, Grep, Glob, Bash           (holds the key; egress network)
       └──────────────────────────────────────────────────────────────────┘
verify: per candidate, fresh container, --network none
        run 1: reproducer on unpatched code  → must print THREADSCAN-PROOF:<nonce1>
        run 2: patch applied, same reproducer → must exit 0 without THREADSCAN-PROOF:<nonce2>
report: findings/*.json, findings.json, report.md, summary.json, dropped.json
```

### Why Python

The Agent SDK exists for Python and TypeScript. Python was chosen because the host side
is mostly subprocess orchestration, file handling and YAML, which the standard library
plus PyYAML covers with no build step; the gateway and the dashboard server are
stdlib-only too, so they can be mounted into a stock `python:*-slim` container without
installing anything. The same language runs on the host and in the container, so the
in-container runner's helpers are covered by the host's unit tests.

### Components

Every file that survives `include`/`exclude` goes to the first matching **explicit**
component; otherwise to the deepest **auto** root containing it, split `depth`
directories below that root; otherwise to the `leftover` component. Explicit components
carry a `priority`, so `--max-components N` takes the most security-relevant ones first.

### The reproducer contract and the gate

Agents must hand in, for each candidate: file:line, severity with a rationale from the
threat model, CWE, a bash reproducer (plus optional files, e.g. a test class) and a
unified diff. The gate then, independently of anything the agent says:

1. writes the files into a fresh container (`--network none`) and runs the script with a
   random `THREADSCAN_NONCE`. It must exit 0 and print `THREADSCAN-PROOF:<nonce>` on its own line;
2. in another fresh container applies the patch (`git apply`, falling back to `patch -p1`)
   and runs the script with a new nonce. It must exit 0 and **not** print the proof.

Drop reasons are counted in the report: invalid output, duplicate, container error,
timeout, reproducer failed, not reproduced, no patch, patch did not apply, patch did not
fix, fix unproven. The agent's own `self_test` text is kept in the finding JSON, labelled
as a claim, and never used as evidence.

`verification.require_patch_differential: false` keeps reproduced candidates even without
a working patch; the report notes this per finding. The default is the strict mode.

## Target config

`targets/<name>/` holds `project.yaml`, a `Dockerfile` and optionally `threat_model.md`.
An unknown key in `project.yaml` is an error, so typos cannot silently change behaviour.

| Key | Default | Meaning |
|---|---|---|
| `name` | required | lowercase id, used in image and container names |
| `repo` | required | local path (relative to the target dir) or `https://`/`ssh://`/`git@` URL, `#branch` optional |
| `dockerfile` | `Dockerfile` | built with the target repo as context; a `<Dockerfile>.dockerignore` next to it overrides the repo's `.dockerignore` |
| `workdir` | `/src` | where the source lives inside the image |
| `threat_model` | `threat_model.md` | where untrusted input enters, scope, severity rules |
| `known_issues` | none | file in the target repo listing known/accepted issues |
| `diff_base` | `HEAD~1` | base ref for diff mode |
| `components` | | `include`, `exclude`, `explicit[{name, paths, priority, description}]`, `auto[{root, depth}]`, `leftover` |
| `scan` | | `auth` (`api_key` or `subscription`), `concurrency` (2 with an API key, 1 with a subscription), `model` (`claude-opus-5-5`), `effort` (high), `max_turns` (80), `max_budget_usd` per component (5.0), `timeout_minutes` (45), `memory`, `cpus`, `pids_limit`, `max_requests` (run-wide gateway cap) |
| `verification` | | `concurrency` (1), `timeout_seconds` (900), `require_patch_differential` (true), `memory`, `cpus` |
| `seeds` | `[]` | `[{tool: codeql|sarif|gitleaks|osv, path}]`; missing files are skipped with a warning |
| `gateway_image` | `python:3.13-slim` | image the gateway runs in |

The Dockerfile must leave the source at `workdir` and make builds and tests work
**offline**. The overlay (`docker/overlay.Dockerfile`) adds Python, the Agent SDK, git and
patch on top (apt, apk or dnf base images) and keeps the image's own user.

### Cost control

Diff mode by default; `concurrency` 2 (1 on a subscription); a per-component USD budget
and turn limit enforced by the Agent SDK (on a subscription the budget caps API-equivalent
usage); a per-component wall-clock timeout; a run-wide request cap in the gateway; on a
subscription, the stop at the usage limit and the full-scan guard described under
Credentials. Token and cost figures come from the SDK's result messages; when it reports
none, the report says "not reported" rather than estimating.

## Security model of the scanner itself

What the scanner protects, and how:

- **The credential never enters a target container.** The scan container gets a
  placeholder of the right kind (`ANTHROPIC_API_KEY`, or `CLAUDE_CODE_OAUTH_TOKEN` with no
  API key variable at all, since an API key would outrank the token) and
  `ANTHROPIC_BASE_URL` pointing at the gateway. The gateway container receives the real one
  by name (`-e ANTHROPIC_API_KEY` or `-e CLAUDE_CODE_OAUTH_TOKEN`, value copied from your
  shell, never on a command line or in `plan.json`), strips any credential the client sent
  and injects the real one: `x-api-key`, or `Authorization: Bearer` plus the OAuth beta flag.
  It also records refused paths in `gateway/stats.json`.
- **No egress except the Anthropic API.** Scan containers sit only on a Docker
  `--internal` network. The gateway is the only container on both that network and a
  per-run egress network (not Docker's default bridge), publishes no host port, accepts
  only `POST /v1/messages`, `POST /v1/messages/count_tokens` and `GET /v1/models…`,
  refuses absolute-form proxy requests, and forwards over verified TLS to the fixed host
  `api.anthropic.com`. Claude Code telemetry, error reporting and auto-update are turned off.
- **Verification has no network at all** (`--network none`), so a reproducer cannot reach
  the API, the gateway or the internet.
- **Target content is untrusted input.** The agent loads no settings, hooks or `CLAUDE.md`
  from the target (`setting_sources=[]`); the Aegis build context excludes `.claude/`,
  `CLAUDE.md`, `.git`, `.env*` and key material. The system prompt tells the agent that repo
  content is material under review, never instructions.
- **Limited agent tools.** Read, Grep, Glob and Bash only, `dontAsk` permission mode (no
  other tool can be approved); Write/Edit/Web tools and subagents are disallowed. Bash runs
  inside the disposable container.
- **Container hardening.** All containers: `--cap-drop ALL`, `no-new-privileges`, memory,
  CPU and PID limits; the gateway also `--read-only` as `nobody`. The scan task is mounted
  read-only; each component gets its own output directory.
- **Read-only toward the target repo.** Only `git ls-files`/`diff`/`rev-parse` (with
  `GIT_OPTIONAL_LOCKS=0`, so not even the index is refreshed) and `docker build` with the repo
  as context. Remote repos are cloned into `.cache/` with the `ext::` and `file://`
  transports disabled.
- **Untrusted agent output is validated, never repaired.** Paths in findings and reproducer
  files must be relative, without `..` or `.git`; sizes are capped.
- **Secrets are scrubbed from output.** Everything written to `runs/` or served by the
  dashboard passes a redactor (the live API key value, `sk-ant-`, GitHub, AWS, Slack tokens,
  private keys). gitleaks seeds are loaded without their `Secret`/`Match` fields.
- **The dashboard is local and read-only.** It binds to 127.0.0.1, checks the `Host` header
  (DNS rebinding), serves only files it names inside `runs/<run-id>/` plus a fixed list of
  its own fonts and mark, loads nothing from other hosts, sends a strict CSP and renders all
  data as text.
- **Reports stay private.** `runs/` and `targets/*/seeds/` are gitignored.

Residual risks to keep in mind:

- `docker build` runs the target's Dockerfile with network on, like any build. Scan only
  targets you trust to build on your machine.
- Code running in the scan container can call the Messages API through the gateway (it
  cannot read the key). That is bounded by the gateway's `max_requests` and the SDK budget.
- The gate proves that the reproducer tells the patched code from the unpatched code, not
  that the behaviour is a vulnerability under your threat model. A model can still write a
  well-behaved reproducer for something harmless, or rate severity too high. Findings are
  model-generated: review them before acting.
- A prompt injection in the target can make an agent miss things (false negatives). It
  cannot get an unproven claim past the gate.
- Subscription mode relies on Claude Code sending its OAuth token to a custom
  `ANTHROPIC_BASE_URL` and on the Messages API being the only endpoint it needs. If the
  first run fails to authenticate, `gateway/stats.json` (`denied_paths`, `by_status`) shows
  what it tried; the fallback would be giving the scan container its own route to the API,
  which weakens the isolation above.
- Docker Desktop containers share one VM kernel; this is container isolation, not a VM per
  scan like the hosted OSS Scanner.

## Output

`runs/<run-id>/`:

| File | Content |
|---|---|
| `status.json` | live phase and per-component state (the dashboard reads it) |
| `plan.json` | selected components and the exact docker commands |
| `components/<slug>/task.json` | prompts, threat model, file list, diff, seeds given to that agent |
| `components/<slug>/out/` | `progress.json`, `transcript.jsonl`, `candidates.json` from the agent |
| `verify/<id>/` | gate inputs, container logs, `verdict.json` |
| `findings/<id>.json`, `findings.json` | verified findings only |
| `dropped.json` | unproven candidates with reasons (scanner debugging, not findings) |
| `report.md` | the human-readable report |
| `summary.json` | components scanned, candidates, verified, dropped, seeds, tokens, cost, gateway stats |

## Adding a target

Copy `targets/aegis/` as a template: point `repo` at the checkout, write a Dockerfile that
leaves the source and an offline-ready build at `workdir`, describe trust boundaries and
severity rules in `threat_model.md`, then `threadscan validate` and `threadscan components`.

## Development

```bash
.venv/Scripts/python -m pytest -q
```

There are no GitHub Actions workflows in this repo on purpose: the account's Actions
budget is zero. Run the tests locally.
