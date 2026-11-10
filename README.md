# vulnscan

A standalone AI vulnerability scanner for private code. It is modelled on the shape of
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

Expect the first real run to need small fixes in those last two rows. Run it on one
component first (`--max-components 1`).

## Setup

Requirements: Python 3.10+, git, Docker (Docker Desktop on Windows/macOS), an Anthropic
API key. The host needs PyYAML only; the Claude Agent SDK is installed inside the scan
image, not on your machine.

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"     # Linux/macOS: .venv/bin/pip
```

The API key comes from the environment only. Set it in the shell you scan from and
never write it into a file in this repo:

```powershell
$env:ANTHROPIC_API_KEY = "<key>"          # PowerShell, this session only
```

```bash
export ANTHROPIC_API_KEY="<key>"          # bash
```

## Usage

```bash
vulnscan validate targets/aegis                         # check the config
vulnscan components targets/aegis                       # what diff mode would scan
vulnscan components targets/aegis --full                # all components
vulnscan scan targets/aegis --dry-run --max-components 1   # plan only: no build, no API calls
vulnscan scan targets/aegis --max-components 1 --dashboard # real scan of one component, with dashboard
vulnscan scan targets/aegis --since origin/main         # diff mode against another base
vulnscan scan targets/aegis --full --concurrency 2      # full scan (expensive)
vulnscan scan targets/aegis --seed codeql=codeql.sarif --seed osv=osv.json
vulnscan dashboard                                      # http://127.0.0.1:8765/
```

Useful flags: `--only NAME` (repeatable) scans named components; `--repo PATH|URL`
overrides `project.yaml`; `--runs-dir` changes where output goes (default `runs/`, which
is gitignored).

### Dashboard

`vulnscan dashboard` (or `scan --dashboard`) serves a read-only page on
`http://127.0.0.1:8765/`: runs in the sidebar; for the selected run the phase
(plan, build, scan, verify, report), per-component state with live agent activity
(turns, tool calls, last action), the verification queue, counts, tokens and cost, and the
verified findings with severity filters, evidence, reproducer and a coloured patch. It
refreshes every 2 s while a run is live. It follows the Claude app's look (ivory and
charcoal surfaces, terracotta accent, serif headings) and the system light/dark setting.

## How it works

```
host (vulnscan)                                   Docker
───────────────                                   ──────
plan: split components, pick diff set, seeds
build: docker build target  ───────────────────▶  vulnscan/<name>-target   (network on)
       docker build overlay ───────────────────▶  vulnscan/<name>-scan     (+ Python, Agent SDK, driver)
scan:  N components, `concurrency` at a time
       ┌──────────────────────── internal network (no route out) ─────────┐
       │ scan container: agent_runner.py ── HTTP ──▶ gateway ──TLS──▶ api.anthropic.com
       │   tools: Read, Grep, Glob, Bash           (holds the key; egress network)
       └──────────────────────────────────────────────────────────────────┘
verify: per candidate, fresh container, --network none
        run 1: reproducer on unpatched code  → must print VULNSCAN-PROOF:<nonce1>
        run 2: patch applied, same reproducer → must exit 0 without VULNSCAN-PROOF:<nonce2>
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
   random `VULNSCAN_NONCE`. It must exit 0 and print `VULNSCAN-PROOF:<nonce>` on its own line;
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
| `scan` | | `concurrency` (2), `model` (`claude-opus-5-5`), `effort` (high), `max_turns` (80), `max_budget_usd` per component (5.0), `timeout_minutes` (45), `memory`, `cpus`, `pids_limit`, `max_requests` (run-wide gateway cap) |
| `verification` | | `concurrency` (1), `timeout_seconds` (900), `require_patch_differential` (true), `memory`, `cpus` |
| `seeds` | `[]` | `[{tool: codeql|sarif|gitleaks|osv, path}]`; missing files are skipped with a warning |
| `gateway_image` | `python:3.13-slim` | image the gateway runs in |

The Dockerfile must leave the source at `workdir` and make builds and tests work
**offline**. The overlay (`docker/overlay.Dockerfile`) adds Python, the Agent SDK, git and
patch on top (apt, apk or dnf base images) and keeps the image's own user.

### Cost control

Diff mode by default; `concurrency: 2`; a per-component USD budget and turn limit
enforced by the Agent SDK; a per-component wall-clock timeout; a run-wide request cap in
the gateway. Token and cost figures in the summary come from the SDK's result messages;
when it reports none, the report says "not reported" rather than estimating.

## Security model of the scanner itself

What the scanner protects, and how:

- **The API key never enters a target container.** The scan container gets a placeholder
  key and `ANTHROPIC_BASE_URL` pointing at the gateway. The gateway container receives the
  key by name (`-e ANTHROPIC_API_KEY`, value copied from your shell, never on a command line
  or in `plan.json`), strips any credential the client sent and injects the real one.
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
  (DNS rebinding), serves only files it names inside `runs/<run-id>/`, sends a strict CSP and
  renders all data as text.
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
severity rules in `threat_model.md`, then `vulnscan validate` and `vulnscan components`.

## Development

```bash
.venv/Scripts/python -m pytest -q
```

There are no GitHub Actions workflows in this repo on purpose: the account's Actions
budget is zero. Run the tests locally.
