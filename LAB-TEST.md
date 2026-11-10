# First real run: lab machine checklist

Everything up to Docker is tested. This is the first time the Docker parts run: image builds,
the API gateway, Claude Code inside the scan container, and the verification containers.
Go in order; each step only costs more than the one before.

## 0. What the machine needs

- Docker Desktop with the WSL 2 backend, set to **Linux containers**, with at least 8 GiB of
  memory for Docker (Settings → Resources), or Docker Engine on Linux.
- Python 3.10+, git, the GitHub CLI (`gh`) logged in as xheavy0.
- Claude Code installed and logged in with the Max subscription (needed once for `claude setup-token`).

## 1. Get the code and run the tests (free)

```powershell
gh repo clone xheavy0/Threadscan
cd Threadscan
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
.venv\Scripts\python -m pytest -q
```

Expect every test to pass.

## 2. Token for this shell (free)

```powershell
claude setup-token
$env:CLAUDE_CODE_OAUTH_TOKEN = "<paste the token>"
```

Keep the token in the shell only, never in a file in the repo, and never paste it into a chat.

## 3. Static checks (free)

```powershell
.venv\Scripts\threadscan doctor targets\demo
```

Fix every `FAIL` line. A `WARN` about Docker memory means lowering `scan.memory` or giving Docker more.

## 4. Live smoke test (a few cents of usage, about 5 minutes the first time)

```powershell
.venv\Scripts\threadscan doctor targets\demo --live
```

This starts the gateway, builds a small scan image and runs one tiny Haiku agent. The lines that matter:

| Line | Must be | If not |
|---|---|---|
| Gateway from scan network | OK | the internal network or gateway is broken; send `runs\doctor-*\gateway\gateway.log` |
| Scan network isolation | OK ("blocked") | **stop**: the scan network reaches the internet |
| Claude Code through the gateway | OK | this is the open question: Claude Code may not send its OAuth token through `ANTHROPIC_BASE_URL`; send the line and `runs\doctor-*\agent-container.log` |
| Gateway refusals | OK ("none") | lists API paths Claude Code wanted that the gateway blocks; send the list |
| Verification driver / isolation | OK | send `runs\doctor-*\doctor.json` |

"Credential accepted upstream" may be a WARN with a subscription token (`/v1/models` can refuse
OAuth tokens); the agent line is the one that decides.

## 5. Demo scan (small usage, a few minutes)

```powershell
.venv\Scripts\threadscan scan targets\demo --full --max-components 1 --dashboard
```

Open http://127.0.0.1:8765/. The demo app has two planted bugs: a path traversal in `/files`
and `/admin/export` without the admin token check. A good run verifies at least one of them,
with a reproducer that prints the proof on the unpatched code and not after the patch. If
nothing is verified, look at Gate (drop reasons), `runs\<run>\dropped.json` and
`runs\<run>\components\*\out\transcript.jsonl`.

## 6. Aegis, one component

The Aegis checkout must sit next to this one (`..\cee-grc-tool`) or be given with `--repo`.

```powershell
.venv\Scripts\threadscan scan targets\aegis --max-components 1 --dashboard
```

The first build of the Aegis scan image downloads Maven and npm dependencies: allow 10–20
minutes and 10–20 GiB of disk. Later runs reuse it. Diff mode scans what changed since
`HEAD~1`; pass `--since <ref>` for more, or `--only auth` for a chosen component.

## 7. What to bring back

- The `doctor --live` output (it never prints the token).
- `runs\<run>\gateway\stats.json` (`denied_paths`, `by_status`).
- `runs\<run>\report.md` and `summary.json`.
- Any traceback, with tokens removed.

## Clean up

```powershell
docker image ls "threadscan/*"
docker image rm threadscan/doctor-scan:latest
```

`runs\` stays local (gitignored); delete old runs when you no longer need them.
