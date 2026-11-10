# Threadscan: threat model

Threadscan is a command-line vulnerability scanner (Python, PyYAML only on the host). It
builds a target repository in Docker, runs Claude agents on it in a container whose only
route out is a local API gateway, and keeps a finding only when its reproducer prints a
proof line on the unpatched code and stops printing it after the patch. A localhost
dashboard shows runs, lets the owner triage issues and ask an AI model about one issue.

## Working in the scan image

- Source at `/src`, package in `threadscan/`. Tests: `python -m pytest -q -p no:cacheprovider`.
- Docker is not available in the image. Exercise the code directly in Python: for example
  start the dashboard with `python -c "from threadscan.dashboard import serve; ..."` on a
  temporary runs directory, or the gateway with `threadscan.gateway`, and send requests with
  `curl` to `127.0.0.1`.
- `examples/vulnapp` is a deliberately vulnerable demo app and is out of scope.

## Trust boundaries and untrusted input

1. **The scanned repository is hostile.** Its files, git metadata, build output, and the
   text the agent writes after reading them (candidate JSON, reproducers, patches, titles,
   evidence) are attacker-controlled. They flow into: candidate parsing (`candidates.py`),
   the verification gate (`verify.py`), reports (`report.py`), exports (`exporters.py`:
   SARIF, CSV, JSON, a self-contained HTML file), the dashboard, and Ask AI prompts.
2. **The gateway** (`gateway.py`) holds the Anthropic credential. Containers on the scan
   network reach it; it must forward only the allowed API paths to `api.anthropic.com`
   and never reveal the credential to the container.
3. **The dashboard** binds to 127.0.0.1. Web pages the owner visits in a browser are
   untrusted: they must not read data from it (DNS rebinding, CORS) or change triage state
   or send Ask AI questions (CSRF). Its POST routes require the `X-Threadscan-Request`
   header, same-origin, and JSON.
4. **Config and seed files** (`project.yaml`, SARIF/JSON seeds, `--repo`, run IDs, issue IDs
   in URLs) are owner-supplied but must not let a value escape its directory or run a command.
5. **Ask AI** (`ask.py`) sends one issue's data to a model provider the owner configured,
   with keys read from environment variables. Issue text is untrusted (see 1).

## What must hold

- The credential (API key or OAuth token) never reaches a scan or verification container,
  a log, a report, an export, the dashboard, or an Ask AI prompt.
- Nothing from the scanned repo or agent output can execute on the host, write outside
  `runs/<run-id>/`, or make Threadscan run a git, docker or shell command with
  attacker-chosen options.
- No finding is reported unless the gate verified it; agent output cannot forge the proof
  line or bypass the differential patch check.
- Agent-controlled text cannot run script in the dashboard or the exported HTML report, and
  cannot inject spreadsheet formulas through the CSV export.
- `threadscan prune` never deletes outside the runs directory.
- Ask AI providers get no tools; their answers are shown, never executed.

## Severity

- **Critical**: credential disclosure to a container or a third party; code execution on
  the host from scanned-repo content or agent output.
- **High**: writing or deleting files outside `runs/`; a forged or unverified finding
  reported as verified; script execution in the dashboard or HTML export; a remote web page
  reading dashboard data or changing triage.
- **Medium**: CSV formula injection; leaking local paths or scan results to another site;
  a scan container reaching the internet other than through the gateway's allowed paths.
- **Low**: hardening, denial of service against the local dashboard.

## Out of scope

- `examples/vulnapp` (vulnerable on purpose) and `tests/`.
- Attacks that need control of the owner's machine, environment variables or Docker daemon.
- Vulnerabilities in Docker, Claude Code or model providers themselves.
