"""``threadscan seeds <target>``: collect seed input for the agents.

* **CodeQL**: the newest analysis per category (one per language) from GitHub code scanning,
  downloaded as SARIF with read-only ``gh api`` calls and merged into one file. The GitHub
  repository comes from ``--github owner/repo`` or the target repo's ``origin`` remote.
* **gitleaks**: ``gitleaks detect --redact`` over the repository, when installed. Secret values
  are redacted by gitleaks and dropped again when Threadscan loads the report.
* **OSV**: ``osv-scanner`` over the lockfiles, when installed.

Everything lands in ``targets/<name>/seeds/`` (gitignored). The target repository is only read.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

Runner = Callable[[list[str], float | None], tuple[int | None, str, str]]


def default_runner(args: list[str], timeout: float | None = None) -> tuple[int | None, str, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return None, "", f"{args[0]}: not found"
    except subprocess.TimeoutExpired:
        return None, "", f"timed out after {timeout}s"


@dataclass
class Outcome:
    tool: str
    status: str  # ok | skipped | failed
    detail: str
    path: Path | None = None


_GH_RE = re.compile(r"github\.com[:/]+([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


def github_slug(remote_url: str) -> str | None:
    m = _GH_RE.search(remote_url.strip())
    return f"{m.group(1)}/{m.group(2)}" if m else None


def infer_github(repo: Path, run: Runner) -> tuple[str | None, str | None]:
    """(owner/repo, current branch ref) from the local checkout, read-only."""
    code, out, _ = run(["git", "-C", str(repo), "remote", "get-url", "origin"], 20)
    slug = github_slug(out) if code == 0 else None
    code, out, _ = run(["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"], 20)
    branch = out.strip() if code == 0 and out.strip() and out.strip() != "HEAD" else None
    return slug, (f"refs/heads/{branch}" if branch else None)


def latest_per_category(analyses: list[dict], tool: str = "CodeQL") -> list[dict]:
    best: dict[str, dict] = {}
    for a in analyses:
        if (a.get("tool") or {}).get("name") != tool:
            continue
        key = a.get("category") or a.get("analysis_key") or "default"
        if key not in best or (a.get("created_at") or "") > (best[key].get("created_at") or ""):
            best[key] = a
    return sorted(best.values(), key=lambda a: a.get("category") or "")


def merge_sarif(docs: list[dict]) -> dict:
    runs = [r for d in docs for r in (d.get("runs") or [])]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": runs}


def fetch_codeql(slug: str, ref: str | None, out: Path, run: Runner) -> Outcome:
    q = f"repos/{slug}/code-scanning/analyses?per_page=100" + (f"&ref={ref}" if ref else "")
    code, body, err = run(["gh", "api", q], 60)
    if code is None and "not found" in err:
        return Outcome("codeql", "skipped", "the GitHub CLI (gh) is not installed")
    if code != 0:
        hint = "code scanning is not enabled, or gh lacks access (gh auth refresh -s security_events)"
        return Outcome("codeql", "failed", f"{(err.strip().splitlines() or ['?'])[-1][:200]} ({hint})")
    try:
        analyses = json.loads(body)
    except ValueError:
        return Outcome("codeql", "failed", "unexpected response from gh api")
    picked = latest_per_category(analyses)
    if not picked:
        return Outcome("codeql", "skipped", f"no CodeQL analyses for {slug}" + (f" on {ref}" if ref else ""))
    docs = []
    for a in picked:
        code, body, err = run(["gh", "api", "-H", "Accept: application/sarif+json", f"repos/{slug}/code-scanning/analyses/{a['id']}"], 120)
        if code != 0:
            return Outcome("codeql", "failed", f"analysis {a['id']}: {(err.strip().splitlines() or ['?'])[-1][:200]}")
        try:
            docs.append(json.loads(body))
        except ValueError:
            return Outcome("codeql", "failed", f"analysis {a['id']} is not valid SARIF")
    merged = merge_sarif(docs)
    out.write_text(json.dumps(merged), encoding="utf-8")
    n = sum(len(r.get("results") or []) for r in merged["runs"])
    cats = ", ".join(a.get("category") or "default" for a in picked)
    return Outcome("codeql", "ok", f"{n} results from {len(picked)} analyses ({cats}), commit {(picked[0].get('commit_sha') or '')[:12]}", out)


def fetch_gitleaks(repo: Path, out: Path, run: Runner) -> Outcome:
    if not shutil.which("gitleaks"):
        return Outcome("gitleaks", "skipped", "gitleaks is not installed")
    code, _, err = run(["gitleaks", "detect", "--source", str(repo), "--report-format", "json", "--report-path", str(out),
                        "--redact", "--no-banner", "--exit-code", "0"], 900)
    if code != 0 or not out.is_file():
        return Outcome("gitleaks", "failed", (err.strip().splitlines() or ["?"])[-1][:200])
    try:
        n = len(json.loads(out.read_text(encoding="utf-8") or "[]"))
    except ValueError:
        return Outcome("gitleaks", "failed", "report is not JSON")
    return Outcome("gitleaks", "ok", f"{n} findings (values redacted)", out)


def fetch_osv(repo: Path, out: Path, run: Runner) -> Outcome:
    if not shutil.which("osv-scanner"):
        return Outcome("osv", "skipped", "osv-scanner is not installed")
    # v2 syntax first, then v1; exit 1 only means vulnerabilities were found
    for args in (["osv-scanner", "scan", "source", "-r", str(repo), "--format", "json", "--output", str(out)],
                 ["osv-scanner", "--format", "json", "--output", str(out), "-r", str(repo)]):
        code, _, err = run(args, 900)
        if code in (0, 1) and out.is_file():
            try:
                data = json.loads(out.read_text(encoding="utf-8"))
            except ValueError:
                continue
            n = sum(len(p.get("vulnerabilities") or []) for r in data.get("results") or [] for p in r.get("packages") or [])
            return Outcome("osv", "ok", f"{n} vulnerable package versions", out)
    return Outcome("osv", "failed", (err.strip().splitlines() or ["?"])[-1][:200])


def fetch_all(target_dir: Path, repo: Path, tools: set[str], github: str | None = None, ref: str | None = None,
              run: Runner = default_runner) -> list[Outcome]:
    seeds_dir = target_dir / "seeds"
    seeds_dir.mkdir(parents=True, exist_ok=True)
    outcomes = []
    if "codeql" in tools:
        slug, inferred_ref = (github, None) if github else infer_github(repo, run)
        if not slug:
            outcomes.append(Outcome("codeql", "skipped", "no GitHub repository: pass --github owner/repo"))
        else:
            outcomes.append(fetch_codeql(slug, ref or inferred_ref, seeds_dir / "codeql.sarif", run))
    if "gitleaks" in tools:
        outcomes.append(fetch_gitleaks(repo, seeds_dir / "gitleaks.json", run))
    if "osv" in tools:
        outcomes.append(fetch_osv(repo, seeds_dir / "osv.json", run))
    return outcomes
