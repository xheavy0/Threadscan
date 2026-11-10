"""Read-only access to the target repository.

Every git call runs with ``GIT_OPTIONAL_LOCKS=0`` so that even ``git diff`` does not
opportunistically rewrite the target's index: the scanner never writes to the repo it
scans. Remote repos are cloned into the scanner's own cache with the command-running
``ext::`` transport and the local ``file://`` transport disabled.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from vulnscan.config import ProjectConfig

_GIT_ENV = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
_SAFE = ["-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never", "-c", "core.fsmonitor=false"]


class RepoError(RuntimeError):
    pass


def _git(repo: Path | None, *args: str, check: bool = True) -> str:
    cmd = ["git", *_SAFE]
    if repo is not None:
        cmd += ["-C", str(repo)]
    cmd += list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=_GIT_ENV)
    if check and proc.returncode != 0:
        raise RepoError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def resolve_repo(cfg: ProjectConfig, cache_dir: Path, offline: bool = False) -> Path:
    """Return a local checkout of the target. Local paths are used in place, read-only."""
    if not cfg.repo_is_url:
        path = Path(cfg.repo)
        if not path.is_dir():
            raise RepoError(f"target repo {path} does not exist")
        return path
    dest = cache_dir / "repos" / cfg.name
    if dest.is_dir():
        if not offline:
            _git(dest, "fetch", "--prune", "origin")
            ref = f"origin/{cfg.branch}" if cfg.branch else "origin/HEAD"
            _git(dest, "checkout", "--detach", ref)
        return dest
    if offline:
        raise RepoError(f"{cfg.repo} is not cloned yet and --offline was given")
    dest.parent.mkdir(parents=True, exist_ok=True)
    args = ["clone", "--filter=blob:none", "--no-recurse-submodules"]
    if cfg.branch:
        args += ["--branch", cfg.branch]
    _git(None, *args, "--", cfg.repo, str(dest))
    return dest


def is_git_repo(repo: Path) -> bool:
    return (repo / ".git").exists()


def head_commit(repo: Path) -> str | None:
    if not is_git_repo(repo):
        return None
    return _git(repo, "rev-parse", "HEAD", check=False).strip() or None


def list_files(repo: Path) -> list[str]:
    """Tracked plus untracked-but-not-ignored files, as POSIX paths relative to the root."""
    if is_git_repo(repo):
        out = _git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
        return sorted({p for p in out.split("\0") if p})
    files = []
    for root, dirs, names in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
        for n in names:
            files.append(Path(root, n).relative_to(repo).as_posix())
    return sorted(files)


def changed_files(repo: Path, base: str) -> list[str]:
    """Files added/changed since ``base`` (working tree included), plus untracked files."""
    if not is_git_repo(repo):
        raise RepoError("diff mode needs a git repository; use --full")
    if not _git(repo, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}", check=False).strip():
        raise RepoError(f"git ref '{base}' not found in {repo}")
    out = _git(repo, "diff", "--name-only", "-z", "--diff-filter=ACMRT", base, "--")
    untracked = _git(repo, "ls-files", "-z", "--others", "--exclude-standard")
    return sorted({p for p in (out + "\0" + untracked).split("\0") if p})


def diff_text(repo: Path, base: str, paths: list[str], max_bytes: int = 60_000) -> str:
    """Unified diff for ``paths`` since ``base``, truncated to ``max_bytes``."""
    if not paths or not is_git_repo(repo):
        return ""
    text = _git(repo, "diff", "--no-color", "--no-ext-diff", base, "--", *paths[:200], check=False)
    if len(text.encode("utf-8")) > max_bytes:
        text = text.encode("utf-8")[:max_bytes].decode("utf-8", "ignore") + "\n[... diff truncated ...]\n"
    return text


def read_repo_file(repo: Path, rel: str, max_bytes: int = 40_000) -> str | None:
    p = (repo / rel).resolve()
    if not p.is_relative_to(repo.resolve()) or not p.is_file():
        return None
    raw = p.read_bytes()
    data = raw[:max_bytes].decode("utf-8", "ignore")
    if len(raw) > max_bytes:
        data += f"\n[... truncated: {len(raw) - max_bytes} more bytes in {rel} ...]\n"
    return data
