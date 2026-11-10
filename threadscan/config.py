"""Target configuration: ``targets/<name>/project.yaml`` plus its Dockerfile and threat model.

Parsing is strict on purpose: an unknown key is an error, not a silent no-op, so a
typo such as ``concurrancy: 8`` cannot quietly run eight heavy containers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
MEMORY_RE = re.compile(r"^[1-9][0-9]*[mg]$")
SEED_TOOLS = ("codeql", "sarif", "gitleaks", "osv")
EFFORTS = ("low", "medium", "high", "xhigh", "max")
# git transports that can run commands (ext::) or read the host (file://) are refused.
_URL_RE = re.compile(r"^(https://|ssh://|git@[A-Za-z0-9.-]+:)[^\s]+$")

DEFAULT_EXCLUDES = [
    "**/node_modules/**",
    "**/target/**",
    "**/dist/**",
    "**/build/**",
    "**/.git/**",
    "**/*.min.js",
    "**/*.map",
    "**/*.lock",
    "**/package-lock.json",
    "**/*.png",
    "**/*.jpg",
    "**/*.jpeg",
    "**/*.gif",
    "**/*.ico",
    "**/*.svg",
    "**/*.woff",
    "**/*.woff2",
    "**/*.pdf",
]


class ConfigError(ValueError):
    """Raised with every problem found, not just the first."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("invalid target config:\n  - " + "\n  - ".join(problems))


@dataclass
class AutoSplit:
    root: str
    depth: int = 1


@dataclass
class ExplicitComponent:
    name: str
    paths: list[str]
    priority: int = 0
    description: str = ""


@dataclass
class ComponentsConfig:
    include: list[str] = field(default_factory=lambda: ["**"])
    exclude: list[str] = field(default_factory=list)
    auto: list[AutoSplit] = field(default_factory=list)
    explicit: list[ExplicitComponent] = field(default_factory=list)
    # Files matched by no explicit component and no auto root go here (or are skipped if None).
    leftover: str | None = "misc"


@dataclass
class ScanConfig:
    concurrency: int = 2
    model: str = "claude-opus-5-5"
    effort: str = "high"
    max_turns: int = 80
    max_budget_usd: float = 5.0  # per component; enforced by the Agent SDK
    timeout_minutes: int = 45  # per component container
    memory: str = "6g"
    cpus: float = 2.0
    pids_limit: int = 2048
    max_requests: int = 2000  # backstop enforced by the API gateway for the whole run


@dataclass
class VerificationConfig:
    concurrency: int = 1
    timeout_seconds: int = 900
    require_patch_differential: bool = True
    memory: str = "4g"
    cpus: float = 2.0


@dataclass
class SeedSpec:
    tool: str
    path: Path


@dataclass
class ProjectConfig:
    name: str
    target_dir: Path
    repo: str  # local path (absolute) or git URL
    branch: str | None
    dockerfile: Path
    workdir: str
    threat_model: Path | None
    threat_model_text: str
    known_issues: str | None  # path inside the target repo
    diff_base: str
    components: ComponentsConfig
    scan: ScanConfig
    verification: VerificationConfig
    seeds: list[SeedSpec]
    gateway_image: str

    @property
    def repo_is_url(self) -> bool:
        return bool(_URL_RE.match(self.repo))


class _Reader:
    """Pulls typed values out of a mapping and records every problem."""

    def __init__(self, problems: list[str]):
        self.problems = problems

    def mapping(self, data: Any, ctx: str, allowed: set[str]) -> dict:
        if data is None:
            return {}
        if not isinstance(data, dict):
            self.problems.append(f"{ctx}: expected a mapping, got {type(data).__name__}")
            return {}
        for key in data:
            if key not in allowed:
                self.problems.append(f"{ctx}: unknown key '{key}' (allowed: {', '.join(sorted(allowed))})")
        return data

    def get(self, data: dict, key: str, typ: type | tuple, default: Any, ctx: str) -> Any:
        if key not in data or data[key] is None:
            return default
        value = data[key]
        # bool is an int subclass; never accept it where a number is expected.
        if isinstance(value, bool) and typ is not bool and bool not in (typ if isinstance(typ, tuple) else (typ,)):
            self.problems.append(f"{ctx}.{key}: expected {_tname(typ)}, got bool")
            return default
        if not isinstance(value, typ):
            self.problems.append(f"{ctx}.{key}: expected {_tname(typ)}, got {type(value).__name__}")
            return default
        return value

    def str_list(self, data: dict, key: str, default: list[str], ctx: str) -> list[str]:
        value = data.get(key)
        if value is None:
            return list(default)
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            self.problems.append(f"{ctx}.{key}: expected a list of non-empty strings")
            return list(default)
        return value

    def int_range(self, data: dict, key: str, default: int, lo: int, hi: int, ctx: str) -> int:
        value = self.get(data, key, int, default, ctx)
        if not lo <= value <= hi:
            self.problems.append(f"{ctx}.{key}: must be between {lo} and {hi}, got {value}")
            return default
        return value

    def float_range(self, data: dict, key: str, default: float, lo: float, hi: float, ctx: str) -> float:
        value = float(self.get(data, key, (int, float), default, ctx))
        if not lo <= value <= hi:
            self.problems.append(f"{ctx}.{key}: must be between {lo} and {hi}, got {value}")
            return default
        return value


def _tname(typ: type | tuple) -> str:
    if isinstance(typ, tuple):
        return " or ".join(t.__name__ for t in typ)
    return typ.__name__


def _safe_rel_glob(pattern: str) -> bool:
    p = pattern.replace("\\", "/")
    return not (p.startswith("/") or re.match(r"^[A-Za-z]:", p) or ".." in PurePosixPath(p).parts)


def _parse_components(r: _Reader, data: Any) -> ComponentsConfig:
    ctx = "components"
    d = r.mapping(data, ctx, {"include", "exclude", "auto", "explicit", "leftover"})
    cfg = ComponentsConfig(
        include=r.str_list(d, "include", ["**"], ctx),
        exclude=DEFAULT_EXCLUDES + r.str_list(d, "exclude", [], ctx),
    )
    if "leftover" in d:
        leftover = d["leftover"]
        if leftover is not None and not isinstance(leftover, str):
            r.problems.append(f"{ctx}.leftover: expected a string or null")
        else:
            cfg.leftover = leftover
    for pat in cfg.include + cfg.exclude:
        if not _safe_rel_glob(pat):
            r.problems.append(f"{ctx}: glob '{pat}' must be relative to the repo root without '..'")

    auto = d.get("auto") or []
    if not isinstance(auto, list):
        r.problems.append(f"{ctx}.auto: expected a list")
        auto = []
    for i, item in enumerate(auto):
        ictx = f"{ctx}.auto[{i}]"
        a = r.mapping(item, ictx, {"root", "depth"})
        root = r.get(a, "root", str, "", ictx).strip("/").replace("\\", "/")
        if not root and "root" not in a:
            r.problems.append(f"{ictx}.root: required")
        if root and not _safe_rel_glob(root):
            r.problems.append(f"{ictx}.root: must be a relative path without '..'")
        cfg.auto.append(AutoSplit(root=root, depth=r.int_range(a, "depth", 1, 1, 4, ictx)))

    explicit = d.get("explicit") or []
    if not isinstance(explicit, list):
        r.problems.append(f"{ctx}.explicit: expected a list")
        explicit = []
    seen: set[str] = set()
    for i, item in enumerate(explicit):
        ictx = f"{ctx}.explicit[{i}]"
        e = r.mapping(item, ictx, {"name", "paths", "priority", "description"})
        name = r.get(e, "name", str, "", ictx)
        if not name:
            r.problems.append(f"{ictx}.name: required")
        elif name in seen:
            r.problems.append(f"{ictx}.name: duplicate component name '{name}'")
        seen.add(name)
        paths = r.str_list(e, "paths", [], ictx)
        if not paths:
            r.problems.append(f"{ictx}.paths: at least one glob is required")
        for pat in paths:
            if not _safe_rel_glob(pat):
                r.problems.append(f"{ictx}.paths: glob '{pat}' must be relative without '..'")
        cfg.explicit.append(
            ExplicitComponent(
                name=name,
                paths=paths,
                priority=r.int_range(e, "priority", 0, -100, 100, ictx),
                description=r.get(e, "description", str, "", ictx),
            )
        )
    return cfg


def _parse_scan(r: _Reader, data: Any) -> ScanConfig:
    ctx = "scan"
    d = r.mapping(
        data,
        ctx,
        {"concurrency", "model", "effort", "max_turns", "max_budget_usd", "timeout_minutes", "memory", "cpus", "pids_limit", "max_requests"},
    )
    s = ScanConfig()
    s.concurrency = r.int_range(d, "concurrency", s.concurrency, 1, 16, ctx)
    s.model = r.get(d, "model", str, s.model, ctx)
    s.effort = r.get(d, "effort", str, s.effort, ctx)
    if s.effort not in EFFORTS:
        r.problems.append(f"{ctx}.effort: must be one of {', '.join(EFFORTS)}")
    s.max_turns = r.int_range(d, "max_turns", s.max_turns, 1, 1000, ctx)
    s.max_budget_usd = r.float_range(d, "max_budget_usd", s.max_budget_usd, 0.01, 1000.0, ctx)
    s.timeout_minutes = r.int_range(d, "timeout_minutes", s.timeout_minutes, 1, 24 * 60, ctx)
    s.memory = r.get(d, "memory", str, s.memory, ctx)
    if not MEMORY_RE.match(s.memory):
        r.problems.append(f"{ctx}.memory: use a Docker size such as 4g or 512m")
    s.cpus = r.float_range(d, "cpus", s.cpus, 0.25, 64.0, ctx)
    s.pids_limit = r.int_range(d, "pids_limit", s.pids_limit, 64, 100000, ctx)
    s.max_requests = r.int_range(d, "max_requests", s.max_requests, 1, 1000000, ctx)
    return s


def _parse_verification(r: _Reader, data: Any) -> VerificationConfig:
    ctx = "verification"
    d = r.mapping(data, ctx, {"concurrency", "timeout_seconds", "require_patch_differential", "memory", "cpus"})
    v = VerificationConfig()
    v.concurrency = r.int_range(d, "concurrency", v.concurrency, 1, 16, ctx)
    v.timeout_seconds = r.int_range(d, "timeout_seconds", v.timeout_seconds, 10, 6 * 3600, ctx)
    v.require_patch_differential = r.get(d, "require_patch_differential", bool, v.require_patch_differential, ctx)
    v.memory = r.get(d, "memory", str, v.memory, ctx)
    if not MEMORY_RE.match(v.memory):
        r.problems.append(f"{ctx}.memory: use a Docker size such as 4g or 512m")
    v.cpus = r.float_range(d, "cpus", v.cpus, 0.25, 64.0, ctx)
    return v


def _parse_seeds(r: _Reader, data: Any, target_dir: Path) -> list[SeedSpec]:
    if data is None:
        return []
    if not isinstance(data, list):
        r.problems.append("seeds: expected a list")
        return []
    out = []
    for i, item in enumerate(data):
        ictx = f"seeds[{i}]"
        d = r.mapping(item, ictx, {"tool", "path"})
        tool = r.get(d, "tool", str, "", ictx)
        path = r.get(d, "path", str, "", ictx)
        if tool not in SEED_TOOLS:
            r.problems.append(f"{ictx}.tool: must be one of {', '.join(SEED_TOOLS)}")
            continue
        if not path:
            r.problems.append(f"{ictx}.path: required")
            continue
        p = Path(path)
        out.append(SeedSpec(tool=tool, path=p if p.is_absolute() else (target_dir / p)))
    return out


def parse_repo_spec(spec: str, target_dir: Path) -> tuple[str, str | None]:
    """Split ``repo[#branch]``; resolve local paths against the target dir."""
    repo, _, branch = spec.partition("#")
    branch = branch or None
    if _URL_RE.match(repo):
        return repo, branch
    if "://" in repo or repo.startswith("ext::") or "::" in repo:
        raise ConfigError([f"repo: unsupported git URL '{repo}' (use https://, ssh:// or git@host:path)"])
    p = Path(repo).expanduser()
    if not p.is_absolute():
        p = (target_dir / p).resolve()
    return str(p), branch


def load_project(target_dir: Path | str, repo_override: str | None = None) -> ProjectConfig:
    target_dir = Path(target_dir).resolve()
    cfg_file = target_dir / "project.yaml"
    if not cfg_file.is_file():
        raise ConfigError([f"{cfg_file} not found"])
    try:
        raw = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError([f"project.yaml is not valid YAML: {exc}"]) from exc

    problems: list[str] = []
    r = _Reader(problems)
    top = r.mapping(
        raw,
        "project.yaml",
        {
            "name", "repo", "dockerfile", "workdir", "threat_model", "known_issues",
            "diff_base", "components", "scan", "verification", "seeds", "gateway_image",
        },
    )

    name = r.get(top, "name", str, "", "project")
    if not NAME_RE.match(name or ""):
        problems.append("name: required; lowercase letters, digits, '-' or '_' (max 40 chars)")

    repo_spec = repo_override or r.get(top, "repo", str, "", "project")
    repo, branch = "", None
    if not repo_spec:
        problems.append("repo: required (local path or git URL), or pass --repo")
    else:
        try:
            repo, branch = parse_repo_spec(repo_spec, target_dir)
        except ConfigError as exc:
            problems.extend(exc.problems)

    dockerfile = target_dir / r.get(top, "dockerfile", str, "Dockerfile", "project")
    if not dockerfile.is_file():
        problems.append(f"dockerfile: {dockerfile} not found")

    workdir = r.get(top, "workdir", str, "/src", "project")
    if not workdir.startswith("/") or ".." in PurePosixPath(workdir).parts:
        problems.append("workdir: must be an absolute POSIX path inside the image, e.g. /src")

    tm_rel = r.get(top, "threat_model", str, "threat_model.md", "project")
    threat_model: Path | None = target_dir / tm_rel
    threat_text = ""
    if threat_model.is_file():
        threat_text = threat_model.read_text(encoding="utf-8")
    elif "threat_model" in top:
        problems.append(f"threat_model: {threat_model} not found")
    else:
        threat_model = None

    known = r.get(top, "known_issues", str, None, "project")
    if known is not None and not _safe_rel_glob(known):
        problems.append("known_issues: must be a path relative to the target repo root")

    cfg = ProjectConfig(
        name=name,
        target_dir=target_dir,
        repo=repo,
        branch=branch,
        dockerfile=dockerfile,
        workdir=workdir,
        threat_model=threat_model,
        threat_model_text=threat_text,
        known_issues=known,
        diff_base=r.get(top, "diff_base", str, "HEAD~1", "project"),
        components=_parse_components(r, top.get("components")),
        scan=_parse_scan(r, top.get("scan")),
        verification=_parse_verification(r, top.get("verification")),
        seeds=_parse_seeds(r, top.get("seeds"), target_dir),
        gateway_image=r.get(top, "gateway_image", str, "python:3.13-slim", "project"),
    )
    if problems:
        raise ConfigError(problems)
    return cfg
