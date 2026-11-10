"""``threadscan init <repo>``: scaffold ``targets/<name>/`` for a new target.

Detects the stacks in the repository (Maven, Gradle, npm/pnpm/yarn, Python, Go, Rust, .NET)
from their manifests and writes four files: ``project.yaml`` (component roots from the
detected source layouts), a ``Dockerfile`` that fetches dependencies while the network is on
and checks the build works offline, a ``Dockerfile.dockerignore``, and a ``threat_model.md``
skeleton. Lines that need a human decision are marked ``TODO``. It never overwrites an
existing target and never writes to the scanned repository.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from threadscan.repo import list_files

SKIP_PARTS = {"node_modules", "vendor", "target", "build", "dist", ".git", "testdata", "fixtures", "third_party", "examples", "e2e"}
MANIFESTS = [
    ("maven", re.compile(r"(^|/)pom\.xml$")),
    ("gradle", re.compile(r"(^|/)build\.gradle(\.kts)?$")),
    ("dotnet", re.compile(r"\.(csproj|fsproj)$")),
    ("go", re.compile(r"(^|/)go\.mod$")),
    ("rust", re.compile(r"(^|/)Cargo\.toml$")),
    ("python", re.compile(r"(^|/)(pyproject\.toml|requirements\.txt|setup\.py)$")),
    ("node", re.compile(r"(^|/)package\.json$")),
]
PRIMARY_ORDER = ["maven", "gradle", "dotnet", "go", "rust", "python", "node"]


@dataclass
class Stack:
    kind: str
    dir: str  # manifest directory, relative to the repo root ("" = root)
    extra: dict = field(default_factory=dict)


@dataclass
class Detection:
    name: str
    stacks: list[Stack]
    roots: list[tuple[str, int]]  # (root, depth) for components.auto
    excludes: list[str]
    java_version: str = "21"


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-_")[:40]
    return s or "target"


def _java_version(text: str) -> str | None:
    for pat in (r"<maven\.compiler\.release>(\d+)<", r"<java\.version>(\d+)<", r"<release>(\d+)</release>", r"languageVersion\.set\(JavaLanguageVersion\.of\((\d+)\)\)", r"JavaVersion\.VERSION_(\d+)"):
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


def _deepest_single_child(base: Path) -> Path:
    """com/acme/app when every level has exactly one sub-directory (a Java package root)."""
    cur = base
    while True:
        subs = [p for p in cur.iterdir() if p.is_dir()] if cur.is_dir() else []
        files = [p for p in cur.iterdir() if p.is_file()] if cur.is_dir() else []
        if len(subs) == 1 and not files:
            cur = subs[0]
        else:
            return cur


def detect(repo: Path) -> Detection:
    files = list_files(repo)
    stacks: list[Stack] = []
    seen: set[tuple[str, str]] = set()
    for f in files:
        parts = f.split("/")
        if len(parts) > 4 or SKIP_PARTS & set(parts[:-1]):
            continue
        for kind, rx in MANIFESTS:
            if rx.search(f):
                d = "/".join(parts[:-1])
                if (kind, d) not in seen:
                    seen.add((kind, d))
                    stacks.append(Stack(kind, d))
                break
    fileset = set(files)
    java_version = None
    roots: list[tuple[str, int]] = []
    for s in stacks:
        base = repo / s.dir if s.dir else repo
        prefix = f"{s.dir}/" if s.dir else ""
        if s.kind in ("maven", "gradle"):
            for manifest in ("pom.xml", "build.gradle", "build.gradle.kts"):
                p = base / manifest
                if p.is_file():
                    java_version = java_version or _java_version(p.read_text(encoding="utf-8", errors="replace"))
            for lang in ("java", "kotlin"):
                src = base / "src" / "main" / lang
                if src.is_dir():
                    pkg = _deepest_single_child(src)
                    roots.append((pkg.relative_to(repo).as_posix(), 1))
        elif s.kind == "node":
            s.extra["lock"] = next((lk for lk in ("pnpm-lock.yaml", "yarn.lock", "package-lock.json") if prefix + lk in fileset), None)
            if (base / "src").is_dir():
                roots.append((prefix + "src", 1))
        elif s.kind == "python":
            for cand in [base / "src"] + [p for p in base.iterdir() if p.is_dir()]:
                if cand.is_dir() and cand.name not in SKIP_PARTS and not cand.name.startswith((".", "test")):
                    if cand.name == "src" or (cand / "__init__.py").is_file():
                        roots.append((cand.relative_to(repo).as_posix(), 1))
        elif s.kind in ("go", "dotnet"):
            roots.append((s.dir, 1))
        elif s.kind == "rust" and (base / "src").is_dir():
            roots.append((prefix + "src", 1))
    roots = list(dict.fromkeys(roots))
    excludes = ["**/test/**", "**/tests/**", "**/__tests__/**", "**/*_test.go", "**/*.test.ts", "**/*.test.tsx", "**/*.spec.ts", "**/*.md", "docs/**", "e2e/**"]
    return Detection(_slug(repo.resolve().name), stacks, roots, excludes, java_version or "21")


def _primary(stacks: list[Stack]) -> Stack | None:
    for kind in PRIMARY_ORDER:
        for s in stacks:
            if s.kind == kind:
                return s
    return None


def dockerfile(det: Detection) -> str:
    kinds = {s.kind for s in det.stacks}
    primary = _primary(det.stacks)
    jv = det.java_version
    base = {
        "maven": f"maven:3.9-eclipse-temurin-{jv}", "gradle": f"gradle:8-jdk{jv}", "dotnet": "mcr.microsoft.com/dotnet/sdk:8.0",
        "go": "golang:1.23-bookworm", "rust": "rust:1-bookworm", "python": "python:3.12-slim", "node": "node:22-bookworm-slim",
    }.get(primary.kind if primary else "", "debian:bookworm-slim")
    L = [
        "# syntax=docker/dockerfile:1",
        "# Threadscan scan image (generated by `threadscan init`; review every TODO).",
        "# Built with the target repository as context and the network on: fetch everything here.",
        "# Afterwards the agent and the verification gate run with NO network, so builds and tests",
        "# must work offline. Keep the source at /src.",
        f"FROM {base}",
        "",
    ]
    if "node" in kinds and primary and primary.kind != "node":
        L += ["# Node for the JavaScript parts of the repo.",
              "COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node",
              "COPY --from=node:22-bookworm-slim /usr/local/lib/node_modules /usr/local/lib/node_modules",
              "RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx", ""]
    apt = ["git", "curl", "ca-certificates", "patch"]
    if "python" in kinds and primary and primary.kind != "python":
        apt += ["python3", "python3-pip", "python3-venv"]
    L += ["RUN apt-get update \\",
          f"    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {' '.join(apt)} \\",
          "    && rm -rf /var/lib/apt/lists/*",
          "RUN useradd -m -u 10101 -s /bin/bash scan && mkdir -p /src && chown scan:scan /src",
          "ENV HOME=/home/scan" + (' MAVEN_CONFIG=""' if "maven" in kinds else ""),
          "USER scan",
          "WORKDIR /src",
          "COPY --chown=scan:scan . /src",
          ""]
    for s in det.stacks:
        d = f"cd /src/{s.dir} && " if s.dir else ""
        where = s.dir or "root"
        if s.kind == "maven":
            L += [f"# Maven ({where}): dependencies, compiled tests, and Surefire's provider for offline test runs.",
                  f"RUN {d}mvn -B -q dependency:go-offline \\",
                  "    && mvn -B -q test-compile \\",
                  "    && mvn -B -q test -Dtest=NoSuchTestThreadscan -Dsurefire.failIfNoSpecifiedTests=false",
                  f"RUN {d}mvn -B -q -o compile", ""]
        elif s.kind == "gradle":
            L += [f"# Gradle ({where}). TODO: use ./gradlew if the repo has a wrapper.",
                  f"RUN {d}gradle --no-daemon -q testClasses",
                  f"RUN {d}gradle --no-daemon -q --offline testClasses", ""]
        elif s.kind == "node":
            cmd = {"pnpm-lock.yaml": "corepack enable --install-directory ~/bin && ~/bin/pnpm install --frozen-lockfile",
                   "yarn.lock": "corepack enable --install-directory ~/bin && ~/bin/yarn install --frozen-lockfile",
                   "package-lock.json": "npm ci --no-audit --no-fund"}.get(s.extra.get("lock") or "", "npm install --no-audit --no-fund  # TODO: commit a lockfile")
            L += [f"# Node ({where})", f"RUN {d}{cmd}", ""]
        elif s.kind == "python":
            L += [f"# Python ({where}). TODO: add test extras (e.g. .[test]) so tests run offline.",
                  f"RUN {d}python3 -m venv /home/scan/venv && /home/scan/venv/bin/pip install -q --upgrade pip \\",
                  "    && if [ -f requirements.txt ]; then /home/scan/venv/bin/pip install -q -r requirements.txt; fi \\",
                  "    && if [ -f pyproject.toml ] || [ -f setup.py ]; then /home/scan/venv/bin/pip install -q -e .; fi \\",
                  "    && /home/scan/venv/bin/pip install -q pytest",
                  'ENV PATH="/home/scan/venv/bin:${PATH}"', ""]
        elif s.kind == "go":
            L += [f"# Go ({where})", f"RUN {d}go mod download && go build ./... && go test -count=1 -run NoSuchTestThreadscan ./...", ""]
        elif s.kind == "rust":
            L += [f"# Rust ({where})", f"RUN {d}cargo fetch && cargo build --tests --offline", ""]
        elif s.kind == "dotnet":
            L += [f"# .NET ({where})", f"RUN {d}dotnet restore && dotnet build --no-restore", ""]
    if not det.stacks:
        L += ["# TODO: no known build manifest was found; install the toolchain and build here.", ""]
    return "\n".join(L).rstrip() + "\n"


DOCKERIGNORE = """# Threadscan uses this instead of the repo's own .dockerignore (BuildKit, named after the Dockerfile).
.git
node_modules
**/node_modules
target
**/target
dist
build
.env
.env.*
*.pem
*.key
*.p12
*.jks
.claude
CLAUDE.md
"""


def project_yaml(det: Detection, repo_rel: str) -> str:
    roots = "\n".join(f'    - root: "{r}"\n      depth: {d}' for r, d in det.roots) or "    # TODO: no source layout detected; add auto roots or explicit components"
    excludes = "\n".join(f'    - "{e}"' for e in det.excludes)
    stacks = ", ".join(f"{s.kind} ({s.dir or 'root'})" for s in det.stacks) or "none detected"
    return f"""# Generated by `threadscan init`. Detected: {stacks}.
# Review the TODOs, then: threadscan validate / components / doctor --live.
name: {det.name}
repo: {repo_rel}
dockerfile: Dockerfile
workdir: /src
threat_model: threat_model.md
# known_issues: docs/security/known-issues.md   # TODO: a file in the repo listing accepted issues
diff_base: HEAD~1

components:
  exclude:
{excludes}
  # TODO: add explicit components for security-critical areas (auth, access control, uploads,
  # anything that fetches URLs), with a priority, so --max-components picks them first.
  explicit: []
  auto:
{roots}
  leftover: misc

scan:
  auth: subscription          # or api_key
  effort: high
  max_turns: 80
  max_budget_usd: 5.0
  timeout_minutes: 45
  memory: 6g
  cpus: 2

verification:
  timeout_seconds: 900
  require_patch_differential: true
"""


def threat_model(det: Detection) -> str:
    stacks = ", ".join(f"{s.kind} in `{s.dir or '/'}`" for s in det.stacks) or "TODO"
    return f"""# {det.name}: threat model

Generated by `threadscan init`. Replace every TODO: the agents rate and scope findings by
this file, so a precise one gives better results than a long one.

## What it is

TODO: one paragraph. Who uses it, how it is deployed, single- or multi-tenant.
Detected stacks: {stacks}.

## Working in the scan image

- Source at `/src`. There is no network: builds and tests must run offline.
- TODO: how to run the tests (one test, not the whole suite) and how to start the app.

## Untrusted input

TODO: where input enters (HTTP routes, uploads, imports, webhooks, messages, CLI args, files
it parses, URLs it fetches) and who can send it (anonymous, signed-in user, admin, another service).

## What must hold

TODO: the invariants a finding breaks: authentication, authorisation and tenant isolation,
secrets never leaving, outbound requests limited, uploads contained.

## Out of scope and accepted risks

TODO: what not to report (test code, demo accounts, known and accepted issues).

## Severity

- **Critical**: authentication bypass, cross-tenant access, secret disclosure, remote code execution.
- **High**: privilege escalation, IDOR on sensitive data, SSRF to internal addresses, stored XSS in another user's session.
- **Medium**: needs unusual conditions or a non-default configuration; single-request resource exhaustion.
- **Low**: hardening and information disclosure of little value.

TODO: adjust these to how you rate severity.
"""


def scaffold(repo: Path, targets_dir: Path, name: str | None = None) -> tuple[Path, Detection]:
    repo = repo.resolve()
    if not repo.is_dir():
        raise RuntimeError(f"{repo} is not a directory")
    det = detect(repo)
    if name:
        det.name = _slug(name)
    out = (targets_dir / det.name).resolve()
    if out.exists():
        raise RuntimeError(f"{out} already exists; choose another --name or remove it first")
    out.mkdir(parents=True)
    try:
        rel = os.path.relpath(repo, out).replace("\\", "/")
    except ValueError:  # different drive on Windows
        rel = repo.as_posix()
    (out / "project.yaml").write_text(project_yaml(det, rel), encoding="utf-8", newline="\n")
    (out / "Dockerfile").write_text(dockerfile(det), encoding="utf-8", newline="\n")
    (out / "Dockerfile.dockerignore").write_text(DOCKERIGNORE, encoding="utf-8", newline="\n")
    (out / "threat_model.md").write_text(threat_model(det), encoding="utf-8", newline="\n")
    return out, det
