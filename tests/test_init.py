"""threadscan init: stack detection and scaffold output that the rest of Threadscan accepts."""

from pathlib import Path

import pytest

from threadscan.components import split_components
from threadscan.config import load_project
from threadscan.init import detect, scaffold
from threadscan.repo import list_files


def make(root: Path, files: dict) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def snapshot(repo: Path) -> dict:
    return {p.relative_to(repo).as_posix(): p.read_bytes() for p in repo.rglob("*") if p.is_file()}


def test_java_backend_plus_node_frontend(tmp_path):
    repo = make(tmp_path / "Shop-App", {
        "backend/pom.xml": "<project><properties><java.version>17</java.version></properties></project>",
        "backend/src/main/java/com/acme/shop/api/OrderController.java": "class A {}",
        "backend/src/main/java/com/acme/shop/auth/Login.java": "class B {}",
        "package.json": "{}", "pnpm-lock.yaml": "", "src/components/Cart.tsx": "x", "src/lib/api.ts": "x",
        "node_modules/x/package.json": "{}",  # ignored
    })
    det = detect(repo)
    assert {(s.kind, s.dir) for s in det.stacks} == {("maven", "backend"), ("node", "")}
    assert ("backend/src/main/java/com/acme/shop", 1) in det.roots and ("src", 1) in det.roots
    assert det.java_version == "17" and det.name == "shop-app"
    before = snapshot(repo)
    out, _ = scaffold(repo, tmp_path / "targets")
    assert snapshot(repo) == before  # the scanned repo is never written
    cfg = load_project(out)
    assert cfg.name == "shop-app" and Path(cfg.repo) == repo.resolve() and cfg.scan.auth == "subscription"
    df = (out / "Dockerfile").read_text()
    assert "FROM maven:3.9-eclipse-temurin-17" in df and "COPY --from=node:22-bookworm-slim" in df
    assert "cd /src/backend && mvn -B -q dependency:go-offline" in df and "pnpm install --frozen-lockfile" in df
    assert ".git" in (out / "Dockerfile.dockerignore").read_text()
    assert "TODO" in (out / "threat_model.md").read_text()
    names = {c.name for c in split_components(list_files(repo), cfg.components)}
    assert {"backend/src/main/java/com/acme/shop/api", "backend/src/main/java/com/acme/shop/auth", "src/components", "src/lib"} <= names


def test_python_go_rust_layouts(tmp_path):
    py = detect(make(tmp_path / "py", {"pyproject.toml": "", "svc/__init__.py": "", "svc/app.py": "", "tests/test_a.py": ""}))
    assert [s.kind for s in py.stacks] == ["python"] and ("svc", 1) in py.roots
    go = detect(make(tmp_path / "go", {"go.mod": "module x", "cmd/main.go": "", "internal/a/a.go": ""}))
    assert [s.kind for s in go.stacks] == ["go"] and go.roots == [("", 1)]
    rs = detect(make(tmp_path / "rs", {"Cargo.toml": "", "src/main.rs": ""}))
    assert [s.kind for s in rs.stacks] == ["rust"] and rs.roots == [("src", 1)]


def test_go_repo_root_component_roundtrips(tmp_path):
    repo = make(tmp_path / "svc", {"go.mod": "module x", "cmd/main.go": "", "internal/auth/a.go": ""})
    out, _ = scaffold(repo, tmp_path / "targets")
    cfg = load_project(out)
    names = {c.name for c in split_components(list_files(repo), cfg.components)}
    assert {"cmd", "internal"} <= names
    assert "FROM golang:" in (out / "Dockerfile").read_text()


def test_unknown_stack_and_no_overwrite(tmp_path):
    repo = make(tmp_path / "plain", {"README.txt": "hi"})
    out, det = scaffold(repo, tmp_path / "targets")
    assert det.stacks == [] and "TODO: no known build manifest" in (out / "Dockerfile").read_text()
    load_project(out)
    with pytest.raises(RuntimeError, match="already exists"):
        scaffold(repo, tmp_path / "targets")
    out2, _ = scaffold(repo, tmp_path / "targets", name="Other Name!")
    assert out2.name == "other-name"
