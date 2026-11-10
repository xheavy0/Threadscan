import subprocess
import textwrap
from pathlib import Path

import pytest


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-C", str(repo), *args],
        check=True, capture_output=True, text=True,
    ).stdout


@pytest.fixture
def target_dir(tmp_path: Path):
    """A minimal valid target config dir; returns a writer for project.yaml."""
    d = tmp_path / "target"
    d.mkdir()
    (d / "Dockerfile").write_text("FROM scratch\n")
    (d / "threat_model.md").write_text("# TM\nSeverity: critical for auth bypass.\n")

    def write(yaml_text: str) -> Path:
        (d / "project.yaml").write_text(textwrap.dedent(yaml_text))
        return d

    return write


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """A small git repo with two commits; the second touches auth and adds a file."""
    r = tmp_path / "repo"
    files = {
        "backend/src/main/java/com/x/auth/Login.java": "class Login {}\n",
        "backend/src/main/java/com/x/auth/Session.java": "class Session {}\n",
        "backend/src/main/java/com/x/storage/Store.java": "class Store {}\n",
        "backend/src/main/java/com/x/App.java": "class App {}\n",
        "src/components/vendors/Portal.tsx": "export {}\n",
        "src/rbac.ts": "export {}\n",
        "deploy/nginx.conf": "server {}\n",
        "README.md": "# r\n",
        "node_modules/x/index.js": "ignored by gitignore\n",
        "package.json": "{}\n",
    }
    for rel, content in files.items():
        p = r / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    (r / ".gitignore").write_text("node_modules/\n")
    git(r, "init", "-q", "-b", "main")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "one")
    (r / "backend/src/main/java/com/x/auth/Login.java").write_text("class Login { int changed; }\n")
    (r / "backend/src/main/java/com/x/auth/Mfa.java").write_text("class Mfa {}\n")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "two")
    return r
