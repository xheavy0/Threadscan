"""``threadscan prune``: delete old run directories, keeping what later runs depend on.

Per target it keeps the newest ``keep`` finished runs (done or failed, dry runs included)
and always the newest completed non-dry run, which the next scan compares against. Runs that
are still going are never touched. Doctor reports and re-checks keep their newest ``keep``.
``triage.json`` and ``.watch/`` are never touched. Nothing is deleted without ``yes=True``;
without it the plan is only returned.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Item:
    path: Path
    kind: str  # run | doctor | recheck
    project: str
    started: float
    reason: str = ""

    def size(self) -> int:
        return sum(p.stat().st_size for p in self.path.rglob("*") if p.is_file())


def _load(p: Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def plan_prune(runs_dir: Path, keep: int = 10, project: str | None = None) -> tuple[list[Item], list[Item]]:
    """(delete, keep) lists. Only direct children of runs_dir (and of runs_dir/rechecks) are considered."""
    if keep < 1:
        raise ValueError("keep must be at least 1")
    runs_dir = runs_dir.resolve()
    delete: list[Item] = []
    kept: list[Item] = []
    by_project: dict[str, list[tuple[Item, dict]]] = {}
    doctors: list[Item] = []
    for d in sorted(runs_dir.iterdir()) if runs_dir.is_dir() else []:
        if not d.is_dir() or d.is_symlink() or d.name.startswith("."):
            continue
        if d.name.startswith("doctor-"):
            doctors.append(Item(d, "doctor", "-", d.stat().st_mtime))
            continue
        st = _load(d / "status.json")
        if not st:
            continue
        it = Item(d, "run", st.get("project") or "?", st.get("started") or d.stat().st_mtime)
        by_project.setdefault(it.project, []).append((it, st))
    for proj, items in by_project.items():
        if project and proj != project:
            continue
        items.sort(key=lambda x: x[0].started, reverse=True)
        baseline = next((it for it, st in items if st.get("phase") == "done" and not st.get("dry_run")), None)
        finished_seen = 0
        for it, st in items:
            if st.get("phase") not in ("done", "failed"):
                it.reason = "still running"
                kept.append(it)
                continue
            finished_seen += 1
            if finished_seen <= keep:
                it.reason = f"among the newest {keep}"
                kept.append(it)
            elif it is baseline:
                it.reason = "newest completed scan (comparison baseline)"
                kept.append(it)
            else:
                delete.append(it)
    if not project:
        doctors.sort(key=lambda i: i.started, reverse=True)
        kept += doctors[:keep]
        delete += doctors[keep:]
        rechecks = sorted((Item(d, "recheck", (_load(d / "recheck.json").get("project") or "?"), d.stat().st_mtime)
                           for d in (runs_dir / "rechecks").iterdir() if d.is_dir() and not d.is_symlink())
                          if (runs_dir / "rechecks").is_dir() else [], key=lambda i: i.started, reverse=True)
        kept += rechecks[:keep]
        delete += rechecks[keep:]
    return delete, kept


def apply_prune(runs_dir: Path, delete: list[Item]) -> int:
    runs_dir = runs_dir.resolve()
    allowed_parents = {runs_dir, (runs_dir / "rechecks").resolve()}
    removed = 0
    for it in delete:
        p = it.path.resolve()
        if p.parent not in allowed_parents or p.is_symlink() or not p.is_dir():
            continue  # never outside the runs directory
        shutil.rmtree(p)
        removed += 1
    return removed
