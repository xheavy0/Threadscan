"""Live run status, written atomically to ``<run>/status.json`` and read by the dashboard."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from vulnscan.redact import redact_obj


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(redact_obj(obj), indent=1, default=str), encoding="utf-8")
    os.replace(tmp, path)


class StatusTracker:
    def __init__(self, run_dir: Path, run_id: str, project: str, mode: str, base: str | None, dry_run: bool):
        self.path = run_dir / "status.json"
        self.lock = threading.Lock()
        now = time.time()
        self.data = {
            "run_id": run_id,
            "project": project,
            "mode": mode,
            "base": base,
            "dry_run": dry_run,
            "started": now,
            "updated": now,
            "finished": None,
            "phase": "planning",
            "message": "",
            "components": [],
            "verification": [],
            "counts": {"components": 0, "candidates": 0, "verified": 0, "dropped": 0, "by_reason": {}},
            "cost": {"usd": None, "input_tokens": 0, "output_tokens": 0},
        }
        self.flush()

    def flush(self) -> None:
        self.data["updated"] = time.time()
        write_json(self.path, self.data)

    def phase(self, phase: str, message: str = "") -> None:
        with self.lock:
            self.data["phase"] = phase
            self.data["message"] = message
            if phase in ("done", "failed"):
                self.data["finished"] = time.time()
            self.flush()

    def set_components(self, comps: list[dict]) -> None:
        with self.lock:
            self.data["components"] = [{**c, "state": "queued", "candidates": 0} for c in comps]
            self.data["counts"]["components"] = len(comps)
            self.flush()

    def component(self, name: str, **fields) -> None:
        with self.lock:
            for c in self.data["components"]:
                if c["name"] == name:
                    c.update(fields)
            self.flush()

    def set_verification(self, items: list[dict]) -> None:
        with self.lock:
            self.data["verification"] = items
            self.flush()

    def verification(self, cand_id: str, **fields) -> None:
        with self.lock:
            for v in self.data["verification"]:
                if v["id"] == cand_id:
                    v.update(fields)
            self.flush()

    def counts(self, **fields) -> None:
        with self.lock:
            self.data["counts"].update(fields)
            self.flush()

    def cost(self, usd: float | None, input_tokens: int, output_tokens: int) -> None:
        with self.lock:
            self.data["cost"] = {"usd": usd, "input_tokens": input_tokens, "output_tokens": output_tokens}
            self.flush()
