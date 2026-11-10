"""Triage state per issue (status, assignee, note), kept in ``<runs>/triage.json``.

Keyed by finding id, so it follows an issue across runs. This file is the only thing the
dashboard ever writes. It is local, gitignored with the rest of ``runs/``, and validated
strictly: unknown statuses, oversized fields and malformed ids are refused.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path

STATUSES = ("open", "in_progress", "resolved", "risk_accepted", "false_positive")
ID_RE = re.compile(r"^TS-[0-9a-f]{10}$")
MAX_ASSIGNEE = 120
MAX_NOTE = 4000
MAX_HISTORY = 30


class TriageError(ValueError):
    pass


class TriageStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()

    def load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def update(self, issue_id: str, body: object, by: str | None = None, reason: str | None = None) -> dict:
        """Apply a change. ``by``/``reason`` mark automatic changes (e.g. ``threadscan recheck``)
        so the Activity log tells them apart from a person's."""
        if not ID_RE.match(issue_id or ""):
            raise TriageError("malformed issue id")
        if not isinstance(body, dict) or set(body) - {"status", "assignee", "note"}:
            raise TriageError("body must be an object with status, assignee and/or note")
        status = body.get("status")
        assignee = body.get("assignee")
        note = body.get("note")
        if status is not None and status not in STATUSES:
            raise TriageError(f"status must be one of {', '.join(STATUSES)}")
        for name, val, cap in (("assignee", assignee, MAX_ASSIGNEE), ("note", note, MAX_NOTE)):
            if val is not None and (not isinstance(val, str) or len(val) > cap):
                raise TriageError(f"{name} must be a string of at most {cap} characters")
        with self.lock:
            data = self.load()
            entry = data.get(issue_id) or {"status": "open", "assignee": "", "note": "", "history": []}
            changes = []
            for key, val in (("status", status), ("assignee", assignee), ("note", note)):
                if val is not None and val != entry.get(key):
                    changes.append({"field": key, "from": entry.get(key), "to": val if key != "note" else "(edited)"})
                    entry[key] = val.strip() if isinstance(val, str) and key != "status" else val
            if changes:
                now = time.time()
                entry["updated"] = now
                event = {"at": now, "changes": changes}
                if by:
                    event["by"] = by[:80]
                if reason:
                    event["reason"] = reason[:500]
                entry["history"] = (entry.get("history") or []) + [event]
                entry["history"] = entry["history"][-MAX_HISTORY:]
                data[issue_id] = entry
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
                os.replace(tmp, self.path)
            return entry
