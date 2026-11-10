"""Split a target repository into components, one agent each.

Assignment order for every file that survives include/exclude:
1. the first explicit component (in config order) with a matching glob;
2. otherwise the deepest ``auto`` root containing it, split ``depth`` directories
   below that root (``backend/src/main/java/com/aegis`` at depth 1 yields
   ``.../aegis/auth``, ``.../aegis/storage`` ...; files directly in the root form
   a component named after the root);
3. otherwise the ``leftover`` component, or nowhere if ``leftover`` is null.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from functools import lru_cache

from threadscan.config import ComponentsConfig


@lru_cache(maxsize=4096)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    p = pattern.replace("\\", "/")
    i, out = 0, []
    while i < len(p):
        if p.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif p.startswith("**", i):
            out.append(".*")
            i += 2
        elif p[i] == "*":
            out.append("[^/]*")
            i += 1
        elif p[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(p[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def glob_match(pattern: str, path: str) -> bool:
    """Root-anchored glob: ``*`` stays within a directory, ``**`` crosses them."""
    return bool(_glob_regex(pattern).match(path))


def matches_any(patterns: list[str], path: str) -> bool:
    return any(glob_match(p, path) for p in patterns)


def slugify(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[-48:].strip("-") or "component"
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:6]
    return f"{base}-{digest}"


@dataclass
class Component:
    name: str
    kind: str  # explicit | auto | leftover
    files: list[str] = field(default_factory=list)
    priority: int = 0
    description: str = ""
    changed_files: list[str] = field(default_factory=list)

    @property
    def slug(self) -> str:
        return slugify(self.name)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "slug": self.slug,
            "kind": self.kind,
            "priority": self.priority,
            "description": self.description,
            "file_count": len(self.files),
            "changed_files": self.changed_files,
        }


def filter_files(files: list[str], cfg: ComponentsConfig) -> list[str]:
    return [f for f in files if matches_any(cfg.include, f) and not matches_any(cfg.exclude, f)]


def _auto_name(path: str, roots: list) -> str | None:
    best = None
    for a in roots:
        prefix = a.root + "/" if a.root else ""
        if path.startswith(prefix) and (best is None or len(a.root) > len(best.root)):
            best = a
    if best is None:
        return None
    rest = path[len(best.root) + 1 :] if best.root else path
    parts = rest.split("/")
    if len(parts) <= 1:  # a file directly inside the root
        return best.root or "(root)"
    dirs = parts[: min(best.depth, len(parts) - 1)]
    return "/".join(([best.root] if best.root else []) + dirs)


def split_components(files: list[str], cfg: ComponentsConfig) -> list[Component]:
    by_name: dict[str, Component] = {}
    for e in cfg.explicit:
        by_name[e.name] = Component(name=e.name, kind="explicit", priority=e.priority, description=e.description)

    for f in filter_files(files, cfg):
        target = None
        for e in cfg.explicit:
            if matches_any(e.paths, f):
                target = by_name[e.name]
                break
        if target is None:
            name = _auto_name(f, cfg.auto)
            if name is not None:
                target = by_name.setdefault(name, Component(name=name, kind="auto"))
            elif cfg.leftover:
                target = by_name.setdefault(cfg.leftover, Component(name=cfg.leftover, kind="leftover", priority=-10))
        if target is not None:
            target.files.append(f)

    comps = [c for c in by_name.values() if c.files]
    comps.sort(key=lambda c: c.name)
    return comps


def select_components(
    components: list[Component],
    changed: list[str] | None,
    max_components: int | None = None,
    only: list[str] | None = None,
) -> list[Component]:
    """Pick what to scan. ``changed`` is None for a full scan.

    Order: higher priority first, then (diff mode) more changed files, then name.
    """
    selected = []
    changed_set = set(changed or [])
    for c in components:
        if only and c.name not in only and c.slug not in only:
            continue
        if changed is not None:
            c.changed_files = sorted(f for f in c.files if f in changed_set)
            if not c.changed_files:
                continue
        selected.append(c)
    selected.sort(key=lambda c: (-c.priority, -len(c.changed_files), c.name))
    if max_components is not None:
        selected = selected[:max_components]
    return selected
