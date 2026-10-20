#!/usr/bin/env python3
"""Diff two project snapshots (snapshot_graph.py) for the regression replay.

    compare_snapshots.py <baseline_dir> <current_dir> \
        [--volatile baseline/volatile.json] [--allow allowlist.json --phase C --project R4]

Every set in graph.json is compared as a set, plus the recon JSON's top-level
keys and its metadata keys and values (timestamps are already masked).

--volatile  {"sets": {"<set>": ["<regex>", ...]}, "metadata_keys": [...], "recon_keys": [...]}
            Differences between two identical runs (measured at baseline); ignored.
--allow     {"<phase>": {"<project>": [{"set": "<set>", "change": "added|removed",
            "match": "<regex>", "why": "..."}]}}
            Intended differences for one phase (the plan's allowlist). An allowed
            difference is reported but does not fail the run.

Exit 0 when every difference is volatile or allowed, 1 otherwise. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def _load(d: Path) -> dict:
    return json.loads((d / "graph.json").read_text())


def _recon_views(snap: dict) -> tuple[set[str], dict[str, object]]:
    keys: set[str] = set()
    meta: dict[str, object] = {}
    for fname, view in snap.get("recon_json", {}).items():
        # Per-run file names carry the project id, which differs between projects
        # but not between runs of one project; key on the suffix after the id.
        tag = re.sub(r"^recon_[a-z0-9]+", "recon_<pid>", fname)
        for k in view.get("top_level_keys", []):
            keys.add(f"{tag}:{k}")
        for k, v in (view.get("metadata") or {}).items():
            meta[f"{tag}:{k}"] = v
    return keys, meta


def _matches(value: str, patterns: list[str]) -> bool:
    return any(re.search(p, value) for p in patterns)


def compare(base: dict, cur: dict, volatile: dict, allowed: list[dict]) -> tuple[list, list]:
    """Return (unexpected, allowed) differences as (set, change, value[, why])."""
    unexpected, ok = [], []
    vol_sets = volatile.get("sets", {})

    def classify(set_name: str, change: str, value: str) -> None:
        if _matches(value, vol_sets.get(set_name, [])):
            return
        for rule in allowed:
            if rule["set"] == set_name and rule["change"] in (change, "any") and re.search(rule["match"], value):
                ok.append((set_name, change, value, rule.get("why", "")))
                return
        unexpected.append((set_name, change, value))

    names = sorted(set(base["sets"]) | set(cur["sets"]))
    for name in names:
        b, c = set(base["sets"].get(name, [])), set(cur["sets"].get(name, []))
        for v in sorted(c - b):
            classify(name, "added", v)
        for v in sorted(b - c):
            classify(name, "removed", v)

    bk, bm = _recon_views(base)
    ck, cm = _recon_views(cur)
    for v in sorted(ck - bk):
        if not _matches(v, volatile.get("recon_keys", [])):
            classify("recon_key", "added", v)
    for v in sorted(bk - ck):
        if not _matches(v, volatile.get("recon_keys", [])):
            classify("recon_key", "removed", v)
    for k in sorted(set(bm) | set(cm)):
        if _matches(k, volatile.get("metadata_keys", [])):
            continue
        if k not in cm:
            classify("recon_metadata", "removed", f"{k}={json.dumps(bm[k], sort_keys=True)}")
        elif k not in bm:
            classify("recon_metadata", "added", f"{k}={json.dumps(cm[k], sort_keys=True)}")
        elif bm[k] != cm[k]:
            classify("recon_metadata", "changed",
                     f"{k}: {json.dumps(bm[k], sort_keys=True)} -> {json.dumps(cm[k], sort_keys=True)}")
    return unexpected, ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("baseline", type=Path)
    ap.add_argument("current", type=Path)
    ap.add_argument("--volatile", type=Path)
    ap.add_argument("--allow", type=Path)
    ap.add_argument("--phase")
    ap.add_argument("--project")
    a = ap.parse_args()

    volatile = json.loads(a.volatile.read_text()) if a.volatile else {}
    allowed: list[dict] = []
    if a.allow:
        table = json.loads(a.allow.read_text())
        phase = table.get(a.phase or "", {})
        allowed = phase.get(a.project or "", []) + phase.get("all", [])

    unexpected, ok = compare(_load(a.baseline), _load(a.current), volatile, allowed)
    for s, ch, v, why in ok:
        print(f"ALLOWED     {s:18s} {ch:8s} {v}   [{why}]")
    for s, ch, v in unexpected:
        print(f"UNEXPECTED  {s:18s} {ch:8s} {v}")
    print(f"\n{len(unexpected)} unexpected, {len(ok)} allowed")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
