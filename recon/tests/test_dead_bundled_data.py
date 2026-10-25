"""Bundled data that nothing reads stays deleted (drift-map #60).

recon/data/mitre_db/ was a second MITRE tree: add_mitre.py reads and refreshes
recon/main_recon_modules/data/mitre_db/, so the copy aged in git, 95 MB of CVE
files whose cwe_*.json already differed from the live ones. A dead copy is
worse than none: the next reader picks it because it is there.

Run: ./redamon.sh test unit (recon section; needs git and the repo at /repo)
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
THIS_FILE = str(Path(__file__).resolve().relative_to(PROJECT_ROOT))

DEAD_PATHS = ("recon/data/mitre_db",)

#: Tracked files that still name a dead path, each with the reason.
STILL_NAMED = {
    "recon/Dockerfile": "drift-map #60: handed back, mkdir of the unused /app/recon/data/mitre_db",
    "recon/entrypoint.sh": "drift-map #60: handed back, mkdir of the unused /app/recon/data/mitre_db",
    "docs/readmes/README.MITRE.md": "drift-map #60: docs are wave 3",
    "docs/readmes/README.DRIFT_MAP.md": "the drift map records the deletion",
}


def _git(*args: str) -> str:
    if shutil.which("git") is None or not (PROJECT_ROOT / ".git").exists():
        pytest.skip("needs git and the repository's .git")
    result = subprocess.run(["git", "-C", str(PROJECT_ROOT), *args],
                            capture_output=True, text=True, timeout=60)
    if result.returncode not in (0, 1):  # git grep exits 1 on no match
        pytest.skip(f"git {args[0]} failed: {result.stderr.strip()[:200]}")
    return result.stdout


def test_the_dead_trees_are_not_tracked():
    for path in DEAD_PATHS:
        assert _git("ls-files", "--", path).strip() == "", f"{path} is tracked again"


def test_nothing_names_a_dead_path():
    hits = {}
    for path in DEAD_PATHS:
        for f in _git("grep", "-I", "-l", "-F", path).splitlines():
            if f != THIS_FILE and f not in STILL_NAMED:
                hits.setdefault(path, []).append(f)
    assert not hits, f"tracked files still name a deleted data path: {hits}"
