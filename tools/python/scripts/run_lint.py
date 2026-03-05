"""Run pre-commit for the whole repo from repo root. Use: poetry run lint."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    # scripts/run_lint.py -> scripts -> tools/python -> repo root
    repo_root = Path(__file__).resolve().parent.parent.parent
    return subprocess.run(
        [sys.executable, "-m", "pre_commit", "run", "--all-files"],
        cwd=repo_root,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
