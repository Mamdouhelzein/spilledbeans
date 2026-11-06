"""Install/uninstall a git pre-commit hook that runs ``beans scan --staged``."""

from __future__ import annotations

import os
import shlex
import stat
import sys
from pathlib import Path

from . import gitutil

MARKER = "# installed by spilledbeans"


def hooks_dir(repo: Path) -> Path:
    custom = gitutil.run(["config", "--get", "core.hooksPath"], repo, check=False).stdout.strip()
    if custom:
        p = Path(custom)
        return p if p.is_absolute() else gitutil.repo_root(repo) / p
    return gitutil.git_dir(repo) / "hooks"


def hook_script() -> str:
    # Prefer the interpreter that installed us (stable with pipx), fall back to `beans` on PATH.
    py = shlex.quote(sys.executable)
    return f"""#!/bin/sh
{MARKER}
# Blocks commits that add secrets. Bypass once with: git commit --no-verify
if {py} -c "import spilledbeans" >/dev/null 2>&1; then
  exec {py} -m spilledbeans scan --staged
elif command -v beans >/dev/null 2>&1; then
  exec beans scan --staged
else
  echo "spilledbeans: 'beans' not found; skipping secret scan (pipx install spilledbeans)" >&2
  exit 0
fi
"""


class HookExists(Exception):
    pass


def install(repo: Path, force: bool = False) -> Path:
    path = hooks_dir(repo) / "pre-commit"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_text(errors="replace")
        if MARKER not in existing:
            if not force:
                raise HookExists(str(path))
            backup = path.with_name("pre-commit.before-spilledbeans")
            path.replace(backup)
    path.write_text(hook_script())
    if os.name != "nt":
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def uninstall(repo: Path) -> bool:
    path = hooks_dir(repo) / "pre-commit"
    if not path.exists() or MARKER not in path.read_text(errors="replace"):
        return False
    path.unlink()
    backup = path.with_name("pre-commit.before-spilledbeans")
    if backup.exists():
        backup.replace(path)
    return True


def is_installed(repo: Path) -> bool:
    path = hooks_dir(repo) / "pre-commit"
    return path.exists() and MARKER in path.read_text(errors="replace")
