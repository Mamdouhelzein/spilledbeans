"""Thin wrappers around the git CLI. Every git call in spilledbeans goes through ``run``."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def run(
    args: list[str],
    cwd: str | Path,
    *,
    input: bytes | None = None,
    check: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        input=input,
        capture_output=True,
        text=text if input is None else False,
    )
    if check and proc.returncode != 0:
        err = proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode(errors="replace")
        raise GitError(f"git {args[0]} failed: {err.strip()}")
    return proc


def out(args: list[str], cwd: str | Path) -> str:
    return run(args, cwd).stdout


def is_git_repo(path: str | Path) -> bool:
    if shutil.which("git") is None:
        return False
    proc = run(["rev-parse", "--is-inside-work-tree"], path, check=False)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def repo_root(path: str | Path) -> Path:
    return Path(out(["rev-parse", "--show-toplevel"], path).strip())


def git_dir(path: str | Path) -> Path:
    return Path(out(["rev-parse", "--absolute-git-dir"], path).strip())


def has_commits(path: str | Path) -> bool:
    return run(["rev-parse", "--verify", "-q", "HEAD"], path, check=False).returncode == 0


def uncommitted_changes(path: str | Path) -> list[str]:
    """Modified/staged tracked files. Untracked files don't affect a history rewrite."""
    return [ln for ln in out(["status", "--porcelain", "--untracked-files=no"], path).splitlines() if ln]


def remotes(path: str | Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in out(["remote", "-v"], path).splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] not in result:
            result[parts[0]] = parts[1]
    return result


def read_objects(cwd: str | Path, shas: list[str]) -> dict[str, tuple[str, bytes]]:
    """Read many objects in one ``git cat-file --batch`` call. Returns sha -> (type, data)."""
    if not shas:
        return {}
    proc = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=str(cwd),
        input=("\n".join(shas) + "\n").encode(),
        capture_output=True,
    )
    if proc.returncode != 0:
        raise GitError(proc.stderr.decode(errors="replace"))
    data = proc.stdout
    result: dict[str, tuple[str, bytes]] = {}
    pos = 0
    while pos < len(data):
        nl = data.index(b"\n", pos)
        header = data[pos:nl].decode()
        pos = nl + 1
        parts = header.split()
        if len(parts) < 3 or parts[1] == "missing":
            continue
        sha, typ, size = parts[0], parts[1], int(parts[2])
        result[sha] = (typ, data[pos : pos + size])
        pos += size + 1
    return result


def filter_repo_available() -> bool:
    if shutil.which("git-filter-repo"):
        return True
    return subprocess.run(["git", "filter-repo", "--version"], capture_output=True).returncode == 0


FILTER_REPO_INSTALL = """git-filter-repo is not installed. Install it with one of:

  pipx install git-filter-repo        # any OS (recommended)
  pip install --user git-filter-repo  # any OS
  brew install git-filter-repo        # macOS
  sudo apt install git-filter-repo    # Debian / Ubuntu
  scoop install git-filter-repo       # Windows (scoop)
"""
