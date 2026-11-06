"""Test helpers: throwaway git repos with obviously FAKE secrets.

Fake keys are assembled at runtime so this source file itself never contains a
string that matches a provider pattern (so `beans scan` on this repo stays clean).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

FAKE = {
    "github": "ghp_" + "EXAMPLE" + "0" * 29,
    "github_pat": "github_pat_" + "EXAMPLE" + "0" * 15 + "_" + "EXAMPLE" + "0" * 52,
    "openai": "sk-proj-" + "EXAMPLEFAKEKEY" + "x" * 40,
    "anthropic": "sk-ant-api03-" + "EXAMPLE" + "A" * 86,
    "aws": "AKIA" + "EXAMPLE" + "0" * 9,
    "huggingface": "hf_" + "EXAMPLE" + "a" * 27,
    "stripe": "sk_live_" + "EXAMPLE" + "0" * 20,
    "slack": "xoxb-" + "1234567890" + "-" + "EXAMPLEFAKE0",
    "google": "AIza" + "EXAMPLE" + "0" * 28,
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout


class Repo:
    def __init__(self, path: Path):
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        git(path, "init", "-q", "-b", "main")
        git(path, "config", "user.name", "Test")
        git(path, "config", "user.email", "test@example.com")
        git(path, "config", "commit.gpgsign", "false")

    def write(self, rel: str, content: str) -> Path:
        p = self.path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return p

    def commit(self, message: str, **files: str) -> str:
        for rel, content in files.items():
            self.write(rel.replace("__", "/"), content)
        git(self.path, "add", "-A")
        git(self.path, "commit", "-q", "-m", message)
        return self.head()

    def head(self) -> str:
        return git(self.path, "rev-parse", "HEAD").strip()

    def git(self, *args: str) -> str:
        return git(self.path, *args)

    def all_history_text(self) -> str:
        """Every blob in every reachable commit, plus loose/packed object contents via log -p."""
        return git(self.path, "log", "--all", "-p", "--format=%H %s")


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path / "project")


@pytest.fixture
def leaked_repo(tmp_path: Path) -> Repo:
    """A repo where a GitHub token was committed, then 'removed' in a later commit."""
    r = Repo(tmp_path / "project")
    r.commit("initial", **{"README.md": "# demo\n"})
    r.commit("add config", **{"config.py": f'GITHUB_TOKEN = "{FAKE["github"]}"\n'})
    r.commit("remove token", **{"config.py": 'import os\nGITHUB_TOKEN = os.environ["GITHUB_TOKEN"]\n'})
    return r
