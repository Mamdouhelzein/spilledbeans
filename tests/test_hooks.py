"""The hook is tested for real: install it, then make actual `git commit` calls."""

import os
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from spilledbeans import hooks
from spilledbeans.cli import app
from tests.conftest import FAKE

runner = CliRunner()
posix_only = pytest.mark.skipif(os.name == "nt", reason="shell hook execution is POSIX-only in tests")


def try_commit(repo, rel, content):
    repo.write(rel, content)
    repo.git("add", rel)
    return subprocess.run(["git", "commit", "-m", "test"], cwd=repo.path, capture_output=True, text=True)


def test_install_and_uninstall(repo):
    repo.commit("init", **{"a.txt": "a\n"})
    path = hooks.install(repo.path)
    assert path.exists() and hooks.MARKER in path.read_text()
    assert sys.executable in path.read_text()
    assert os.access(path, os.X_OK) or os.name == "nt"
    assert hooks.uninstall(repo.path)
    assert not path.exists()


def test_does_not_clobber_existing_hook(repo):
    hook = repo.path / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho mine\n")
    with pytest.raises(hooks.HookExists):
        hooks.install(repo.path)
    hooks.install(repo.path, force=True)
    backup = hook.with_name("pre-commit.before-spilledbeans")
    assert backup.read_text() == "#!/bin/sh\necho mine\n"
    hooks.uninstall(repo.path)
    assert hook.read_text() == "#!/bin/sh\necho mine\n"  # restored


def test_respects_core_hooks_path(repo):
    repo.git("config", "core.hooksPath", ".githooks")
    path = hooks.install(repo.path)
    assert path == repo.path / ".githooks" / "pre-commit"


@posix_only
def test_hook_blocks_secret_commit(repo):
    repo.commit("init", **{"a.txt": "a\n"})
    hooks.install(repo.path)
    proc = try_commit(repo, "config.py", f'TOKEN = "{FAKE["huggingface"]}"\n')
    assert proc.returncode != 0
    out = proc.stdout + proc.stderr
    assert "Commit blocked" in out
    assert FAKE["huggingface"] not in out


@posix_only
def test_hook_allows_clean_commit_and_ignore_marker(repo):
    repo.commit("init", **{"a.txt": "a\n"})
    hooks.install(repo.path)
    assert try_commit(repo, "ok.py", "x = 1\n").returncode == 0
    marked = f'TOKEN = "{FAKE["huggingface"]}"  # beans:ignore\n'
    assert try_commit(repo, "fixture.py", marked).returncode == 0


@posix_only
def test_hook_ignores_secret_already_in_history(repo):
    """Editing a file that already has an old secret shouldn't block every commit."""
    repo.commit("init", **{"a.py": f'OLD = "{FAKE["google"]}"\n'})
    hooks.install(repo.path)
    assert try_commit(repo, "a.py", f'OLD = "{FAKE["google"]}"\nx = 2\n').returncode == 0


def test_cli_hook_install(repo):
    repo.commit("init", **{"a.txt": "a\n"})
    result = runner.invoke(app, ["hook", "install", str(repo.path)])
    assert result.exit_code == 0
    assert hooks.is_installed(repo.path)
    result = runner.invoke(app, ["hook", "uninstall", str(repo.path)])
    assert result.exit_code == 0
    assert not hooks.is_installed(repo.path)
