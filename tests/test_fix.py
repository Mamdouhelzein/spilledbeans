import subprocess

import pytest
from typer.testing import CliRunner

from spilledbeans import fixer, history
from spilledbeans.cli import app
from tests.conftest import FAKE, Repo, git

runner = CliRunner()

pytestmark = pytest.mark.skipif(
    subprocess.run(["git", "filter-repo", "--version"], capture_output=True).returncode != 0,
    reason="git-filter-repo not installed",
)


def run_fix(repo: Repo, answers: list[str]):
    return runner.invoke(app, ["fix", str(repo.path)], input="\n".join(answers) + "\n")


def backups(repo: Repo):
    return list(repo.path.parent.glob(f"{repo.path.name}-backup-*.git"))


def secret_anywhere(repo: Repo, secret: str) -> bool:
    return bool(history.objects_containing(repo.path, [secret]))


def test_fix_removes_secret_from_history(leaked_repo):
    secret = FAKE["github"]
    assert secret in leaked_repo.all_history_text()

    result = run_fix(leaked_repo, ["y", "yes", "n"])

    assert result.exit_code == 0, result.output
    assert secret not in result.output  # never printed
    history_text = leaked_repo.all_history_text()
    assert secret not in history_text
    assert fixer.REPLACEMENT in history_text
    assert not secret_anywhere(leaked_repo, secret)  # not even in unreachable objects
    assert "git push origin --force --all" in result.output  # printed, not run
    assert len(backups(leaked_repo)) == 1


def test_backup_is_a_full_mirror(leaked_repo):
    run_fix(leaked_repo, ["y", "yes", "n"])
    (backup,) = backups(leaked_repo)
    log = subprocess.run(["git", "log", "--all", "-p"], cwd=backup, capture_output=True, text=True).stdout
    assert FAKE["github"] in log  # backup preserves the original history


def test_fix_refuses_with_uncommitted_changes(leaked_repo):
    leaked_repo.write("README.md", "# changed\n")
    result = run_fix(leaked_repo, ["y", "yes", "n"])
    assert result.exit_code == 2
    assert "uncommitted changes" in result.output
    assert FAKE["github"] in leaked_repo.all_history_text()
    assert backups(leaked_repo) == []


def test_untracked_files_do_not_block(leaked_repo):
    leaked_repo.write("notes.txt", "scratch\n")
    result = run_fix(leaked_repo, ["y", "yes", "n"])
    assert result.exit_code == 0, result.output


def test_fix_stops_if_key_not_rotated(leaked_repo):
    before = leaked_repo.head()
    result = run_fix(leaked_repo, ["n"])
    assert result.exit_code == 1
    assert "Rotate the key first" in result.output
    assert leaked_repo.head() == before
    assert backups(leaked_repo) == []


def test_fix_requires_explicit_yes(leaked_repo):
    before = leaked_repo.head()
    result = run_fix(leaked_repo, ["y", "y"])  # "y" is not "yes"
    assert result.exit_code == 1
    assert "History was not changed" in result.output
    assert leaked_repo.head() == before
    assert FAKE["github"] in leaked_repo.all_history_text()


def test_fix_never_pushes(leaked_repo, tmp_path, monkeypatch):
    remote = tmp_path / "remote.git"
    git(tmp_path, "init", "-q", "--bare", str(remote))
    leaked_repo.git("remote", "add", "origin", str(remote))
    leaked_repo.git("push", "-q", "origin", "main")

    calls = []
    real_run, real_popen = subprocess.run, subprocess.Popen

    def spy_run(args, *a, **kw):
        calls.append(list(args) if not isinstance(args, str) else [args])
        return real_run(args, *a, **kw)

    class SpyPopen(real_popen):
        def __init__(self, args, *a, **kw):
            calls.append(list(args) if not isinstance(args, str) else [args])
            super().__init__(args, *a, **kw)

    monkeypatch.setattr(subprocess, "run", spy_run)
    monkeypatch.setattr(subprocess, "Popen", SpyPopen)

    result = run_fix(leaked_repo, ["y", "yes", "n"])
    assert result.exit_code == 0, result.output
    assert calls, "spy saw no subprocess calls"
    assert not any("push" in argv for argv in calls)
    # The remote still has the old history: we only printed the push command.
    remote_log = subprocess.run(
        ["git", "log", "--all", "-p"], cwd=remote, capture_output=True, text=True
    ).stdout
    assert FAKE["github"] in remote_log
    assert f"git remote add origin {remote}" in result.output
    assert "git push origin --force --all" in result.output


def test_env_file_removed_whole(repo):
    repo.commit("init", **{"app.py": "print('hi')\n"})
    repo.commit("oops", **{".env": f"OPENAI_API_KEY={FAKE['openai']}\nDB_PASSWORD=hunter2hunter2\n"})
    repo.commit("more", **{"app.py": "print('hello')\n"})

    # two findings (openai + env value) -> rotate twice, choose "file", confirm, skip hook
    result = run_fix(repo, ["y", "y", "file", "yes", "n"])
    assert result.exit_code == 0, result.output
    assert repo.git("log", "--all", "--format=%H", "--", ".env").strip() == ""
    assert not secret_anywhere(repo, FAKE["openai"])
    assert ".gitignore" in result.output


def test_secret_in_commit_message_is_replaced(repo):
    repo.commit("init", **{"a.py": f'K = "{FAKE["anthropic"]}"\n'})
    repo.write("b.txt", "x\n")
    repo.git("add", "b.txt")
    repo.git("commit", "-q", "-m", f"debug with {FAKE['anthropic']}")
    result = run_fix(repo, ["y", "yes", "n"])
    assert result.exit_code == 0, result.output
    assert FAKE["anthropic"] not in repo.git("log", "--all", "--format=%B")


def test_fix_installs_hook_when_asked(leaked_repo):
    result = run_fix(leaked_repo, ["y", "yes", "y"])
    assert result.exit_code == 0, result.output
    hook = leaked_repo.path / ".git" / "hooks" / "pre-commit"
    assert hook.exists() and "spilledbeans" in hook.read_text()


def test_nothing_to_fix(repo):
    repo.commit("init", **{"a.py": "print(1)\n"})
    result = run_fix(repo, [])
    assert result.exit_code == 0
    assert "Nothing to rewrite" in result.output


def test_missing_filter_repo_prints_install_command(leaked_repo, monkeypatch):
    monkeypatch.setattr("spilledbeans.gitutil.filter_repo_available", lambda: False)
    result = run_fix(leaked_repo, [])
    assert result.exit_code == 2
    assert "pipx install git-filter-repo" in result.output
