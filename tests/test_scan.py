import json

from typer.testing import CliRunner

from spilledbeans import scanner
from spilledbeans.cli import app
from tests.conftest import FAKE

runner = CliRunner()


def test_working_tree_only_folder(tmp_path):
    (tmp_path / "app.py").write_text(f'KEY = "{FAKE["google"]}"\n')
    findings = scanner.scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].provider_id == "google"
    assert findings[0].commits == set()


def test_history_finds_deleted_secret_with_commits_and_branches(leaked_repo):
    leaked_repo.git("checkout", "-q", "-b", "feature")
    leaked_repo.commit("feature work", **{"feature.txt": "hello\n"})
    leaked_repo.git("checkout", "-q", "main")

    findings = scanner.scan(leaked_repo.path)
    assert len(findings) == 1
    f = findings[0]
    assert f.provider_id == "github"
    assert not f.in_working_tree  # removed from the tree, still in history
    log = leaked_repo.git("log", "--format=%H %s", "--all").splitlines()
    by_msg = {line.split(" ", 1)[1]: line.split(" ", 1)[0] for line in log}
    # Only the commit that added it contains it; the "remove token" commit does not.
    assert f.commits == {by_msg["add config"]}
    assert f.branches == ["feature", "main"]
    assert f.locations[0].path == "config.py"


def test_secret_present_in_many_commits(repo):
    repo.commit("add", **{"src__keys.py": f'K = "{FAKE["openai"]}"\n'})
    c2 = repo.commit("unrelated", **{"other.txt": "x\n"})
    findings = scanner.scan(repo.path)
    assert len(findings) == 1
    assert c2 in findings[0].commits
    assert len(findings[0].commits) == 2
    assert findings[0].in_working_tree
    assert findings[0].paths == ["src/keys.py"]


def test_committed_env_and_notebook(repo):
    nb = {"cells": [{"cell_type": "code", "source": [], "outputs": [{"text": [FAKE["huggingface"]]}]}]}
    repo.commit("oops", **{".env": "SECRET_TOKEN=abcd1234efgh5678\n", "nb.ipynb": json.dumps(nb)})
    findings = scanner.scan(repo.path)
    ids = sorted(f.provider_id for f in findings)
    assert ids == ["env-file", "huggingface"]
    hf = next(f for f in findings if f.provider_id == "huggingface")
    assert any(loc.note and "output" in loc.note for loc in hf.locations)


def test_staged_scans_only_added_lines(repo):
    repo.commit("old", **{"a.py": f'OLD = "{FAKE["stripe"]}"\n'})
    repo.write("a.py", f'OLD = "{FAKE["stripe"]}"\nNEW = "{FAKE["aws"]}"\n')
    repo.git("add", "a.py")
    findings = scanner.scan(repo.path, staged=True)
    assert [f.provider_id for f in findings] == ["aws"]
    assert findings[0].locations[0].line == 2


def test_cli_json_never_contains_secret(leaked_repo):
    result = runner.invoke(app, ["scan", str(leaked_repo.path), "--json"])
    assert result.exit_code == 1
    assert FAKE["github"] not in result.output
    data = json.loads(result.output)
    f = data["findings"][0]
    assert f["masked"] == FAKE["github"][:4] + "…" + FAKE["github"][-4:]
    assert f["commits"] and f["branches"] == ["main"]


def test_cli_pretty_output_never_contains_secret(leaked_repo):
    result = runner.invoke(app, ["scan", str(leaked_repo.path)])
    assert result.exit_code == 1
    assert FAKE["github"] not in result.output
    assert "GitHub token" in result.output
    assert "beans fix" in result.output


def test_cli_clean_repo(repo):
    repo.commit("init", **{"a.py": "print('hi')\n"})
    result = runner.invoke(app, ["scan", str(repo.path)])
    assert result.exit_code == 0
    assert "No secrets found" in result.output


def test_low_confidence_only_exits_zero(repo):
    repo.commit("init", **{"a.py": 'db_password = "Xk9#mQ2$vL7pR4wZ8nB3"\n'})  # beans:ignore
    result = runner.invoke(app, ["scan", str(repo.path)])
    assert result.exit_code == 0
    assert "low-confidence" in result.output
