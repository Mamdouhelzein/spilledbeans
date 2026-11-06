import csv
import json
import random
import string

from typer.testing import CliRunner

from spilledbeans import features, importers, scoring
from spilledbeans.cli import app
from tests.conftest import FAKE

runner = CliRunner()

# A random (but fake, never-issued) token that looks like a real one.
_rng = random.Random(1234)
REALISTIC_GH = "ghp_" + "".join(_rng.choice(string.ascii_letters + string.digits) for _ in range(36))
REALISTIC_GENERIC = "".join(_rng.choice(string.ascii_letters + string.digits + "+/") for _ in range(40))
COMMIT_SHA = "".join(_rng.choice("0123456789abcdef") for _ in range(40))
UUID = "3f2b8c1e-9a4d-4c7e-8b1a-2d5e6f7a8b9c"


def gitleaks_report():
    def item(rule, secret, file, match=None):
        return {
            "RuleID": rule,
            "Description": rule,
            "StartLine": 3,
            "EndLine": 3,
            "Match": match or f'token = "{secret}"',
            "Secret": secret,
            "File": file,
            "Commit": "a" * 40,
            "Entropy": 4.5,
            "Fingerprint": f"{file}:{rule}:3",
        }

    return [
        item("github-pat", REALISTIC_GH, "src/deploy.py"),
        item(
            "generic-api-key", REALISTIC_GENERIC, "config/settings.py", f'aws_secret = "{REALISTIC_GENERIC}"'
        ),
        item("generic-api-key", COMMIT_SHA, "scripts/release.sh", f'api_key_sha = "{COMMIT_SHA}"'),
        item("generic-api-key", UUID, "src/app.py", f'client_token = "{UUID}"'),
        item("github-pat", FAKE["github"], "tests/test_client.py", f'TEST_TOKEN = "{FAKE["github"]}"'),
        item("generic-api-key", "your_api_key_here", "README.md", 'API_KEY="your_api_key_here"'),
        item("generic-api-key", "sha512-" + "A" * 80, "package-lock.json"),
    ]


def trufflehog_report():
    def item(detector, raw, file, verified):
        return {
            "SourceMetadata": {"Data": {"Git": {"commit": "b" * 40, "file": file, "line": 7}}},
            "SourceName": "trufflehog - git",
            "DetectorName": detector,
            "Verified": verified,
            "Raw": raw,
            "Redacted": raw[:4] + "***",
        }

    lines = [
        item("Github", REALISTIC_GH, "app/main.py", True),
        item("Huggingface", FAKE["huggingface"], "docs/example.md", False),
    ]
    return "\n".join(json.dumps(x) for x in lines) + "\n"


def test_detect_formats():
    assert importers.detect_format(json.dumps(gitleaks_report())) == "gitleaks"
    assert importers.detect_format(trufflehog_report()) == "trufflehog"
    assert importers.detect_format("[]") == "gitleaks"


def test_variable_name_extraction():
    assert importers.variable_name('TEST_TOKEN = "abc123"', "abc123") == "TEST_TOKEN"
    assert importers.variable_name("export API_KEY=abc123", "abc123") == "API_KEY"
    assert importers.variable_name('{"secret": "abc123"}', "abc123") == "secret"


def test_features_have_no_secret_and_stable_order():
    f = features.extract_features(REALISTIC_GH, file_path="src/x.py", variable="TOKEN")
    assert list(f) == features.FEATURE_NAMES
    assert REALISTIC_GH not in json.dumps(f)
    assert f["provider_prefix"] == 1
    assert features.extract_features(COMMIT_SHA)["looks_commit_sha"] == 1
    assert features.extract_features(UUID)["looks_uuid"] == 1
    assert len(features.to_vector(f)) == len(features.FEATURE_NAMES)


def test_rule_scorer_separates_real_from_noise():
    _fmt, findings = importers.parse(json.dumps(gitleaks_report()))
    scorer = scoring.RuleScorer()
    scores = {
        f.file: scorer.score(features.extract_features(f.secret, file_path=f.file, variable=f.variable)).score
        for f in findings
    }
    assert scores["src/deploy.py"] >= 0.8
    assert scores["config/settings.py"] >= 0.5
    for noisy in (
        "scripts/release.sh",
        "src/app.py",
        "tests/test_client.py",
        "README.md",
        "package-lock.json",
    ):
        assert scores[noisy] < 0.5, noisy


def test_verified_trufflehog_is_always_real():
    score = scoring.RuleScorer().score(features.extract_features(UUID, verified=True))
    assert score.score > 0.9


def test_cli_filter_gitleaks(tmp_path):
    report = tmp_path / "gitleaks.json"
    report.write_text(json.dumps(gitleaks_report()))
    result = runner.invoke(app, ["filter", str(report), "--json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["format"] == "gitleaks" and data["total"] == 7 and data["likely_real"] == 2
    kept = {f["finding"]["File"] for f in data["findings"]}
    assert kept == {"src/deploy.py", "config/settings.py"}
    for secret in (REALISTIC_GH, REALISTIC_GENERIC):
        assert secret not in result.output  # Secret/Match fields are masked


def test_cli_filter_show_all_trufflehog(tmp_path):
    report = tmp_path / "th.json"
    report.write_text(trufflehog_report())
    result = runner.invoke(app, ["filter", str(report), "--show-all"])
    assert result.exit_code == 1
    assert "trufflehog" in result.output
    assert "noise" in result.output and "real" in result.output
    assert REALISTIC_GH not in result.output


def test_cli_filter_all_noise_exits_zero(tmp_path):
    report = tmp_path / "g.json"
    report.write_text(json.dumps(gitleaks_report()[2:]))
    result = runner.invoke(app, ["filter", str(report)])
    assert result.exit_code == 0


def test_cli_filter_rejects_unknown_format(tmp_path):
    report = tmp_path / "x.json"
    report.write_text('{"hello": 1}')
    result = runner.invoke(app, ["filter", str(report)])
    assert result.exit_code == 2


def test_label_mode_writes_csv_without_secrets(tmp_path):
    report = tmp_path / "g.json"
    report.write_text(json.dumps(gitleaks_report()[:3]))
    labels = tmp_path / "labels.csv"
    result = runner.invoke(
        app, ["filter", str(report), "--label", "--labels-file", str(labels)], input="r\nn\ns\n"
    )
    assert result.exit_code == 0, result.output
    rows = list(csv.DictReader(labels.open()))
    assert [r["label"] for r in rows] == ["real", "noise"]
    assert set(features.FEATURE_NAMES) <= set(rows[0])
    content = labels.read_text()
    for secret in (REALISTIC_GH, REALISTIC_GENERIC, COMMIT_SHA):
        assert secret not in content

    # Resuming skips what's already labelled.
    result = runner.invoke(app, ["filter", str(report), "--label", "--labels-file", str(labels)], input="n\n")
    assert "already in" in result.output
    assert len(list(csv.DictReader(labels.open()))) == 3


def test_model_scorer_is_a_v2_stub():
    import pytest

    with pytest.raises(NotImplementedError):
        scoring.ModelScorer.load("model.joblib")

    class FakeModel:
        def predict_proba(self, rows):
            return [[0.2, 0.8] for _ in rows]

    s = scoring.ModelScorer(FakeModel()).score(features.extract_features(REALISTIC_GH))
    assert s.score == 0.8
