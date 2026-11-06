import pytest

from spilledbeans import detectors
from tests.conftest import FAKE


@pytest.mark.parametrize(
    "key,provider",
    [
        ("github", "github"),
        ("github_pat", "github"),
        ("openai", "openai"),
        ("anthropic", "anthropic"),
        ("aws", "aws"),
        ("huggingface", "huggingface"),
        ("stripe", "stripe"),
        ("slack", "slack"),
        ("google", "google"),
    ],
)
def test_provider_patterns(key, provider):
    line = f'KEY = "{FAKE[key]}"'
    matches = detectors.detect_line(line, 1)
    assert [m.provider_id for m in matches] == [provider]
    assert matches[0].secret == FAKE[key]
    assert matches[0].confidence == "high"


def test_anthropic_key_is_not_reported_as_openai():
    matches = detectors.detect_line(FAKE["anthropic"], 1)
    assert [m.provider_id for m in matches] == ["anthropic"]


def test_aws_secret_key_with_context():
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"  # beans:ignore
    matches = detectors.detect_line(f"aws_secret_access_key = {secret}", 1)  # beans:ignore
    assert [m.secret for m in matches] == [secret]


def test_generic_high_entropy_is_low_confidence():
    matches = detectors.detect_line('db_password = "Xk9#mQ2$vL7pR4wZ8nB3"', 1)  # beans:ignore
    assert len(matches) == 1
    assert matches[0].provider_id == "generic"
    assert matches[0].confidence == "low"


def test_generic_ignores_low_entropy_and_placeholders():
    assert detectors.detect_line('api_key = "aaaaaaaaaaaaaaaaaaaa"', 1) == []
    assert detectors.detect_line('api_key = "your_api_key_here_please"', 1) == []
    assert detectors.detect_line('api_key = "${OPENAI_API_KEY_FROM_ENV}"', 1) == []
    assert detectors.detect_line('api_key = "{API_KEY_FROM_SETTINGS}"', 1) == []


def test_ignore_marker():
    assert detectors.detect_line(f'x = "{FAKE["github"]}"  # beans:ignore', 1) == []


def test_env_file_values():
    text = "DEBUG=true\nPORT=8080\nDB_PASSWORD=hunter2hunter2\nAPI_KEY=changeme\n"
    matches = detectors.detect_text(text, ".env")
    assert [(m.provider_id, m.line, m.variable) for m in matches] == [("env-file", 3, "DB_PASSWORD")]
    assert matches[0].confidence == "medium"
    # same content in a non-.env file is not flagged by the .env rule
    assert detectors.detect_text(text, "settings.txt") == []


def test_env_file_detection():
    assert detectors.is_env_file(".env")
    assert detectors.is_env_file("app/.env.production")
    assert not detectors.is_env_file(".env.example")
    assert not detectors.is_env_file("environment.py")


def test_notebook_output_location():
    import json

    nb = {
        "cells": [
            {"cell_type": "code", "source": ["print(1)"], "outputs": []},
            {
                "cell_type": "code",
                "source": ["import os\n", "print(os.environ['HF'])"],
                "outputs": [{"output_type": "stream", "text": [FAKE["huggingface"] + "\n"]}],
            },
        ]
    }
    matches = detectors.detect_text(json.dumps(nb, indent=1), "analysis.ipynb")
    assert len(matches) == 1
    assert matches[0].location_note == "notebook cell 2 output"


def test_mask_never_reveals_middle():
    s = FAKE["openai"]
    masked = detectors.mask(s)
    assert masked == f"{s[:4]}…{s[-4:]}"
    assert s not in masked
    assert detectors.mask("short123") == "sh…****"


def test_repr_does_not_leak():
    m = detectors.detect_line(FAKE["github"], 1)[0]
    assert FAKE["github"] not in repr(m)
