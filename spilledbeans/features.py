"""Feature extraction for scoring findings as likely-real vs likely-noise.

``extract_features`` returns a flat dict of numbers/bools and NEVER includes the
secret itself, so the same dicts can be written to a training CSV and fed to a
scikit-learn model in v2 (see ``FEATURE_NAMES`` for a stable column order).
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from . import detectors
from . import providers as prov

TEST_WORDS = ("test", "example", "dummy", "fake", "sample", "mock", "placeholder", "demo", "foo", "lorem")
TEST_DIRS = (
    "test",
    "tests",
    "spec",
    "specs",
    "__tests__",
    "__mocks__",
    "testdata",
    "test_data",
    "fixtures",
    "fixture",
    "examples",
    "example",
    "samples",
    "docs",
    "doc",
    "demo",
)
DOC_EXTS = (".md", ".rst", ".txt", ".adoc", ".html")
LOCKFILES = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "go.sum",
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "uv.lock",
)

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HASH_LENGTHS = (32, 40, 56, 64, 96, 128)  # md5, sha1/commit, sha224, sha256, sha384, sha512

FEATURE_NAMES = [
    "length",
    "entropy",
    "unique_ratio",
    "repeat_ratio",
    "char_classes",
    "provider_prefix",
    "looks_uuid",
    "looks_hash",
    "looks_commit_sha",
    "is_placeholder",
    "secret_has_test_word",
    "var_has_test_word",
    "path_in_test_dir",
    "path_is_doc",
    "path_is_lockfile",
    "verified",
]


def _longest_run(s: str) -> int:
    best = run = 0
    prev = None
    for ch in s:
        run = run + 1 if ch == prev else 1
        best = max(best, run)
        prev = ch
    return best


def _provider_prefix(secret: str) -> str | None:
    for p in prov.PROVIDERS.values():
        for pattern in p.patterns:
            if "secret" in pattern.groupindex:
                continue  # context-dependent patterns can't match a bare value
            if pattern.fullmatch(secret):
                return p.id
    return None


def _has_word(text: str, words=TEST_WORDS) -> bool:
    t = text.lower()
    return any(w in t for w in words)


def extract_features(
    secret: str,
    *,
    file_path: str = "",
    variable: str = "",
    verified: bool | None = None,
) -> dict[str, float]:
    n = len(secret)
    path = PurePosixPath(file_path.replace("\\", "/").lower())
    parts = set(path.parts[:-1])
    is_hex = bool(_HEX_RE.match(secret))
    classes = sum(
        bool(re.search(pattern, secret)) for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")
    )
    return {
        "length": n,
        "entropy": round(detectors.shannon_entropy(secret), 4),
        "unique_ratio": round(len(set(secret)) / n, 4) if n else 0.0,
        "repeat_ratio": round(_longest_run(secret) / n, 4) if n else 0.0,
        "char_classes": classes,
        "provider_prefix": int(_provider_prefix(secret) is not None),
        "looks_uuid": int(bool(_UUID_RE.match(secret))),
        "looks_hash": int(is_hex and n in _HASH_LENGTHS),
        "looks_commit_sha": int(is_hex and n == 40 and secret == secret.lower()),
        "is_placeholder": int(detectors.is_placeholder(secret)),
        "secret_has_test_word": int(_has_word(secret) or "xxxx" in secret.lower()),
        "var_has_test_word": int(_has_word(variable)),
        "path_in_test_dir": int(bool(parts & set(TEST_DIRS)) or path.name.startswith("test_")),
        "path_is_doc": int(path.suffix in DOC_EXTS),
        "path_is_lockfile": int(path.name in LOCKFILES),
        "verified": -1 if verified is None else int(verified),
    }


def provider_for(secret: str) -> str | None:
    return _provider_prefix(secret)


def to_vector(features: dict[str, float]) -> list[float]:
    return [float(features[name]) for name in FEATURE_NAMES]
