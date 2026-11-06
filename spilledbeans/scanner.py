"""Combine working-tree, staged and history scans into one list of findings,
one finding per unique secret value."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import detectors, gitutil, history
from . import providers as prov

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".ruff_cache"}
MAX_FILE_BYTES = history.MAX_BLOB_BYTES


@dataclass
class Location:
    path: str
    line: int
    source: str  # "working tree" | "history" | "staged"
    note: str | None = None


@dataclass
class Finding:
    provider_id: str
    confidence: str
    secret: str = field(repr=False)
    locations: list[Location] = field(default_factory=list)
    commits: set[str] = field(default_factory=set)
    branches: list[str] = field(default_factory=list)
    variable: str | None = None

    @property
    def provider(self) -> prov.Provider:
        return prov.get(self.provider_id)

    @property
    def masked(self) -> str:
        return detectors.mask(self.secret)

    @property
    def fingerprint(self) -> str:
        return detectors.fingerprint(self.secret)

    @property
    def paths(self) -> list[str]:
        return sorted({loc.path for loc in self.locations})

    @property
    def in_working_tree(self) -> bool:
        return any(loc.source == "working tree" for loc in self.locations)

    def __repr__(self) -> str:
        return f"Finding({self.provider_id}, {self.masked}, {len(self.commits)} commits)"

    def to_dict(self) -> dict:
        """JSON-safe view. Contains only the masked preview, never the secret."""
        return {
            "provider": self.provider.name,
            "provider_id": self.provider_id,
            "confidence": self.confidence,
            "masked": self.masked,
            "fingerprint": self.fingerprint,
            "locations": [
                {"path": loc.path, "line": loc.line, "source": loc.source, "note": loc.note}
                for loc in self.locations
            ],
            "commits": sorted(self.commits),
            "branches": self.branches,
            "revoke_url": self.provider.revoke_url or None,
        }


def _iter_files(root: Path) -> list[str]:
    if gitutil.is_git_repo(root):
        out = gitutil.out(["ls-files", "-z", "-co", "--exclude-standard"], root)
        return [p for p in out.split("\0") if p]
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            files.append(str(Path(dirpath, name).relative_to(root).as_posix()))
    return files


def scan_working_tree(root: Path) -> list[tuple[str, detectors.RawMatch]]:
    results = []
    for rel in _iter_files(root):
        path = root / rel
        try:
            if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if detectors.looks_binary(data):
            continue
        for m in detectors.detect_text(data.decode("utf-8", errors="replace"), rel):
            results.append((rel, m))
    return results


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def scan_staged(root: Path) -> list[tuple[str, detectors.RawMatch]]:
    """Scan only lines being added in the staged diff (what the pre-commit hook needs)."""
    diff = gitutil.out(
        ["diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--diff-filter=ACMR", "--text"], root
    )
    results = []
    path = None
    line_no = 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:]
            path = target[2:] if target.startswith("b/") else None
            continue
        if raw.startswith("@@"):
            m = _HUNK_RE.match(raw)
            line_no = int(m.group(1)) if m else 0
            continue
        if path is None:
            continue
        if raw.startswith("+"):
            for m in detectors.detect_line(raw[1:], line_no, detectors.is_env_file(path)):
                results.append((path, m))
            line_no += 1
    return results


def _merge(findings: dict[str, Finding], path: str, m: detectors.RawMatch, source: str) -> Finding:
    f = findings.get(m.secret)
    if f is None:
        f = Finding(m.provider_id, m.confidence, m.secret, variable=m.variable)
        findings[m.secret] = f
    elif prov.CONFIDENCE_ORDER[m.confidence] > prov.CONFIDENCE_ORDER[f.confidence]:
        f.provider_id, f.confidence = m.provider_id, m.confidence
    loc = Location(path, m.line, source, m.location_note)
    if not any((x.path, x.line, x.source) == (loc.path, loc.line, loc.source) for x in f.locations):
        f.locations.append(loc)
    return f


def _sorted(findings: dict[str, Finding]) -> list[Finding]:
    return sorted(
        findings.values(),
        key=lambda f: (-prov.CONFIDENCE_ORDER[f.confidence], f.provider_id, f.paths[:1]),
    )


def scan(root: Path, *, include_history: bool = True, staged: bool = False) -> list[Finding]:
    root = Path(root).resolve()
    findings: dict[str, Finding] = {}
    is_repo = gitutil.is_git_repo(root)
    if is_repo:
        root = gitutil.repo_root(root)

    if staged:
        if not is_repo:
            raise gitutil.GitError("--staged needs a git repository")
        for path, m in scan_staged(root):
            _merge(findings, path, m, "staged")
        return _sorted(findings)

    for path, m in scan_working_tree(root):
        _merge(findings, path, m, "working tree")

    if include_history and is_repo:
        result = history.scan_history(root)
        by_blob: dict[str, list[Finding]] = {}
        for hit in result.hits:
            f = _merge(findings, hit.path, hit.match, "history")
            by_blob.setdefault(hit.blob, []).append(f)
        for blob, fs in by_blob.items():
            commits = set(result.blob_commits.get(blob, {}))
            for f in fs:
                f.commits |= commits
        for f in findings.values():
            f.branches = history.refs_containing(root, f.commits)
    return _sorted(findings)


def fail_worthy(findings: list[Finding]) -> list[Finding]:
    """Findings that should fail a scan/hook: medium or high confidence."""
    return [f for f in findings if prov.CONFIDENCE_ORDER[f.confidence] >= prov.CONFIDENCE_ORDER[prov.MEDIUM]]
