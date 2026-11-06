"""Secret detection: provider-specific patterns first, generic entropy fallback last.

Nothing in this module ever prints a secret. ``RawMatch`` keeps the value in memory
(the fixer needs it to build replacement rules) but its ``repr`` is masked.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from . import providers as prov

IGNORE_MARKERS = ("beans:ignore", "spilledbeans:ignore")

SECRET_NAME_RE = re.compile(
    r"(?i)(api[_\-.]?key|apikey|secret|token|passw(?:or)?d|pwd|auth[_\-]?key|"
    r"access[_\-]?key|private[_\-]?key|client[_\-]?secret|credential)"
)

GENERIC_ASSIGN_RE = re.compile(
    r"(?P<name>[A-Za-z0-9_.\-]*" + SECRET_NAME_RE.pattern[4:] + r"[A-Za-z0-9_.\-]*)"
    r"[\"']?\s*(?::=|=>|[:=])\s*[\"'](?P<secret>[^\"'\s]{16,})[\"']",
    re.IGNORECASE,
)

ENV_LINE_RE = re.compile(
    r"^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"']?(?P<secret>[^\"'\s#]+)"
)

PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:<.*>|\$\{.*\}|\{\{.*\}\}|\{[A-Za-z_][\w.\[\]]*\}|%\(.*\)s?|x{6,}|\*{4,}|\.{3,}|"
    r".*(?:your[_\-]?(?:api[_\-]?)?(?:key|token|secret)|changeme|change[_\-]me|placeholder|"
    r"replace[_\-]?me|insert[_\-]|redacted|removed-by-spilledbeans).*)$"
)

GENERIC_MIN_ENTROPY = 3.5
NOTEBOOK_SUFFIX = ".ipynb"
SECRET_FILE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore", ".jks")
SECRET_FILE_NAMES = ("credentials.json", "service-account.json", "id_rsa", "id_ed25519", ".npmrc", ".pypirc")


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def mask(secret: str) -> str:
    """First 4 + last 4 characters only. Short values reveal even less."""
    if len(secret) <= 12:
        return secret[:2] + "…" + "*" * 4
    return f"{secret[:4]}…{secret[-4:]}"


def fingerprint(secret: str) -> str:
    """Stable, non-reversible id for a secret (safe to print, log, or store)."""
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_RE.match(value))


def is_env_file(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    if not (name == ".env" or name.startswith(".env.") or name.endswith(".env")):
        return False
    return not any(name.endswith(s) for s in (".example", ".sample", ".template", ".dist"))


def is_secret_file(path: str) -> bool:
    """Files that are credentials by nature; removing them whole is often right."""
    name = PurePosixPath(path).name.lower()
    return is_env_file(path) or name in SECRET_FILE_NAMES or name.endswith(SECRET_FILE_SUFFIXES)


@dataclass
class RawMatch:
    provider_id: str
    confidence: str
    secret: str = field(repr=False)
    line: int
    variable: str | None = None
    location_note: str | None = None  # e.g. "cell 3 output" for notebooks

    @property
    def masked(self) -> str:
        return mask(self.secret)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.secret)

    def __repr__(self) -> str:  # never leak the secret through debugging output
        return f"RawMatch({self.provider_id}, {self.confidence}, {self.masked}, line={self.line})"


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    return any(span[0] < e and s < span[1] for s, e in taken)


def detect_line(line: str, line_no: int, env_file: bool = False) -> list[RawMatch]:
    if any(m in line for m in IGNORE_MARKERS):
        return []
    found: list[RawMatch] = []
    taken: list[tuple[int, int]] = []

    for p in prov.PROVIDERS.values():
        for pattern in p.patterns:
            for m in pattern.finditer(line):
                group = "secret" if "secret" in pattern.groupindex else 0
                secret = m.group(group)
                span = m.span(group)
                if _overlaps(span, taken):
                    continue
                taken.append(span)
                found.append(RawMatch(p.id, p.confidence, secret, line_no))

    if env_file:
        m = ENV_LINE_RE.match(line)
        if m and SECRET_NAME_RE.search(m.group("name")):
            secret = m.group("secret")
            span = m.span("secret")
            if len(secret) >= 8 and not is_placeholder(secret) and not _overlaps(span, taken):
                taken.append(span)
                found.append(RawMatch(prov.ENV_FILE.id, prov.MEDIUM, secret, line_no, m.group("name")))

    for m in GENERIC_ASSIGN_RE.finditer(line):
        secret = m.group("secret")
        span = m.span("secret")
        if _overlaps(span, taken) or is_placeholder(secret):
            continue
        if shannon_entropy(secret) < GENERIC_MIN_ENTROPY:
            continue
        taken.append(span)
        found.append(RawMatch(prov.GENERIC.id, prov.LOW, secret, line_no, m.group("name")))
    return found


def _notebook_locator(text: str):
    """Return a function secret -> 'cell N source/output' for .ipynb files."""
    try:
        nb = json.loads(text)
        cells = nb.get("cells", [])
    except (ValueError, AttributeError):
        return lambda _s: None

    def locate(secret: str) -> str | None:
        for i, cell in enumerate(cells, start=1):
            source = cell.get("source", "")
            source = "".join(source) if isinstance(source, list) else str(source)
            if secret in source:
                return f"notebook cell {i} source"
            if secret in json.dumps(cell.get("outputs", [])):
                return f"notebook cell {i} output"
        return None

    return locate


def detect_text(text: str, path: str = "") -> list[RawMatch]:
    env_file = is_env_file(path)
    results: list[RawMatch] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if len(line) > 20_000:  # minified bundles etc.: scan, but in chunks
            for start in range(0, len(line), 10_000):
                results.extend(detect_line(line[start : start + 10_500], i, env_file))
        else:
            results.extend(detect_line(line, i, env_file))
    if path.endswith(NOTEBOOK_SUFFIX) and results:
        locate = _notebook_locator(text)
        for r in results:
            r.location_note = locate(r.secret)
    return _dedupe(results)


def _dedupe(results: list[RawMatch]) -> list[RawMatch]:
    seen: set[tuple[str, int]] = set()
    out = []
    for r in results:
        key = (r.secret, r.line)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


def looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]
