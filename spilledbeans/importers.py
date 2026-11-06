"""Parse Gitleaks and TruffleHog JSON output into one common shape.

Format is auto-detected:
* Gitleaks (``gitleaks detect --report-format json``): a JSON array of objects with ``RuleID``/``Secret``.
* TruffleHog v3 (``trufflehog ... --json``): newline-delimited JSON objects with ``DetectorName``/``Raw``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .detectors import mask

GITLEAKS = "gitleaks"
TRUFFLEHOG = "trufflehog"


class UnknownFormat(ValueError):
    pass


@dataclass
class ExternalFinding:
    tool: str
    rule: str
    secret: str = field(repr=False)
    file: str = ""
    line: int = 0
    commit: str = ""
    context: str = field(default="", repr=False)  # the matched line/snippet; may contain the secret
    verified: bool | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def masked(self) -> str:
        return mask(self.secret)

    @property
    def variable(self) -> str:
        return variable_name(self.context, self.secret)

    def redacted(self) -> dict[str, Any]:
        """The original record with every occurrence of the secret masked."""
        return _redact(self.raw, self.secret)


_VAR_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.\-]*)[\"'\]]?\s*(?::=|=>|[:=])\s*$")


def variable_name(context: str, secret: str) -> str:
    """Best-effort name the secret was assigned to, e.g. ``TEST_API_KEY = "..."``."""
    if not context:
        return ""
    idx = context.find(secret) if secret else -1
    before = context[:idx] if idx >= 0 else context
    before = before.rstrip().rstrip("\"'`").rstrip()
    m = _VAR_RE.search(before)
    return m.group(1) if m else ""


def _redact(obj: Any, secret: str) -> Any:
    if isinstance(obj, str):
        return obj.replace(secret, mask(secret)) if secret and secret in obj else obj
    if isinstance(obj, list):
        return [_redact(x, secret) for x in obj]
    if isinstance(obj, dict):
        return {k: _redact(v, secret) for k, v in obj.items()}
    return obj


def detect_format(text: str) -> str:
    stripped = text.lstrip()
    if not stripped:
        raise UnknownFormat("input is empty")
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except ValueError as e:
            raise UnknownFormat(f"invalid JSON: {e}") from e
        if not data or (isinstance(data[0], dict) and "RuleID" in data[0]):
            return GITLEAKS
        if isinstance(data[0], dict) and "DetectorName" in data[0]:
            return TRUFFLEHOG  # trufflehog output wrapped into an array
        raise UnknownFormat("JSON array, but not Gitleaks findings")
    for line in stripped.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if "DetectorName" in obj or "SourceMetadata" in obj:
            return TRUFFLEHOG
        if "RuleID" in obj:
            return GITLEAKS
    raise UnknownFormat("could not recognise Gitleaks or TruffleHog JSON output")


def _gitleaks(item: dict) -> ExternalFinding:
    secret = str(item.get("Secret") or item.get("Match") or "")
    return ExternalFinding(
        tool=GITLEAKS,
        rule=str(item.get("RuleID", "")),
        secret=secret,
        file=str(item.get("File", "")),
        line=int(item.get("StartLine") or 0),
        commit=str(item.get("Commit", "")),
        context=str(item.get("Line") or item.get("Match") or ""),
        raw=item,
    )


def _trufflehog(item: dict) -> ExternalFinding:
    data = (item.get("SourceMetadata") or {}).get("Data") or {}
    src = next(iter(data.values()), {}) if isinstance(data, dict) and data else {}
    secret = str(item.get("Raw") or item.get("RawV2") or "")
    verified = item.get("Verified")
    return ExternalFinding(
        tool=TRUFFLEHOG,
        rule=str(item.get("DetectorName", "")),
        secret=secret,
        file=str(src.get("file") or src.get("path") or ""),
        line=int(src.get("line") or 0),
        commit=str(src.get("commit") or ""),
        context="",
        verified=bool(verified) if verified is not None else None,
        raw=item,
    )


def parse(text: str) -> tuple[str, list[ExternalFinding]]:
    fmt = detect_format(text)
    stripped = text.strip()
    if stripped.startswith("["):
        items = json.loads(stripped)
    else:
        items = []
        for line in stripped.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    items.append(json.loads(line))
                except ValueError:
                    continue
    convert = _gitleaks if fmt == GITLEAKS else _trufflehog
    findings = [convert(i) for i in items if isinstance(i, dict)]
    return fmt, [f for f in findings if f.secret]
