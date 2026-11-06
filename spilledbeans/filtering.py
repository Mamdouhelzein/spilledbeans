"""``beans filter``: score other scanners' findings and keep the likely-real ones."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from . import features as feat
from .detectors import fingerprint
from .importers import ExternalFinding
from .scoring import Score, Scorer


@dataclass
class Scored:
    finding: ExternalFinding
    features: dict[str, float]
    result: Score

    def to_dict(self, threshold: float) -> dict:
        return {
            "score": self.result.score,
            "likely_real": self.result.likely_real(threshold),
            "reasons": self.result.reasons,
            "masked": self.finding.masked,
            "fingerprint": fingerprint(self.finding.secret),
            "features": self.features,
            "finding": self.finding.redacted(),
        }


def score_all(findings: list[ExternalFinding], scorer: Scorer) -> list[Scored]:
    scored = []
    for f in findings:
        features = feat.extract_features(f.secret, file_path=f.file, variable=f.variable, verified=f.verified)
        scored.append(Scored(f, features, scorer.score(features)))
    return sorted(scored, key=lambda s: -s.result.score)


def _score_text(score: float, threshold: float) -> Text:
    style = "bold red" if score >= max(threshold, 0.75) else ("yellow" if score >= threshold else "dim")
    return Text(f"{score:.2f}", style=style)


def table(items: list[Scored], threshold: float, show_all: bool) -> Table:
    t = Table(show_header=True, header_style="bold")
    t.add_column("Score", justify="right")
    if show_all:
        t.add_column("Verdict")
    t.add_column("Rule")
    t.add_column("Location")
    t.add_column("Preview")
    t.add_column("Why")
    for s in items:
        f = s.finding
        loc = f"{f.file}:{f.line}" if f.line else f.file
        row = [_score_text(s.result.score, threshold)]
        if show_all:
            real = s.result.likely_real(threshold)
            row.append(Text("real" if real else "noise", style="red" if real else "green"))
        row += [f.rule, loc, f.masked, "\n".join(s.result.reasons[:4])]
        t.add_row(*row)
    return t


# --------------------------------------------------------------------------- labelling

CSV_FIELDS = ["fingerprint", "tool", "rule", "file", "line", *feat.FEATURE_NAMES, "rule_score", "label"]


def _already_labelled(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open(newline="") as fh:
        return {row["fingerprint"] + "|" + row["file"] for row in csv.DictReader(fh)}


def label(items: list[Scored], csv_path: Path, console: Console) -> tuple[int, int]:
    """Interactively label findings. Returns (labelled, skipped). The CSV never contains secrets."""
    done = _already_labelled(csv_path)
    new_file = not csv_path.exists()
    labelled = skipped = 0
    todo = [s for s in items if fingerprint(s.finding.secret) + "|" + s.finding.file not in done]
    if len(todo) < len(items):
        console.print(f"[dim]Skipping {len(items) - len(todo)} finding(s) already in {csv_path}.[/dim]")
    with csv_path.open("a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        if new_file:
            writer.writeheader()
        for i, s in enumerate(todo, start=1):
            f = s.finding
            body = Table.grid(padding=(0, 2))
            body.add_column(style="bold")
            body.add_column()
            body.add_row("Preview", f.masked)
            body.add_row("Location", f"{f.file}:{f.line}" if f.line else f.file)
            if f.variable:
                body.add_row("Variable", f.variable)
            body.add_row("Rule score", f"{s.result.score:.2f}")
            body.add_row("Signals", "\n".join(s.result.reasons) or "—")
            console.print(Panel(body, title=f"[{i}/{len(todo)}] {f.tool}: {f.rule}", title_align="left"))
            answer = Prompt.ask(
                "[r]eal / [n]oise / [s]kip / [q]uit", choices=["r", "n", "s", "q"], console=console
            )
            if answer == "q":
                break
            if answer == "s":
                skipped += 1
                continue
            writer.writerow(
                {
                    "fingerprint": fingerprint(f.secret),
                    "tool": f.tool,
                    "rule": f.rule,
                    "file": f.file,
                    "line": f.line,
                    **s.features,
                    "rule_score": s.result.score,
                    "label": "real" if answer == "r" else "noise",
                }
            )
            fh.flush()
            labelled += 1
    return labelled, skipped
