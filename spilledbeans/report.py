"""Rich rendering for scan findings. Only masked previews are ever rendered."""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .providers import HIGH, LOW, MEDIUM
from .scanner import Finding

CONF_STYLE = {HIGH: "bold red", MEDIUM: "yellow", LOW: "dim"}
MAX_COMMITS_SHOWN = 50


def _locations(f: Finding) -> Text:
    t = Text()
    seen = set()
    for loc in f.locations:
        key = (loc.path, loc.line)
        if key in seen:
            continue
        seen.add(key)
        sources = sorted({x.source for x in f.locations if (x.path, x.line) == key})
        t.append(f"{loc.path}:{loc.line}", style="cyan")
        if loc.note:
            t.append(f" ({loc.note})", style="magenta")
        t.append(f"  [{', '.join(sources)}]\n", style="dim")
    t.rstrip()
    return t


def _commits(f: Finding) -> Text:
    if not f.commits:
        return Text("none (not committed)", style="green")
    shas = sorted(f.commits)
    t = Text(" ".join(s[:10] for s in shas[:MAX_COMMITS_SHOWN]), style="yellow")
    if len(shas) > MAX_COMMITS_SHOWN:
        t.append(f"  … and {len(shas) - MAX_COMMITS_SHOWN} more (use --json for all)", style="dim")
    return t


def render_finding(f: Finding, index: int) -> Panel:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column()
    grid.add_row("Preview", Text(f.masked, style="bold"))
    grid.add_row("Found in", _locations(f))
    grid.add_row(f"Commits ({len(f.commits)})", _commits(f))
    grid.add_row("Branches/tags", Text(", ".join(f.branches) or "—", style="blue"))
    if f.provider.revoke_url:
        grid.add_row("Rotate at", Text(f.provider.revoke_url, style="underline"))
    title = Text.assemble(
        (f"#{index} ", "bold"),
        (f.provider.name, "bold"),
        "  ",
        (f"{f.confidence} confidence", CONF_STYLE[f.confidence]),
    )
    return Panel(grid, title=title, title_align="left", border_style=CONF_STYLE[f.confidence])


def render_findings(console: Console, findings: list[Finding]) -> None:
    console.print(Group(*(render_finding(f, i) for i, f in enumerate(findings, start=1))))


def summary_table(findings: list[Finding]) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", justify="right")
    table.add_column("Provider")
    table.add_column("Preview")
    table.add_column("Files")
    table.add_column("Commits", justify="right")
    for i, f in enumerate(findings, start=1):
        table.add_row(str(i), f.provider.name, f.masked, "\n".join(f.paths), str(len(f.commits)))
    return table
