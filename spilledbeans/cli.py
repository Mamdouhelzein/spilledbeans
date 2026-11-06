"""spilledbeans command-line interface (``beans``)."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from . import __version__, gitutil, report, scanner

app = typer.Typer(
    name="beans",
    help="Spilled your API key on GitHub? Clean it up in one command.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()
err = Console(stderr=True)


def _version(value: bool) -> None:
    if value:
        console.print(f"spilledbeans {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show version."),
) -> None:
    """Find leaked secrets, rotate them, scrub them from git history, and stop it happening again."""


@app.command()
def scan(
    path: Path = typer.Argument(
        Path("."), exists=True, file_okay=False, help="Repository or folder to scan."
    ),
    staged: bool = typer.Option(
        False, "--staged", help="Scan only staged changes (used by the pre-commit hook)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
    no_history: bool = typer.Option(
        False, "--no-history", help="Skip git history; scan the working tree only."
    ),
) -> None:
    """Scan the working tree AND full git history for secrets.

    Exit code 1 if any medium/high-confidence secret is found, 0 otherwise.
    """
    try:
        with console.status("Scanning…", spinner="dots") if not as_json else _nullctx():
            findings = scanner.scan(path, include_history=not no_history, staged=staged)
    except gitutil.GitError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(2) from e

    blocking = scanner.fail_worthy(findings)
    if as_json:
        print(json.dumps({"findings": [f.to_dict() for f in findings]}, indent=2))
        raise typer.Exit(1 if blocking else 0)

    if not findings:
        console.print("[bold green]✓ No secrets found.[/bold green]")
        raise typer.Exit(0)

    report.render_findings(console, findings)
    low = len(findings) - len(blocking)
    console.print(
        f"\n[bold]{len(findings)} secret(s) found[/bold]"
        + (f" ([dim]{low} low-confidence[/dim])" if low else "")
    )
    if staged:
        if blocking:
            console.print(
                "\n[bold red]Commit blocked by spilledbeans.[/bold red] Remove the secret(s) above from "
                "your staged changes (use an environment variable instead).\n"
                "False positive? Add [cyan]beans:ignore[/cyan] in a comment on that line, or bypass once "
                "with [cyan]git commit --no-verify[/cyan]."
            )
        else:
            console.print("[dim]Only low-confidence findings; commit allowed.[/dim]")
    elif any(f.commits for f in blocking):
        console.print("\nRun [bold cyan]beans fix[/bold cyan] to rotate and scrub these from history.")
    raise typer.Exit(1 if blocking else 0)


class _nullctx:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@app.command()
def fix(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, help="Repository to clean."),
) -> None:
    """Guided cleanup: rotate → plan → backup → dry run → rewrite → verify → next steps → prevent.

    Never pushes. Never prints a full secret. Refuses to run with uncommitted changes.
    """
    from .fixer import run_fix

    raise typer.Exit(run_fix(path, console))


hook_app = typer.Typer(help="Manage the pre-commit hook that blocks commits containing secrets.")
app.add_typer(hook_app, name="hook")


@hook_app.command("install")
def hook_install(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False),
    force: bool = typer.Option(
        False, "--force", help="Replace an existing pre-commit hook (kept as a backup)."
    ),
) -> None:
    """Install a git pre-commit hook that runs `beans scan --staged`."""
    from . import hooks

    if not gitutil.is_git_repo(path):
        err.print(f"[red]error:[/red] {path} is not a git repository")
        raise typer.Exit(2)
    try:
        hook_path = hooks.install(gitutil.repo_root(path), force=force)
    except hooks.HookExists as e:
        err.print(
            f"[yellow]A pre-commit hook already exists at {e}.[/yellow] Re-run with --force to replace it "
            "(the old hook is saved as pre-commit.before-spilledbeans)."
        )
        raise typer.Exit(1) from e
    console.print(f"[green]✓ Installed pre-commit hook:[/green] {hook_path}")


@hook_app.command("uninstall")
def hook_uninstall(path: Path = typer.Argument(Path("."), exists=True, file_okay=False)) -> None:
    """Remove the spilledbeans pre-commit hook (restores any hook it replaced)."""
    from . import hooks

    if hooks.uninstall(gitutil.repo_root(path)):
        console.print("[green]✓ Removed the spilledbeans pre-commit hook.[/green]")
    else:
        console.print("No spilledbeans hook installed.")


@app.command("filter")
def filter_cmd(
    file: str = typer.Argument(
        ..., metavar="FILE", help="Gitleaks or TruffleHog JSON report ('-' for stdin)."
    ),
    show_all: bool = typer.Option(
        False, "--show-all", help="Show every finding with its score, not just likely-real ones."
    ),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output (secrets masked)."),
    threshold: float = typer.Option(
        0.5, "--threshold", min=0.0, max=1.0, help="Score at or above which a finding counts as likely real."
    ),
    label_mode: bool = typer.Option(
        False, "--label", help="Interactively mark findings real/noise and save to a CSV."
    ),
    labels_file: Path = typer.Option(
        Path("spilledbeans-labels.csv"), "--labels-file", help="CSV for --label (no secrets are written)."
    ),
) -> None:
    """Filter false positives out of Gitleaks/TruffleHog output (format auto-detected).

    Exit code 1 if any likely-real finding remains, 0 otherwise.
    """
    import sys

    from . import filtering, importers, scoring

    try:
        text = sys.stdin.read() if file == "-" else Path(file).read_text(encoding="utf-8")
    except OSError as e:
        err.print(f"[red]error:[/red] can't read {file}: {e}")
        raise typer.Exit(2) from e
    try:
        fmt, findings = importers.parse(text)
    except importers.UnknownFormat as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(2) from e

    items = filtering.score_all(findings, scoring.RuleScorer())

    if label_mode:
        labelled, skipped = filtering.label(items, labels_file, console)
        console.print(f"\nSaved {labelled} label(s) to [cyan]{labels_file}[/cyan] ({skipped} skipped).")
        raise typer.Exit(0)

    real = [s for s in items if s.result.likely_real(threshold)]
    shown = items if show_all else real
    if as_json:
        print(
            json.dumps(
                {
                    "format": fmt,
                    "total": len(items),
                    "likely_real": len(real),
                    "findings": [s.to_dict(threshold) for s in shown],
                },
                indent=2,
            )
        )
        raise typer.Exit(1 if real else 0)

    console.print(f"Read [bold]{len(items)}[/bold] {fmt} finding(s).")
    if shown:
        console.print(filtering.table(shown, threshold, show_all))
    console.print(
        f"[bold]{len(real)}[/bold] likely real, [green]{len(items) - len(real)}[/green] likely noise "
        f"(threshold {threshold:.2f})." + ("" if show_all else " Use --show-all to see everything.")
    )
    raise typer.Exit(1 if real else 0)
