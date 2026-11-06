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
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, help="Repository or folder to scan."),
    staged: bool = typer.Option(False, "--staged", help="Scan only staged changes (used by the pre-commit hook)."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
    no_history: bool = typer.Option(False, "--no-history", help="Skip git history; scan the working tree only."),
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
