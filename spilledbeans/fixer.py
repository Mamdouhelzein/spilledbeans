"""The guided ``beans fix`` flow.

Order matters: rotate -> plan -> backup -> dry run -> rewrite -> verify -> next steps -> prevent.

Hard safety rules enforced here:
* Never force-push (or push at all). Push commands are only printed.
* Never print, log, or write a full secret. Replacement rules are handed to
  git-filter-repo through anonymous pipes (/dev/fd/N), not files.
* No network requests.
* Refuse to run with uncommitted changes.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table

from . import gitutil, history, hooks, report, scanner
from .detectors import is_secret_file
from .providers import CONFIDENCE_ORDER, GITHUB_SENSITIVE_DATA_DOCS, LOW

REPLACEMENT = "***REMOVED-BY-SPILLEDBEANS***"


class FixAborted(Exception):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


@dataclass
class Plan:
    findings: list[scanner.Finding]
    remove_paths: list[str] = field(default_factory=list)

    @property
    def secrets(self) -> list[str]:
        return [f.secret for f in self.findings]

    @property
    def commits(self) -> set[str]:
        return set().union(*(f.commits for f in self.findings)) if self.findings else set()


# --------------------------------------------------------------------------- filter-repo


def _rules_text(secrets: list[str]) -> bytes:
    # Longest first so a secret that contains another is replaced whole.
    lines = [f"{s}==>{REPLACEMENT}" for s in sorted(set(secrets), key=len, reverse=True)]
    return ("\n".join(lines) + "\n").encode()


def masked_rules(plan: Plan) -> list[str]:
    return [f"{f.masked}  ==>  {REPLACEMENT}" for f in plan.findings]


def filter_repo_args(plan: Plan, replace_text: str, replace_message: str, dry_run: bool) -> list[str]:
    args = [
        "git",
        "filter-repo",
        "--force",
        "--replace-text",
        replace_text,
        "--replace-message",
        replace_message,
    ]
    if plan.remove_paths:
        for p in plan.remove_paths:
            args += ["--path", p]
        args.append("--invert-paths")
    if dry_run:
        args.append("--dry-run")
    return args


def run_filter_repo(root: Path, plan: Plan, dry_run: bool) -> subprocess.CompletedProcess:
    rules = _rules_text(plan.secrets)
    # A stale "already_ran" marker (>1 day old) makes filter-repo stop and ask on stdin.
    ran = gitutil.git_dir(root) / "filter-repo" / "already_ran"
    if ran.exists():
        ran.unlink()

    if os.name != "nt" and Path("/dev/fd").exists():
        fds = [os.pipe(), os.pipe()]

        def feed(w: int) -> None:
            try:
                os.write(w, rules)
            finally:
                os.close(w)

        threads = [threading.Thread(target=feed, args=(w,), daemon=True) for _r, w in fds]
        for t in threads:
            t.start()
        try:
            args = filter_repo_args(plan, f"/dev/fd/{fds[0][0]}", f"/dev/fd/{fds[1][0]}", dry_run)
            return subprocess.run(
                args,
                cwd=root,
                pass_fds=(fds[0][0], fds[1][0]),
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
        finally:
            for r, _w in fds:
                os.close(r)
            for t in threads:
                t.join(timeout=5)

    # Windows fallback: owner-only temp file, deleted immediately afterwards.
    fd, tmp = tempfile.mkstemp(prefix="beans-", suffix=".rules")
    try:
        os.write(fd, rules)
        os.close(fd)
        args = filter_repo_args(plan, tmp, tmp, dry_run)
        return subprocess.run(args, cwd=root, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    finally:
        try:
            Path(tmp).write_bytes(b"\0" * len(rules))
        finally:
            os.unlink(tmp)


def dry_run_summary(root: Path, plan: Plan) -> dict[str, int]:
    """Run filter-repo --dry-run and summarise the diff of the fast-export streams
    without ever printing their contents (the 'original' stream contains the secret)."""
    proc = run_filter_repo(root, plan, dry_run=True)
    if proc.returncode != 0:
        raise FixAborted(f"git filter-repo dry run failed:\n{proc.stderr.strip()}", 2)
    d = gitutil.git_dir(root) / "filter-repo"
    original = d / "fast-export.original"
    filtered = d / "fast-export.filtered"
    try:
        a = original.read_bytes().splitlines()
        b = filtered.read_bytes().splitlines()
        marker = REPLACEMENT.encode()
        return {
            "lines_replaced": sum(ln.count(marker) for ln in b) - sum(ln.count(marker) for ln in a),
            "file_entries_removed": max(
                0,
                sum(1 for ln in a if ln.startswith(b"M ")) - sum(1 for ln in b if ln.startswith(b"M ")),
            ),
            "commits": sum(1 for ln in a if ln.startswith(b"commit ")),
        }
    finally:
        for p in (original, filtered):
            if p.exists():
                p.unlink()


# --------------------------------------------------------------------------- the flow


class Fixer:
    def __init__(self, path: Path, console: Console | None = None):
        self.console = console or Console()
        self.path = Path(path)
        self.root: Path = self.path
        self.backup: Path | None = None
        self.remotes: dict[str, str] = {}

    # ---- helpers
    def step(self, n: int, title: str) -> None:
        self.console.print()
        self.console.print(Rule(f"[bold]Step {n}/8 · {title}[/bold]", align="left"))

    def ask(self, question: str, default: bool = False) -> bool:
        return Confirm.ask(question, default=default, console=self.console)

    # ---- preflight
    def preflight(self) -> list[scanner.Finding]:
        if not gitutil.is_git_repo(self.path):
            raise FixAborted(f"{self.path} is not a git repository.", 2)
        self.root = gitutil.repo_root(self.path)
        dirty = gitutil.uncommitted_changes(self.root)
        if dirty:
            listing = "\n".join(f"  {ln}" for ln in dirty[:10])
            raise FixAborted(
                "You have uncommitted changes. Commit or stash them first so nothing is lost "
                f"when history is rewritten:\n{listing}",
                2,
            )
        if not gitutil.filter_repo_available():
            raise FixAborted(gitutil.FILTER_REPO_INSTALL, 2)
        self.remotes = gitutil.remotes(self.root)

        with self.console.status("Scanning working tree and full history…"):
            findings = scanner.scan(self.root)
        committed = [f for f in findings if f.commits]
        uncommitted = [f for f in findings if not f.commits and CONFIDENCE_ORDER[f.confidence] > 0]
        if uncommitted:
            self.console.print(
                f"[yellow]{len(uncommitted)} secret(s) are in files that were never committed.[/yellow] "
                "History is fine for those; move them to environment variables before committing."
            )
        if not committed:
            raise FixAborted("No secrets found in git history. Nothing to rewrite. ✓", 0)
        return committed

    def select(self, findings: list[scanner.Finding]) -> list[scanner.Finding]:
        self.console.print(report.summary_table(findings))
        selected = [f for f in findings if f.confidence != LOW]
        low = [f for f in findings if f.confidence == LOW]
        for f in low:
            idx = findings.index(f) + 1
            if self.ask(
                f"#{idx} {f.masked} in {', '.join(f.paths)} is [dim]low confidence[/dim]. Treat it as a real secret?",
                default=False,
            ):
                selected.append(f)
        if not selected:
            raise FixAborted("Nothing selected. Exiting without changes.", 0)
        return selected

    # ---- step 1
    def rotate(self, findings: list[scanner.Finding]) -> None:
        self.step(1, "Rotate first")
        self.console.print(
            Panel(
                "Treat every key below as [bold red]compromised[/bold red]. Bots scrape public GitHub "
                "pushes within minutes, and rewriting history does not un-leak a key: anyone who "
                "already cloned, forked, or scraped it still has it.\n\n"
                "So rotate (revoke and replace) each key [bold]before[/bold] cleaning history.",
                border_style="red",
            )
        )
        for i, f in enumerate(findings, start=1):
            p = f.provider
            self.console.print(
                f"\n[bold]#{i} {p.name}[/bold]  [bold]{f.masked}[/bold]  ({', '.join(f.paths)})"
            )
            if p.revoke_url:
                self.console.print(f"  Revoke/rotate at: [underline cyan]{p.revoke_url}[/underline cyan]")
            self.console.print(f"  {p.rotate_help}")
            if not self.ask(f"  Have you revoked/rotated {f.masked}?", default=False):
                raise FixAborted(
                    "Stopping here. Rotate the key first, then run `beans fix` again. "
                    "Nothing has been changed.",
                    1,
                )

    # ---- step 2
    def plan(self, findings: list[scanner.Finding]) -> Plan:
        self.step(2, "Plan")
        plan = Plan(findings)
        secret_files = sorted({p for f in findings for p in f.paths if is_secret_file(p)})
        for path in secret_files:
            choice = Prompt.ask(
                f"[cyan]{path}[/cyan] looks like a credentials file. Remove the [bold]whole file[/bold] "
                "from history, or replace just the secret [bold]text[/bold]?",
                choices=["file", "text"],
                default="file",
                console=self.console,
            )
            if choice == "file":
                plan.remove_paths.append(path)

        table = Table(title="What will be rewritten", show_header=True, header_style="bold")
        table.add_column("Secret")
        table.add_column("Action")
        table.add_column("Files")
        table.add_column("Commits", justify="right")
        table.add_column("Branches/tags")
        for f in findings:
            removed = [p for p in f.paths if p in plan.remove_paths]
            action = f"replace with {REPLACEMENT}"
            if removed:
                action = "delete file(s) from history" + (
                    "" if removed == f.paths else " + replace elsewhere"
                )
            table.add_row(f.masked, action, "\n".join(f.paths), str(len(f.commits)), ", ".join(f.branches))
        self.console.print(table)
        self.console.print(
            f"[bold]{len(plan.commits)}[/bold] commit(s) contain these secrets. Every commit from the "
            "first affected one onward gets a new SHA. The same replacement is applied to commit messages."
        )
        if plan.remove_paths:
            self.console.print(
                "[yellow]Note:[/yellow] removed files also disappear from your working directory "
                "(a copy stays in the backup)."
            )
        return plan

    # ---- step 3
    def make_backup(self) -> Path:
        self.step(3, "Safety backup")
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        dest = self.root.parent / f"{self.root.name}-backup-{stamp}.git"
        gitutil.run(
            ["clone", "--mirror", "--no-hardlinks", "-q", str(self.root), str(dest)], self.root.parent
        )
        self.backup = dest
        self.console.print(f"Mirror backup created: [cyan]{dest}[/cyan]")
        self.console.print(
            "[dim]The backup still contains the secret. Delete it once you've confirmed the cleanup.[/dim]"
        )
        return dest

    # ---- step 4
    def dry_run(self, plan: Plan) -> None:
        self.step(4, "Dry run")
        shown = filter_repo_args(plan, "<rules via pipe>", "<rules via pipe>", dry_run=False)
        self.console.print("Command: [cyan]" + " ".join(shown) + "[/cyan]")
        self.console.print("Replacement rules (masked; the real rules never touch disk):")
        for rule in masked_rules(plan):
            self.console.print(f"  {rule}")
        for p in plan.remove_paths:
            self.console.print(f"  delete path from every commit: [cyan]{p}[/cyan]")
        with self.console.status("Running git filter-repo --dry-run…"):
            summary = dry_run_summary(self.root, plan)
        self.console.print(
            f"Dry run: {summary['commits']} commits processed, "
            f"{summary['lines_replaced']} secret occurrence(s) replaced in file contents, "
            f"{summary['file_entries_removed']} file version(s) removed."
        )
        answer = Prompt.ask(
            "\nThis rewrites history in place. Type [bold]yes[/bold] to proceed",
            console=self.console,
            default="",
        )
        if answer.strip().lower() != "yes":
            raise FixAborted(f"Aborted. History was not changed. (Backup kept at {self.backup})", 1)

    # ---- step 5
    def rewrite(self, plan: Plan) -> None:
        self.step(5, "Rewrite")
        with self.console.status("Rewriting history with git filter-repo…"):
            proc = run_filter_repo(self.root, plan, dry_run=False)
        if proc.returncode != 0:
            raise FixAborted(
                f"git filter-repo failed:\n{proc.stderr.strip()}\nYour backup is at {self.backup}", 2
            )
        self.console.print("[green]✓ History rewritten.[/green]")

    # ---- step 6
    def verify(self, plan: Plan) -> bool:
        self.step(6, "Verify")
        with self.console.status("Re-scanning every object in the repository…"):
            left = history.objects_containing(self.root, plan.secrets)
            still_paths = [
                p
                for p in plan.remove_paths
                if gitutil.out(["log", "--all", "--format=%H", "--", p], self.root).strip()
            ]
        ok = not left and not still_paths
        for f in plan.findings:
            if f.secret in left:
                self.console.print(f"[red]✗ {f.masked} is still present in the repository objects.[/red]")
            else:
                self.console.print(
                    f"[green]✓ {f.masked} no longer appears in any commit, blob or message.[/green]"
                )
        for p in still_paths:
            self.console.print(f"[red]✗ {p} still appears in history.[/red]")
        if not ok:
            self.console.print(f"[red]Verification failed.[/red] Your backup is at {self.backup}.")
        return ok

    # ---- step 7
    def next_steps(self, plan: Plan) -> None:
        self.step(7, "Next steps (spilledbeans will NOT run these for you)")
        lines = []
        current = gitutil.remotes(self.root)
        removed = {n: u for n, u in self.remotes.items() if n not in current}
        if removed:
            lines.append("# git-filter-repo removed these remotes as a safety measure; re-add them:")
            lines += [f"git remote add {n} {u}" for n, u in removed.items()]
        remote_names = list(self.remotes) or ["origin"]
        if not self.remotes:
            lines.append("# no remote configured; replace 'origin' with yours")
        for name in remote_names:
            lines.append(f"git push {name} --force --all")
            lines.append(f"git push {name} --force --tags")
        self.console.print("[bold cyan]Force-push when you're ready (copy these yourself):[/bold cyan]\n")
        for line in lines:
            self.console.print(
                "    " + line,
                soft_wrap=True,
                markup=False,
                highlight=False,
                style="dim" if line.startswith("#") else "bold",
            )
        self.console.print()
        gitignore = [p for p in plan.remove_paths] or [
            p for f in plan.findings for p in f.paths if is_secret_file(p)
        ]
        checklist = [
            "Confirm the key was rotated and check the provider's usage/audit logs for abuse.",
            "Temporarily allow force-push if the branch is protected, then re-protect it.",
            "Tell collaborators to re-clone (NOT pull/merge — that brings the old history back).",
            "Forks, other people's clones, and cached pull-request refs (refs/pull/*) may still contain "
            "the secret. GitHub Support can purge cached views and PR refs.",
            f"GitHub guide: {GITHUB_SENSITIVE_DATA_DOCS}",
        ]
        if gitignore:
            checklist.append("Add to .gitignore: " + ", ".join(sorted(set(gitignore))))
        if any(f.in_working_tree for f in plan.findings if not set(f.paths) <= set(plan.remove_paths)):
            checklist.append(
                f"Your code now contains the literal {REPLACEMENT}. Load the new key from an environment "
                "variable or secrets manager instead."
            )
        if self.backup:
            checklist.append(f"Delete the backup once you're happy (it still has the secret): {self.backup}")
        self.console.print("[bold]Checklist:[/bold]")
        for item in checklist:
            self.console.print(f"  [ ] {item}", soft_wrap=True, markup=False, highlight=False)

    # ---- step 8
    def prevent(self) -> None:
        self.step(8, "Prevent")
        if hooks.is_installed(self.root):
            self.console.print("The spilledbeans pre-commit hook is already installed. ✓")
            return
        if not self.ask("Install a pre-commit hook that blocks commits containing secrets?", default=True):
            self.console.print("Skipped. You can install it later with [cyan]beans hook install[/cyan].")
            return
        try:
            path = hooks.install(self.root)
            self.console.print(f"[green]✓ Installed[/green] {path}")
        except hooks.HookExists as e:
            self.console.print(
                f"[yellow]A different pre-commit hook already exists at {e}.[/yellow] "
                "Run [cyan]beans hook install --force[/cyan] to replace it (the old one is kept as a backup), "
                "or add `beans scan --staged` to it yourself."
            )

    # ---- orchestration
    def run(self) -> int:
        findings = self.preflight()
        self.console.print(f"\nFound [bold]{len(findings)}[/bold] secret(s) in git history.\n")
        selected = self.select(findings)
        self.rotate(selected)
        plan = self.plan(selected)
        self.make_backup()
        self.dry_run(plan)
        self.rewrite(plan)
        ok = self.verify(plan)
        self.next_steps(plan)
        self.prevent()
        return 0 if ok else 3


def run_fix(path: Path, console: Console | None = None) -> int:
    console = console or Console()
    try:
        return Fixer(path, console).run()
    except FixAborted as e:
        style = "green" if e.code == 0 else ("red" if e.code >= 2 else "yellow")
        console.print(f"\n[{style}]{e}[/{style}]")
        return e.code
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        return 130
    except gitutil.GitError as e:
        console.print(f"[red]git error:[/red] {e}")
        return 2


__all__ = ["run_fix", "Fixer", "Plan", "REPLACEMENT", "FixAborted"]
