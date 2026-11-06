# spilledbeans

**spilledbeans — remove a leaked API key from your git history, safely, in one guided command.**

*Spilled your API key on GitHub? Clean it up in one command.*

<!-- Demo: replace with an asciinema recording or GIF of `beans fix` -->
<p align="center"><em>[ demo GIF / asciinema goes here ]</em></p>

[![CI](https://github.com/Mamdouhelzein/spilledbeans/actions/workflows/ci.yml/badge.svg)](https://github.com/Mamdouhelzein/spilledbeans/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/spilledbeans)](https://pypi.org/project/spilledbeans/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

```bash
pipx install spilledbeans
```

---

## 🚨 Spilled a key? Do this right now

Committed an API key, token, or `.env` file to git, or pushed a secret to GitHub? Follow these steps in order:

1. **Revoke/rotate the key immediately.** Assume it's already stolen: bots scrape public GitHub pushes within minutes. Deleting the commit does **not** make the key safe. `beans fix` shows you the exact revoke page for each provider.
2. **Don't just delete the file in a new commit.** The secret stays in your git history, and anyone can still read it.
3. **Run the guided cleanup** from inside your repo:

   ```bash
   pipx install spilledbeans git-filter-repo
   cd your-repo
   beans fix
   ```

   It walks you through rotating, backs up your repo, removes the secret from **every commit on every branch**, verifies it's gone, and prints (but never runs) the force-push commands.
4. **Force-push, then tell collaborators to re-clone** (not pull).
5. **Check the provider's usage logs** for anything you didn't do.

---

## What it does

| Command | What it's for |
|---|---|
| `beans scan` | Find secrets in your working tree **and** full git history: every commit and branch that contains each one. |
| `beans fix` | Guided, step-by-step: rotate → plan → backup → dry run → rewrite → verify → next steps → prevent. |
| `beans hook install` | Pre-commit hook that blocks commits containing secrets. |
| `beans filter` | Cut the false positives out of Gitleaks / TruffleHog reports. |

Fully local. No network calls, no telemetry, no key validation requests.

## Install

```bash
pipx install spilledbeans
```

`beans fix` also needs [git-filter-repo](https://github.com/newren/git-filter-repo), the tool GitHub recommends for rewriting history. If it's missing, spilledbeans tells you the exact install command:

```bash
pipx install git-filter-repo        # any OS
brew install git-filter-repo        # macOS
sudo apt install git-filter-repo    # Debian/Ubuntu
```

Requires Python 3.10+ and git.

## Usage

### `beans scan`: where did it leak?

```bash
beans scan                 # current repo: working tree + entire history
beans scan path/to/repo
beans scan --staged        # only lines being added in staged changes (what the hook runs)
beans scan --json          # machine-readable
beans scan --no-history    # working tree only (fast)
```

```text
╭─ #1 GitHub token  high confidence ──────────────────────────────────────╮
│ Preview        ghp_…x9Qa                                                │
│ Found in       config.py:12  [history]                                  │
│ Commits (14)   3f9a1c02de 7be01c44a1 …                                  │
│ Branches/tags  main, feature/deploy, v1.2.0                             │
│ Rotate at      https://github.com/settings/tokens                       │
╰─────────────────────────────────────────────────────────────────────────╯
```

Secrets are only ever shown masked (first 4 + last 4 characters). The full value is never printed, logged, or written to disk.

**Detects** (provider-specific formats first, high confidence):
OpenAI · Anthropic · AWS access keys (and secret keys next to `aws_secret_access_key`) · GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) · Hugging Face (`hf_`) · Stripe · Slack tokens & webhooks · Google API keys

Also:
- values in committed `.env` files (medium confidence),
- secrets inside **Jupyter notebook outputs** (reported as `notebook cell 3 output`),
- a generic fallback for high-entropy strings assigned to names like `*_key`, `*secret*`, `*token*`, `*password*`, flagged **low confidence**.

Exit code is `1` if a medium/high-confidence secret is found, `0` otherwise (low-confidence findings alone don't fail). False positive? Put `beans:ignore` in a comment on that line.

### `beans fix`: clean it up

```bash
cd your-repo
beans fix
```

1. **Rotate first.** For each key: the provider's revoke page and plain instructions. It waits until you confirm you've rotated.
2. **Plan.** Exactly which secrets, files, commits and branches will be rewritten. For credential files like `.env` it asks whether to delete the whole file from history or just replace the secret text.
3. **Safety backup.** A full `git clone --mirror` into a sibling folder (`your-repo-backup-<timestamp>.git`) before anything changes.
4. **Dry run.** Runs `git filter-repo --dry-run` and shows what will change. You must type `yes` to continue.
5. **Rewrite.** `git filter-repo --replace-text` swaps the secret for `***REMOVED-BY-SPILLEDBEANS***` in every file and commit message (or `--invert-paths` to drop a whole file).
6. **Verify.** Re-scans *every object* in `.git`, reachable or not, to confirm the secret is gone.
7. **Next steps.** Prints the force-push commands and a checklist. **It never pushes.**
8. **Prevent.** Offers to install the pre-commit hook.

Safety rules that are tested:
- never pushes (tests intercept every subprocess call and assert no `git push`),
- never prints or writes the full secret: replacement rules reach git-filter-repo through an in-memory pipe (on Windows, a short-lived owner-only temp file that is overwritten and deleted immediately),
- no network requests,
- refuses to run with uncommitted changes.

### `beans hook`: stop it happening again

```bash
beans hook install      # .git/hooks/pre-commit runs `beans scan --staged`
beans hook uninstall
```

It respects `core.hooksPath` and won't overwrite an existing hook unless you pass `--force` (the old one is backed up and restored on uninstall). Using the [pre-commit](https://pre-commit.com) framework instead:

```yaml
repos:
  - repo: https://github.com/Mamdouhelzein/spilledbeans
    rev: v0.1.0
    hooks:
      - id: spilledbeans
```

### `beans filter`: fewer false positives from Gitleaks / TruffleHog

```bash
gitleaks detect --report-format json --report-path leaks.json
beans filter leaks.json              # only the likely-real findings
beans filter leaks.json --show-all   # every finding, with score and reasons
beans filter leaks.json --json       # for CI; secrets are masked in the output

trufflehog git file://. --json > th.json
beans filter th.json                 # format is auto-detected
```

Each finding is scored 0–1 from features such as entropy, length, a known provider prefix, whether it looks like a UUID/hash/commit SHA, repeated characters, a `test`/`example`/`dummy`/`fake` variable name, and paths like `tests/`, `docs/`, `examples/`, `fixtures/` or lockfiles. TruffleHog-verified secrets always count as real. Every score comes with its reasons.

**Help build a better filter:** `beans filter leaks.json --label` lets you mark findings as real or noise and saves them to `spilledbeans-labels.csv`. The CSV holds only features and labels, **never the secrets**, so it can train the planned ML scorer (`ModelScorer`) in v2.

## Why not just use Gitleaks / TruffleHog?

Use them! spilledbeans works **with** them, not instead of them.

- **They detect.** Gitleaks and TruffleHog are excellent, battle-tested scanners with hundreds of rules.
- **spilledbeans fixes.** Finding the leak is the easy part. Rotating, rewriting history without breaking your repo, verifying, and knowing what to do about forks and collaborators is where people get stuck. `beans fix` handles that part.
- **spilledbeans filters.** Pipe their JSON into `beans filter` to cut the noise.

`beans scan` covers the most common providers so `beans fix` works on its own, but for broad detection in CI, run a dedicated scanner.

## Honest limitations

- **It can't undo a leak.** If the key was public, even for seconds, assume it's compromised. Rotation is the fix; history cleanup is hygiene.
- **It can't clean other copies.** Forks, other people's clones, CI caches, and GitHub's cached views and pull-request refs (`refs/pull/*`) may still contain the secret. GitHub Support can purge cached data. See GitHub's guide: [Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
- **Rotation is manual** for most providers. spilledbeans links you to the right page but can't rotate for you, and by design it never contacts provider APIs.
- **Rewriting history changes commit SHAs.** Everyone has to re-clone, and open pull requests will need rebuilding.
- **Detection isn't exhaustive.** Provider patterns cover the common cases; the generic fallback is deliberately conservative.
- The backup made by `beans fix` still contains the secret. Delete it once you've verified the cleanup.

## FAQ

**How do I remove an API key from git history?**
Rotate the key first, then run `beans fix`. It uses git-filter-repo to rewrite every commit on every branch and tag, then verifies the key is gone.

**I leaked a secret on GitHub. What do I do?**
See [Spilled a key? Do this right now](#-spilled-a-key-do-this-right-now). Rotate first, clean history second, force-push third.

**I removed the key in a new commit. Am I safe?**
No. It's still in the earlier commit. `beans scan` will show you which commits and branches still contain it.

**I committed my `.env` file.**
`beans fix` will offer to remove the whole file from history. Then add it to `.gitignore` and install the hook.

**Does it work with BFG Repo-Cleaner?**
spilledbeans uses git-filter-repo instead. git's own documentation recommends it over `git filter-branch`, and GitHub's sensitive-data guide uses it.

## Development

```bash
git clone https://github.com/Mamdouhelzein/spilledbeans
cd spilledbeans
pip install -e ".[dev]" git-filter-repo
pytest
ruff check . && ruff format --check .
```

Tests build throwaway git repos, commit obviously fake keys (e.g. `ghp_EXAMPLE000…`), run the real `scan`/`fix` flow, and assert the secret is gone from history.

## License

MIT
