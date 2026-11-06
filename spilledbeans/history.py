"""Scan every blob reachable from any ref, then work out which commits and branches
contain each secret.

Strategy (fast enough for real repos):
1. ``git rev-list --all --objects`` lists every reachable object once.
2. Blobs are read in one ``git cat-file --batch`` pass and scanned once each,
   no matter how many commits share them.
3. For flagged blobs only, commit trees are walked with memoisation by tree id, so
   unchanged subtrees shared across thousands of commits are visited once.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import detectors, gitutil

MAX_BLOB_BYTES = 5 * 1024 * 1024
_BATCH = 2000


@dataclass
class BlobHit:
    blob: str
    path: str
    match: detectors.RawMatch


@dataclass
class HistoryResult:
    hits: list[BlobHit] = field(default_factory=list)
    # blob sha -> {commit sha -> [paths]}
    blob_commits: dict[str, dict[str, set[str]]] = field(default_factory=dict)


def _list_blobs(root: Path) -> list[tuple[str, str]]:
    """(sha, path) for every reachable blob. Commits/trees have no path or are filtered later."""
    listing = gitutil.out(["rev-list", "--all", "--objects"], root)
    candidates = []
    for line in listing.splitlines():
        sha, _, path = line.partition(" ")
        if path:  # commits have no path; trees and blobs do
            candidates.append((sha, path))
    if not candidates:
        return []
    check = gitutil.run(
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        root,
        input=("\n".join(s for s, _ in candidates) + "\n").encode(),
    ).stdout.decode()
    kinds = {}
    for line in check.splitlines():
        parts = line.split()
        if len(parts) == 3:
            kinds[parts[0]] = (parts[1], int(parts[2]))
    return [
        (sha, path)
        for sha, path in candidates
        if kinds.get(sha, ("", 0))[0] == "blob" and kinds[sha][1] <= MAX_BLOB_BYTES
    ]


def scan_blobs(root: Path) -> list[BlobHit]:
    blobs = _list_blobs(root)
    hits: list[BlobHit] = []
    for i in range(0, len(blobs), _BATCH):
        chunk = blobs[i : i + _BATCH]
        objects = gitutil.read_objects(root, [s for s, _ in chunk])
        for sha, path in chunk:
            _typ, data = objects.get(sha, ("", b""))
            if not data or detectors.looks_binary(data):
                continue
            text = data.decode("utf-8", errors="replace")
            for m in detectors.detect_text(text, path):
                hits.append(BlobHit(sha, path, m))
    return hits


def _parse_tree(data: bytes, hash_len: int) -> list[tuple[bool, str, str]]:
    """Parse a raw tree object into (is_tree, sha, name) entries."""
    entries = []
    pos = 0
    while pos < len(data):
        sp = data.index(b" ", pos)
        nul = data.index(b"\0", sp)
        mode = data[pos:sp]
        name = data[sp + 1 : nul].decode("utf-8", errors="replace")
        sha = data[nul + 1 : nul + 1 + hash_len].hex()
        pos = nul + 1 + hash_len
        if mode == b"160000":  # submodule commit, not in this repo's object db
            continue
        entries.append((mode == b"40000", sha, name))
    return entries


def _load_trees(root: Path, top_trees: set[str]) -> dict[str, list[tuple[bool, str, str]]]:
    """Read every tree reachable from ``top_trees`` in level-by-level batches."""
    hash_len = len(next(iter(top_trees))) // 2
    trees: dict[str, list[tuple[bool, str, str]]] = {}
    frontier = set(top_trees)
    while frontier:
        batch = sorted(frontier)
        frontier = set()
        for i in range(0, len(batch), _BATCH):
            objects = gitutil.read_objects(root, batch[i : i + _BATCH])
            for sha, (_typ, data) in objects.items():
                entries = _parse_tree(data, hash_len)
                trees[sha] = entries
                frontier.update(s for is_tree, s, _ in entries if is_tree and s not in trees)
        frontier -= trees.keys()
    return trees


def map_commits(root: Path, flagged_blobs: set[str]) -> dict[str, dict[str, set[str]]]:
    """blob -> {commit -> paths} for every commit (on any ref) whose tree contains the blob."""
    result: dict[str, dict[str, set[str]]] = {b: {} for b in flagged_blobs}
    if not flagged_blobs:
        return result
    pairs = [
        ln.split()
        for ln in gitutil.out(["log", "--all", "--format=%H %T"], root).splitlines()
        if ln.strip()
    ]
    if not pairs:
        return result
    trees = _load_trees(root, {t for _, t in pairs})
    memo: dict[str, tuple[tuple[str, str], ...]] = {}

    def flagged_in(tree: str) -> tuple[tuple[str, str], ...]:
        if tree in memo:
            return memo[tree]
        found: list[tuple[str, str]] = []
        for is_tree, sha, name in trees.get(tree, []):
            if not is_tree and sha in flagged_blobs:
                found.append((name, sha))
            elif is_tree:
                found.extend((f"{name}/{p}", b) for p, b in flagged_in(sha))
        memo[tree] = tuple(found)
        return memo[tree]

    for commit, tree in pairs:
        for path, blob in flagged_in(tree):
            result[blob].setdefault(commit, set()).add(path)
    return result


def refs_containing(root: Path, commits: set[str]) -> list[str]:
    """Branch, remote-branch and tag names from which any of ``commits`` is reachable."""
    if not commits:
        return []
    names: set[str] = set()
    commit_list = sorted(commits)
    for i in range(0, len(commit_list), 200):
        args = ["for-each-ref", "--format=%(refname)"]
        for c in commit_list[i : i + 200]:
            args += ["--contains", c]
        args += ["refs/heads", "refs/remotes", "refs/tags"]
        for ref in gitutil.out(args, root).splitlines():
            if ref.endswith("/HEAD"):
                continue
            for prefix in ("refs/heads/", "refs/remotes/", "refs/"):
                if ref.startswith(prefix):
                    ref = ref[len(prefix) :]
                    break
            names.add(ref)
    return sorted(names)


def scan_history(root: Path) -> HistoryResult:
    if not gitutil.has_commits(root):
        return HistoryResult()
    hits = scan_blobs(root)
    blob_commits = map_commits(root, {h.blob for h in hits})
    return HistoryResult(hits=hits, blob_commits=blob_commits)
