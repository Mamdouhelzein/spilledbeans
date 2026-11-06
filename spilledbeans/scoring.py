"""Scorers turn a feature dict into a likely-real probability.

``RuleScorer`` is a transparent, hand-tuned baseline (v1). ``ModelScorer`` is the
v2 slot: train a scikit-learn classifier on the CSV produced by
``beans filter --label`` using ``features.FEATURE_NAMES`` as columns, and it plugs
in here with the same interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from . import features as feat


@dataclass
class Score:
    score: float  # 0 = certainly noise, 1 = certainly real
    reasons: list[str] = field(default_factory=list)

    def likely_real(self, threshold: float) -> bool:
        return self.score >= threshold


class Scorer(Protocol):
    name: str

    def score(self, features: dict[str, float]) -> Score: ...


class RuleScorer:
    name = "rules-v1"

    # (feature check, weight, reason). Applied additively to a 0.5 prior.
    def score(self, f: dict[str, float]) -> Score:
        if f["verified"] == 1:
            return Score(0.99, ["verified live by the scanner"])

        s = 0.5
        reasons: list[str] = []

        def adj(delta: float, why: str) -> None:
            nonlocal s
            s += delta
            reasons.append(f"{'+' if delta > 0 else '−'}{abs(delta):.2f} {why}")

        if f["provider_prefix"]:
            adj(0.35, "matches a known provider key format")
        if f["verified"] == 0:
            adj(-0.15, "scanner tried to verify it and it was not live")
        if f["entropy"] >= 4.0:
            adj(0.10, "high entropy")
        elif f["entropy"] < 3.0:
            adj(-0.25, "low entropy")
        if f["length"] < 12:
            adj(-0.20, "short value")
        if f["is_placeholder"]:
            adj(-0.50, "looks like a placeholder")
        if (f["looks_uuid"] or f["looks_hash"]) and not f["provider_prefix"]:
            adj(-0.35, "looks like a UUID/hash/commit SHA")
        if f["repeat_ratio"] > 0.3:
            adj(-0.30, "long run of repeated characters")
        elif f["length"] >= 16 and f["unique_ratio"] < 0.25:
            adj(-0.15, "few distinct characters")
        if f["secret_has_test_word"]:
            adj(-0.30, "value contains example/test/dummy/fake")
        if f["var_has_test_word"]:
            adj(-0.25, "variable name suggests test/example data")
        if f["path_in_test_dir"]:
            adj(-0.20, "in a tests/docs/examples/fixtures path")
        if f["path_is_lockfile"]:
            adj(-0.40, "in a lockfile (integrity hashes)")
        elif f["path_is_doc"]:
            adj(-0.10, "in a documentation file")
        return Score(round(min(1.0, max(0.0, s)), 3), reasons)


class ModelScorer:
    """v2: a trained classifier over ``features.FEATURE_NAMES``.

    Expected usage once trained::

        scorer = ModelScorer.load("model.joblib")   # any object with predict_proba
        scorer.score(features)
    """

    name = "model"

    def __init__(self, model) -> None:
        self.model = model

    @classmethod
    def load(cls, path: str | Path) -> ModelScorer:
        raise NotImplementedError(
            "ModelScorer is planned for v2. Collect labels with `beans filter --label` first."
        )

    def score(self, features: dict[str, float]) -> Score:
        proba = self.model.predict_proba([feat.to_vector(features)])[0][1]
        return Score(round(float(proba), 3), [f"model probability {proba:.2f}"])


DEFAULT_THRESHOLD = 0.5


def get_scorer(name: str = "rules") -> Scorer:
    if name in ("rules", RuleScorer.name):
        return RuleScorer()
    raise ValueError(f"unknown scorer {name!r}")
