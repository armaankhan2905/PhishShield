"""Score fusion: rule findings + model scores -> 0-100 score, verdict, category.

Owner: Armaan (Phase 2 tunes weights, Phase 3 plugs in Govind's models).
A layer whose score is None is left out and the remaining weights are
rescaled, so the API keeps working with rules alone.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from .rules import Finding

WEIGHTS = {"rules": 0.35, "url": 0.30, "text": 0.35}
SAFE_BELOW = 35      # score < 35        -> safe
PHISHING_FROM = 70   # score >= 70       -> phishing; in between -> suspicious

CATEGORIES = ("impersonation", "urgency", "credential_harvesting", "suspicious_link", "financial_scam")


@dataclass
class FusionResult:
    score: int
    verdict: str
    category: Optional[str]


def verdict_for(score: int) -> str:
    if score >= PHISHING_FROM:
        return "phishing"
    return "suspicious" if score >= SAFE_BELOW else "safe"


def rules_score(findings: Sequence[Finding]) -> int:
    return min(100, sum(max(0, f.weight) for f in findings))


def fuse(findings: List[Finding], url_scores: Optional[Sequence[float]] = None,
         text_score: Optional[float] = None) -> FusionResult:
    """url_scores and text_score are model probabilities in [0, 1], or None when unavailable."""
    parts = [(WEIGHTS["rules"], rules_score(findings))]
    if url_scores:
        parts.append((WEIGHTS["url"], 100 * max(url_scores)))
    if text_score is not None:
        parts.append((WEIGHTS["text"], 100 * text_score))
    score = round(sum(w * s for w, s in parts) / sum(w for w, _ in parts))
    top = max((f for f in findings if f.category), key=lambda f: f.weight, default=None)
    return FusionResult(score, verdict_for(score), top.category if top else None)
