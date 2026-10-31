"""Score fusion: findings -> 0-100 score, verdict, category, confidence.

Owner: Armaan. PROVISIONAL: this is the Phase 1 baseline
(35% rules + 30% worst URL + 35% text model, missing layers skipped).
Phase 2 replaces it with evidence-gated scoring (confirmed / heuristic / ml
tiers, corroboration before "phishing"); Phase 3 calibrates it on validation
data. The response shape stays the same.

Model layers report through findings too (tier "ml", confidence = probability),
so every point of the score belongs to a finding ("contribution").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .rules import Finding

WEIGHTS = {"rules": 0.35, "url": 0.30, "text": 0.35}
SAFE_BELOW = 35      # score < 35        -> safe
PHISHING_FROM = 70   # score >= 70       -> phishing; in between -> suspicious

CATEGORIES = ("impersonation", "urgency", "credential_harvesting", "suspicious_link", "financial_scam")

# Layer states reported in the response's "coverage".
RAN, UNAVAILABLE, FAILED, STUB = "ran", "unavailable", "failed", "stub"
DETECTION_LAYERS = ("rules", "anomaly", "url_model", "text_model")


@dataclass
class FusionResult:
    score: int
    verdict: str
    category: Optional[str]
    confidence: str
    contributions: Dict[int, float] = field(default_factory=dict)  # index into findings -> points


def verdict_for(score: int) -> str:
    if score >= PHISHING_FROM:
        return "phishing"
    return "suspicious" if score >= SAFE_BELOW else "safe"


def confidence_for(findings: List[Finding], coverage: Dict[str, str]) -> str:
    """high: every detection layer ran. medium: a layer is missing but a confirmed
    finding stands on its own. low: anything else - never a confident verdict on partial checks."""
    if all(coverage.get(layer) == RAN for layer in DETECTION_LAYERS):
        return "high"
    if any(f.tier == "confirmed" for f in findings):
        return "medium"
    return "low"


def fuse(findings: List[Finding], coverage: Dict[str, str]) -> FusionResult:
    rule_idx = [i for i, f in enumerate(findings) if f.tier != "ml"]
    url_idx = [i for i, f in enumerate(findings) if f.source == "url-model" and f.confidence is not None]
    text_idx = [i for i, f in enumerate(findings) if f.source == "text-model" and f.confidence is not None]

    # (layer weight, layer score 0-100, {finding index: share of the layer score})
    parts = []
    raw = sum(max(0, findings[i].weight) for i in rule_idx)
    rules_score = min(100, raw)
    parts.append((WEIGHTS["rules"], rules_score,
                  {i: max(0, findings[i].weight) * rules_score / raw for i in rule_idx} if raw else {}))
    for key, idx in (("url", url_idx), ("text", text_idx)):
        if idx:
            top = max(idx, key=lambda i: findings[i].confidence)
            s = 100 * findings[top].confidence
            parts.append((WEIGHTS[key], s, {top: s}))

    total_w = sum(w for w, _, _ in parts)
    contributions: Dict[int, float] = {}
    for w, _, shares in parts:
        for i, pts in shares.items():
            contributions[i] = contributions.get(i, 0.0) + w * pts / total_w
    score = round(sum(w * s for w, s, _ in parts) / total_w)

    top = max((i for i, f in enumerate(findings) if f.category), key=lambda i: contributions.get(i, 0), default=None)
    return FusionResult(score, verdict_for(score), findings[top].category if top is not None else None,
                        confidence_for(findings, coverage), contributions)
