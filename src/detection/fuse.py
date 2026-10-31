"""Evidence-gated scoring: findings -> 0-100 score, verdict, category, confidence.

Owner: Armaan. Deterministic and explainable: every point of the score belongs
to a finding ("contribution"), and every number below is a named constant.

  1. Points. Confirmed findings count in full. Heuristics count once per label
     and are capped per family, so repeating "urgent" five times adds nothing.
     Model findings add 0 below their floor (URL_FLOOR / TEXT_FLOOR), rising to ML_MAX at p=1.
  2. Gates. "phishing" needs a confirmed finding, or a confident model backed by
     a heuristic from another family. Heuristics alone stop at HEURISTIC_ONLY_CAP,
     and just under SAFE_BELOW when the message gives you nothing to act on (no link,
     phone number or app to install).
  3. Consistency. When every link and the sender belong to the brand the
     message names, heuristic points are halved. When an email's sender and every
     link belong to one organisation and the email asks for nothing (no details,
     payment, login, call or app), model points count at FIRST_PARTY_ML_FACTOR:
     both models over-flag ordinary newsletters and sign-in emails, and the phishing
     they exist to catch sends you somewhere other than the sender. Confirmed
     evidence is never discounted, and nothing is ever declared safe by domain alone.
  4. Confidence. Missing layers lower confidence; they never count as safety.

Model-related values and SAFE_BELOW are tuned on validation data (see below); the
heuristic weights and caps are hand-set and still provisional.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .rules import Finding

# SAFE_BELOW, ML_MAX, URL_FLOOR and TEXT_FLOOR were chosen on the validation split by
# `python -m src.eval.phish_bench --tune` (record: data/calibration.json). Re-run it after retraining.
SAFE_BELOW = 30      # score < 30        -> safe
PHISHING_FROM = 70   # score >= 70       -> phishing; in between -> suspicious

FAMILY_CAPS = {"content": 40, "link": 25, "sender": 25}  # heuristic points per family
ML_MAX = 45                    # points per model at p = 1.0
URL_FLOOR = 0.7                # URL model adds points only above this calibrated probability
TEXT_FLOOR = 0.5               # same for the text model
ML_CONFIDENT = 0.8             # model probability that can stand in for a confirmed finding
HEURISTIC_ONLY_CAP = 60
CONSISTENT_DISCOUNT = 0.5
FIRST_PARTY_ML_FACTOR = 0.25   # model points in a sender-consistent email that asks for nothing
# Messages with nothing to act on (no link, number, app or payment) always stay just under SAFE_BELOW.

CATEGORIES = ("impersonation", "urgency", "credential_harvesting", "suspicious_link", "financial_scam")

# Layer states reported in the response's "coverage".
RAN, UNAVAILABLE, FAILED, STUB = "ran", "unavailable", "failed", "stub"
DETECTION_LAYERS = ("rules", "anomaly", "url_model", "text_model")


@dataclass
class Context:
    actionable: bool = True          # the message gives a way to act: link, phone number, app
    identity_consistent: bool = False  # every link and the sender belong to the brand it names
    first_party: bool = False        # email whose sender owns every link, asking for nothing


@dataclass
class FusionResult:
    score: int
    verdict: str
    category: Optional[str]
    confidence: str
    contributions: Dict[int, float] = field(default_factory=dict)  # index into findings -> points
    gate: Optional[str] = None       # which cap applied, for the explanation and debugging


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


def ml_floor(source: str) -> float:
    return URL_FLOOR if source == "url-model" else TEXT_FLOOR


def _ml_points(p: Optional[float], floor: float) -> float:
    return 0.0 if p is None or p < floor else ML_MAX * (p - floor) / max(1e-9, 1 - floor)


def fuse(findings: List[Finding], coverage: Dict[str, str], context: Optional[Context] = None) -> FusionResult:
    ctx = context or Context()
    raw: Dict[int, float] = {}

    # Confirmed: full weight, once per (label, evidence).
    seen = set()
    for i, f in enumerate(findings):
        if f.tier == "confirmed" and (f.label, f.text) not in seen:
            seen.add((f.label, f.text))
            raw[i] = float(f.weight)

    # Heuristics: once per label, strongest instance, capped per family.
    best: Dict[str, int] = {}
    for i, f in enumerate(findings):
        if f.tier == "heuristic" and (f.label not in best or f.weight > findings[best[f.label]].weight):
            best[f.label] = i
    by_family: Dict[str, List[int]] = {}
    for i in best.values():
        by_family.setdefault(findings[i].family, []).append(i)
    discount = CONSISTENT_DISCOUNT if ctx.identity_consistent else 1.0
    for fam, idx in by_family.items():
        total = sum(findings[i].weight for i in idx)
        scale = min(1.0, FAMILY_CAPS.get(fam, 25) / total) if total else 0
        for i in idx:
            raw[i] = findings[i].weight * scale * discount

    # Models: strongest finding per model.
    for source in ("url-model", "text-model"):
        idx = [i for i, f in enumerate(findings) if f.tier == "ml" and f.source == source]
        if idx:
            top = max(idx, key=lambda i: findings[i].confidence or 0)
            raw[top] = _ml_points(findings[top].confidence, ml_floor(source)) * (FIRST_PARTY_ML_FACTOR if ctx.first_party else 1.0)

    total = sum(raw.values())
    confirmed = any(findings[i].tier == "confirmed" and pts > 0 for i, pts in raw.items())
    ml_conf = [findings[i] for i, pts in raw.items() if findings[i].tier == "ml" and (findings[i].confidence or 0) >= ML_CONFIDENT]
    heur_fams = {findings[i].family for i, pts in raw.items() if findings[i].tier == "heuristic" and pts > 0}
    any_ml = any(findings[i].tier == "ml" and pts > 0 for i, pts in raw.items())

    cap, gate = 100.0, None
    if not confirmed:
        if not ctx.actionable:
            cap, gate = SAFE_BELOW - 1, "nothing_to_act_on"   # applies whatever the models say
        elif ml_conf and heur_fams:
            cap, gate = 100.0, None
        elif any_ml:
            cap, gate = PHISHING_FROM - 1, "no_corroboration"
        else:
            cap, gate = HEURISTIC_ONLY_CAP, "heuristics_only"
    score = round(min(total, cap, 100.0))
    if total > score > 0:
        factor = score / total
        raw = {i: pts * factor for i, pts in raw.items()}
    elif score == 0:
        raw = {i: 0.0 for i in raw}
    if gate and total <= cap:
        gate = None

    by_cat: Dict[str, float] = {}
    for i, pts in raw.items():
        if findings[i].category and pts > 0:
            by_cat[findings[i].category] = by_cat.get(findings[i].category, 0) + pts
    category = max(by_cat, key=by_cat.get) if by_cat else None
    return FusionResult(score, verdict_for(score), category, confidence_for(findings, coverage), raw, gate)
