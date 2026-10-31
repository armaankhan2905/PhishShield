"""Analyze pipeline behind POST /api/analyze (contract: doc/API.md).

  message -> extract URLs -> rules + anomaly checks (+ models, Phase 3)
          -> fuse() -> sanitize() -> explanation

The original text is never modified: findings point into it, and only a
separate sanitized copy goes on to the explanation step. A layer that did not
run is reported in "coverage" and lowers "confidence"; it is never read as
evidence of safety.

While src.detection.rules.READY is False the findings come from
src/pipeline/stub.py and the response carries "stub": true.

Run:
    python -m src.pipeline.analyze "URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz"
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import uuid
from typing import Dict, List, Optional

from src.detection import anomaly, rules
from src.detection.fuse import FAILED, RAN, STUB, UNAVAILABLE, fuse
from src.detection.main import URL_RX, URL_TRAILING
from src.pipeline import stub
from src.pipeline.sanitize import SanitizationError, sanitize

logger = logging.getLogger(__name__)

KINDS = ("auto", "email", "sms", "url")
MODES = ("local", "hosted")
MAX_URLS = 50
_LONE_URL = re.compile(r"\s*(?:https?://|www\.)?[\w-]+(?:\.[\w-]+)+(?:[/?#]\S*)?\s*", re.I)


def mode() -> str:
    """local: the server runs on the user's machine. hosted: messages are sent to a remote server."""
    m = os.environ.get("PHISHSHIELD_MODE", "local").lower()
    return m if m in MODES else "local"


def detect_kind(text: str, email: Optional[dict]) -> str:
    if email:
        return "email"
    if _LONE_URL.fullmatch(text) and " " not in text.strip():
        return "url"
    return "sms"


def extract_urls(text: str, kind: str, links: List[dict]) -> List[str]:
    found = [text.strip()] if kind == "url" else [m.group(0).rstrip(URL_TRAILING) for m in URL_RX.finditer(text)]
    found += [link.get("href", "") for link in links]
    seen, out = set(), []
    for u in found:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out[:MAX_URLS]


def utf16_index(text: str, i: Optional[int]) -> Optional[int]:
    """Python indexes code points; JavaScript strings index UTF-16 units (emoji count twice)."""
    return None if i is None else len(text[:i].encode("utf-16-le")) // 2


def explain(verdict: str, score: int, ranked: List[rules.Finding], confidence: str) -> str:
    """Template explanation built only from findings. Phase 5 (Ryan) adds the grounded local LLM."""
    reasons = []
    for f in ranked:
        r = f.reason.removeprefix("[stub] ")
        if r not in reasons:
            reasons.append(r)
    if not reasons:
        text = "No phishing signals were found in this message."
    else:
        text = f"Rated {verdict} ({score}/100). Main reasons: " + "; ".join(reasons[:3]) + "."
    if confidence == "low":
        text += " Some checks were not available, so treat this result with caution."
    return text


def _layer(name: str, coverage: Dict[str, str], fn, *args):
    try:
        out = fn(*args)
        coverage[name] = RAN
        return out
    except Exception:  # noqa: BLE001 - one broken layer must not take the analysis down
        logger.exception("%s layer failed", name)
        coverage[name] = FAILED
        return []


def analyze(text: str, kind: str = "auto", email: Optional[dict] = None,
            links: Optional[List[dict]] = None) -> dict:
    t0 = time.perf_counter()
    links = links or []
    if kind == "auto":
        kind = detect_kind(text, email)
    urls = extract_urls(text, kind, links)
    coverage = {"rules": UNAVAILABLE, "anomaly": UNAVAILABLE, "url_model": UNAVAILABLE, "text_model": UNAVAILABLE}

    if rules.READY:
        findings = _layer("rules", coverage, rules.analyze_rules, text)
        findings += _layer("anomaly", coverage, anomaly.check_email, email, links)
        url_rows = [{"url": u, "score": None, "flags": rules.analyze_url(u)} for u in urls]
        # Phase 3: Govind's URL and text models add tier "ml" findings and set their coverage to "ran".
    else:
        findings = stub.findings(text)
        coverage["rules"] = STUB
        url_rows = []
        for u in urls:
            f, flags = stub.url_finding(text, u)
            findings.append(f)
            url_rows.append({"url": u, "score": f.confidence, "flags": flags})
        if urls:
            coverage["url_model"] = STUB

    findings.sort(key=lambda f: (f.start is None, f.start or 0))
    result = fuse(findings, coverage)

    out_findings = []
    for i, f in enumerate(findings):
        d = f.to_dict()
        d.update(id=f"f{i + 1}", contribution=round(result.contributions.get(i, 0.0), 1),
                 start_u16=utf16_index(text, f.start), end_u16=utf16_index(text, f.end))
        out_findings.append(d)

    partial = any(state == FAILED for state in coverage.values())
    try:
        sanitized = sanitize(text).sanitized if text.strip() else ""
    except SanitizationError:
        sanitized, partial = None, True  # fail closed: never echo raw text as "sanitized"

    ranked = [findings[i] for i in sorted(result.contributions, key=lambda i: -result.contributions[i])
              if result.contributions[i] > 0]
    return {
        "analysis_id": uuid.uuid4().hex,
        "score": result.score,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "category": result.category,
        "kind": kind,
        "findings": out_findings,
        "urls": url_rows,
        "coverage": coverage,
        "explanation": explain(result.verdict, result.score, ranked, result.confidence),
        "explanation_source": "template",
        "sanitized": sanitized,
        "partial": partial,
        "stub": not rules.READY,
        "mode": mode(),
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
    }


def main() -> None:
    text = " ".join(sys.argv[1:]) or "URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz/login"
    print(json.dumps(analyze(text), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
