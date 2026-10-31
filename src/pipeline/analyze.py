"""Analyze pipeline behind POST /api/analyze (contract: doc/API.md).

  message -> extract URLs -> rules + anomaly checks (+ models, Phase 3)
          -> fuse() -> sanitize() -> explanation

While src.detection.rules.READY is False the findings come from
src/pipeline/stub.py and the response carries "stub": true.

Run:
    python -m src.pipeline.analyze "URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz"
"""
from __future__ import annotations

import json
import re
import sys
import time
from typing import List, Optional

from src.detection import anomaly, rules
from src.detection.fuse import fuse
from src.detection.main import URL_RX, URL_TRAILING
from src.pipeline import stub
from src.pipeline.sanitize import SanitizationError, sanitize

KINDS = ("auto", "email", "sms", "url")
MAX_URLS = 50
_LONE_URL = re.compile(r"\s*(?:https?://|www\.)?[\w-]+(?:\.[\w-]+)+(?:[/?#]\S*)?\s*", re.I)


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


def explain(verdict: str, score: int, findings: List[rules.Finding]) -> str:
    """Template explanation. Phase 3 (Ryan): replaced by the local LLM in explain.py."""
    if not findings:
        return "No phishing signals were found in this message."
    reasons = []
    for f in sorted(findings, key=lambda f: -f.weight):
        r = f.reason.removeprefix("[stub] ")
        if r not in reasons:
            reasons.append(r)
    return f"Rated {verdict} ({score}/100). Main reasons: " + "; ".join(reasons[:3]) + "."


def analyze(text: str, kind: str = "auto", email: Optional[dict] = None,
            links: Optional[List[dict]] = None) -> dict:
    t0 = time.perf_counter()
    links = links or []
    if kind == "auto":
        kind = detect_kind(text, email)
    urls = extract_urls(text, kind, links)

    if rules.READY:
        findings = rules.analyze_rules(text) + anomaly.check_email(email, links)
        url_rows = [{"url": u, "score": None, "flags": rules.analyze_url(u)} for u in urls]
        url_scores = None  # Phase 3: Govind's URL model
    else:
        findings = stub.findings(text)
        url_rows = []
        for u in urls:
            flags = stub.url_flags(u)
            url_rows.append({"url": u, "score": round(stub.url_score(flags), 2), "flags": flags})
        url_scores = [r["score"] for r in url_rows]

    result = fuse(findings, url_scores=url_scores, text_score=None)

    partial = False
    try:
        sanitized = sanitize(text).sanitized if text.strip() else ""
    except SanitizationError:
        sanitized, partial = None, True  # fail closed: never echo raw text as "sanitized"

    return {
        "score": result.score,
        "verdict": result.verdict,
        "category": result.category,
        "kind": kind,
        "findings": [f.to_dict() for f in sorted(findings, key=lambda f: (f.start is None, f.start or 0))],
        "urls": url_rows,
        "explanation": explain(result.verdict, result.score, findings),
        "sanitized": sanitized,
        "partial": partial,
        "stub": not rules.READY,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
    }


def main() -> None:
    text = " ".join(sys.argv[1:]) or "URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz/login"
    print(json.dumps(analyze(text), indent=2))


if __name__ == "__main__":
    main()
