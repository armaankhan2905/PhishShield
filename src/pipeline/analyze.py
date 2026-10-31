"""Analyze pipeline behind POST /api/analyze (contract: doc/API.md).

  message -> detection engine (rules, anomaly checks, URL + text models)
          -> fuse() -> sanitize() -> template explanation (the local-AI one is /api/explain)

The original text is never modified: findings point into it, and only a
separate sanitized copy goes on to the explanation step. A layer that did not
run is reported in "coverage" and lowers "confidence"; it is never read as
evidence of safety.

Run:
    python -m src.pipeline.analyze "URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz"
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from typing import List, Optional

from src.detection import engine, rules
from src.detection.fuse import FAILED, fuse
from src.pipeline.explain import template
from src.pipeline.sanitize import SanitizationError, sanitize

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


def utf16_index(text: str, i: Optional[int]) -> Optional[int]:
    """Python indexes code points; JavaScript strings index UTF-16 units (emoji count twice)."""
    return None if i is None else len(text[:i].encode("utf-16-le")) // 2


def analyze(text: str, kind: str = "auto", email: Optional[dict] = None,
            links: Optional[List[dict]] = None) -> dict:
    t0 = time.perf_counter()
    links = links or []
    if kind == "auto":
        kind = detect_kind(text, email)

    det = engine.run(text, kind, email, links, MAX_URLS)
    findings = det.findings
    order = sorted(range(len(findings)), key=lambda i: (findings[i].start is None, findings[i].start or 0))
    findings = [findings[i] for i in order]
    result = fuse(findings, det.coverage, det.context)

    out_findings = []
    for i, f in enumerate(findings):
        d = f.to_dict()
        d.update(id=f"f{i + 1}", contribution=round(result.contributions.get(i, 0.0), 1),
                 start_u16=utf16_index(text, f.start), end_u16=utf16_index(text, f.end))
        out_findings.append(d)

    partial = any(state == FAILED for state in det.coverage.values())
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
        "urls": det.urls,
        "coverage": det.coverage,
        "explanation": template(result.verdict, result.score, [f.reason for f in ranked], result.confidence, result.gate),
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
