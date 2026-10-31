"""Stub findings served while the rules engine isn't READY (Phase 1 only).

Deliberately crude: a few keywords and URL checks so the web app and the
extension get realistic spans, reasons and scores to render. Every reason
starts with "[stub]". Delete this module once src/detection/rules.READY is True.
"""
from __future__ import annotations

import re
from typing import List, Tuple
from urllib.parse import urlparse

from src.detection.main import URL_RX
from src.detection.rules import Finding

_KEYWORDS = [
    (r"\b(urgent(?:ly)?|immediately|within 24 hours|suspended|blocked)\b", "URGENCY", "urgency", 20,
     "Pressures you to act fast"),
    (r"\b(verify|password|otp|pin|login|kyc)\b", "CREDENTIAL_REQUEST", "credential_harvesting", 25,
     "Asks for login details or account verification"),
    (r"\b(refund|prize|lottery|won|cashback|reward)\b", "MONEY_BAIT", "financial_scam", 20,
     "Offers money or a prize"),
]
_RISKY_TLDS = {"xyz", "top", "zip", "click", "link", "buzz", "info"}


def findings(text: str) -> List[Finding]:
    url_spans = [m.span() for m in URL_RX.finditer(text)]
    out = []
    for pattern, label, category, weight, reason in _KEYWORDS:
        for m in re.finditer(pattern, text, re.I):
            if any(s <= m.start() < e for s, e in url_spans):
                continue  # words inside a link are the URL checks' job
            out.append(Finding(label, m.group(0), m.start(), m.end(), f"[stub] {reason}", "rule", weight, category,
                               tier="heuristic", family="content", field="body", severity="medium"))
    return out


def url_finding(text: str, url: str) -> Tuple[Finding, List[str]]:
    """Stands in for the URL model: one ml-tier finding per URL, located in the body when it appears there."""
    host = urlparse(url if "://" in url else "http://" + url).hostname or ""
    flags = []
    if not url.lower().startswith("https://"):
        flags.append("no_https")
    if host.rsplit(".", 1)[-1] in _RISKY_TLDS:
        flags.append("risky_tld")
    if re.fullmatch(r"[\d.]+", host):
        flags.append("ip_host")
    p = round(min(0.95, 0.1 + 0.3 * len(flags)), 2)
    at = text.find(url)
    reason = f"[stub] Link looks risky ({', '.join(flags)})" if flags else "[stub] No obvious link red flags"
    return Finding("URL_MODEL", url, at if at >= 0 else None, at + len(url) if at >= 0 else None, reason,
                   "url-model", 0, "suspicious_link" if flags else None, tier="ml", family="ml",
                   field="body" if at >= 0 else "link", severity="high" if p >= 0.7 else "medium" if p >= 0.4 else "low",
                   confidence=p), flags
