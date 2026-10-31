"""Stub findings served while the rules engine isn't READY (Phase 1 only).

Deliberately crude: a few keywords and URL checks so the web app and the
extension get realistic spans, reasons and scores to render. Every reason
starts with "[stub]". Delete this module once src/detection/rules.READY is True.
"""
from __future__ import annotations

import re
from typing import List
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
            out.append(Finding(label, m.group(0), m.start(), m.end(), f"[stub] {reason}", "rule", weight, category))
    return out


def url_flags(url: str) -> List[str]:
    host = urlparse(url if "://" in url else "http://" + url).hostname or ""
    flags = []
    if not url.lower().startswith("https://"):
        flags.append("no_https")
    if host.rsplit(".", 1)[-1] in _RISKY_TLDS:
        flags.append("risky_tld")
    if re.fullmatch(r"[\d.]+", host):
        flags.append("ip_host")
    return flags


def url_score(flags: List[str]) -> float:
    return min(0.95, 0.1 + 0.3 * len(flags))
