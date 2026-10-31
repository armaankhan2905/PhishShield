"""Rules engine: hand-written phishing signals over message text and URLs.

Owner: Armaan (Phase 2). Phase 1 fixes only the interface the API calls.
Set READY = True once analyze_rules() returns real findings; until then the
API serves stub data (src/pipeline/stub.py) so the web app and extension
can be built against realistic responses.

Every finding says what kind of evidence it is (doc/API.md, "Evidence"):
  tier    confirmed  a verifiable technical fact (lookalike domain, link text != real link)
          heuristic  a pattern that is often but not always phishing (urgency, shortener)
          ml         a model prediction (set by the model layers, not here)
  family  sender | link | content | ml   - independent sources of evidence
  field   body | subject | from | reply_to | link - where the evidence is

Usage:
    from src.detection.rules import analyze_rules, analyze_url
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import List, Optional

READY = False

SOURCES = ("rule", "url-model", "text-model", "anomaly")
TIERS = ("confirmed", "heuristic", "ml")
FAMILIES = ("sender", "link", "content", "ml")
FIELDS = ("body", "subject", "from", "reply_to", "link")
SEVERITIES = ("low", "medium", "high")


@dataclass
class Finding:
    label: str                    # e.g. "URGENCY", "LOOKALIKE_DOMAIN"
    text: str                     # the flagged span, or the header/link value
    start: Optional[int]          # index into the analysed text; None unless field == "body"
    end: Optional[int]
    reason: str                   # one sentence a user can read, stating only what was detected
    source: str = "rule"          # one of SOURCES
    weight: int = 10              # points this finding asks for (before caps); see fuse.py
    category: Optional[str] = None  # one of fuse.CATEGORIES
    tier: str = "heuristic"       # one of TIERS
    family: str = "content"       # one of FAMILIES
    field: str = "body"           # one of FIELDS
    severity: str = "low"         # one of SEVERITIES
    confidence: Optional[float] = None  # model probability for tier "ml"; None for rules

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_rules(text: str) -> List[Finding]:
    """Rule findings for *text*; spans index into *text*. Phase 2: Armaan."""
    return []


def analyze_url(url: str) -> List[str]:
    """Red-flag names for one URL, e.g. ["ip_host", "risky_tld"]. Phase 2: Armaan."""
    return []
