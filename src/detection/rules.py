"""Rules engine: hand-written phishing signals over message text and URLs.

Owner: Armaan (Phase 2). Phase 1 fixes only the interface the API calls.
Set READY = True once analyze_rules() returns real findings; until then the
API serves stub data (src/pipeline/stub.py) so the web app and extension
can be built against realistic responses.

Usage:
    from src.detection.rules import analyze_rules, analyze_url
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import List, Optional

READY = False

SOURCES = ("rule", "url-model", "text-model", "anomaly")


@dataclass
class Finding:
    label: str                    # e.g. "URGENCY", "LOOKALIKE_DOMAIN"
    text: str                     # the flagged span, or the header/link value
    start: Optional[int]          # index into the analysed text; None for header/link findings
    end: Optional[int]
    reason: str                   # one sentence a user can read
    source: str = "rule"          # one of SOURCES
    weight: int = 10              # contribution to the 0-100 rules score
    category: Optional[str] = None  # one of fuse.CATEGORIES

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_rules(text: str) -> List[Finding]:
    """Rule findings for *text*; spans index into *text*. Phase 2: Armaan."""
    return []


def analyze_url(url: str) -> List[str]:
    """Red-flag names for one URL, e.g. ["ip_host", "risky_tld"]. Phase 2: Armaan."""
    return []
