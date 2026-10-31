"""Email anomaly checks: mismatches between what a message claims and what it is.

Owner: Armaan (Phase 2). Planned checks:
  - display name vs sender domain ("HDFC Bank" <x@gmail.com>)
  - Reply-To differs from From
  - link text shows one domain, href goes to another
  - free-mail sender claiming to be a company
"""
from __future__ import annotations

from typing import List, Optional

from .rules import Finding


def check_email(email: Optional[dict], links: List[dict]) -> List[Finding]:
    """Findings with source="anomaly" and start/end None.

    email: {"from", "reply_to", "subject"} or None; links: [{"text", "href"}].
    """
    return []
