"""Detection engine: runs every detection layer over one message.

Owner: Armaan. Called by src/pipeline/analyze.py, which turns the result into
the API response. Each layer is isolated: if one raises, it is reported as
"failed" in coverage and the others still run.

Phase 3 (Govind): the URL and text models plug in here as extra layers that
return tier "ml" findings and set coverage["url_model"/"text_model"] = "ran".
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import anomaly, brands as B, domains as D, rules
from .fuse import FAILED, RAN, UNAVAILABLE, Context
from .main import PHONE_RX
from .rules import Finding

logger = logging.getLogger(__name__)

_LONE_URL = re.compile(r"\s*\S+\s*")


@dataclass
class Detection:
    findings: List[Finding]
    urls: List[dict]                 # [{"url", "score", "flags"}] for the response
    context: Context
    coverage: Dict[str, str]
    claimed: List[str] = field(default_factory=list)  # brand names the message claims


def _layer(name: str, coverage: Dict[str, str], fn, *args) -> list:
    try:
        out = fn(*args)
        coverage[name] = RAN
        return out
    except Exception:  # noqa: BLE001 - one broken layer must not take the analysis down
        logger.exception("%s layer failed", name)
        coverage[name] = FAILED
        return []


def run(text: str, kind: str, email: Optional[dict], links: List[dict], max_urls: int = 50) -> Detection:
    coverage = {"rules": UNAVAILABLE, "anomaly": UNAVAILABLE, "url_model": UNAVAILABLE, "text_model": UNAVAILABLE}
    links = [{"text": l.get("text", ""), "href": D.unwrap_redirect(l.get("href", ""))} for l in links if l.get("href")]

    body_urls = D.find_urls(text)
    if kind == "url" and not body_urls and text.strip():
        s = len(text) - len(text.lstrip())
        body_urls = [(text.strip(), s, s + len(text.strip()))]
    spots, seen = [], set()
    for u, s, e in body_urls:
        if u not in seen:
            seen.add(u)
            spots.append((u, s, e, "body"))
    for l in links:
        if l["href"] not in seen:
            seen.add(l["href"])
            spots.append((l["href"], None, None, "link"))
    spots = spots[:max_urls]

    def rule_layer():
        out = rules.content_findings(text, skip=[(s, e) for _, s, e in body_urls])
        for u, s, e, fld in spots:
            out += rules.url_findings(u, s, e, fld)
        return out

    findings = _layer("rules", coverage, rule_layer)
    findings += _layer("anomaly", coverage, anomaly.check_email, email, links)

    url_skip = [(s, e) for _, s, e in body_urls]
    claimed = B.brands_in_text(text, url_skip)
    if email:
        claimed += [b for b in B.brands_in_text(email.get("subject") or "") if b not in claimed]
        name = (email.get("from") or "").split("<")[0]
        claimed += [b for b in B.brands_in_text(name) if b not in claimed]
    if coverage["rules"] == RAN:
        findings += _layer("rules", coverage, rules.correlate, findings, claimed, spots)

    infos = [D.parse_url(u) for u, *_ in spots]
    sender = D.parse_host(email["from"].rsplit("@", 1)[-1].strip(" >").lower()) if email and "@" in (email.get("from") or "") else None
    names = {b.name for b in claimed}
    consistent = bool(names) and all(B.official_for(i) & names for i in infos) and \
        (sender is None or bool(B.official_for(sender) & names))
    actionable = bool(spots) or bool(PHONE_RX.search(text)) or \
        any(f.label in ("REMOTE_ACCESS", "CALLBACK_REQUEST") for f in findings) or bool(email and email.get("reply_to"))

    flags_by_url: Dict[str, List[str]] = {}
    for f in findings:
        if f.family == "link" and f.source == "rule":
            flags_by_url.setdefault(f.text, []).append(f.label.lower())
    url_rows = [{"url": u, "score": None, "flags": flags_by_url.get(u, [])} for u, *_ in spots]
    return Detection(findings, url_rows, Context(actionable, consistent), coverage, [b.name for b in claimed])
