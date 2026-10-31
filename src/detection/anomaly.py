"""Email anomaly checks: mismatches between what a message claims and what it is.

Owner: Armaan.
  - display name names a brand, sender domain isn't theirs (or is free mail)
  - sender domain imitates a brand
  - display name contains a different email address than the real sender
  - Reply-To goes somewhere other than the sender
  - link text shows one domain, the real link goes to another
"""
from __future__ import annotations

from email.utils import parseaddr
from typing import List, Optional

from . import brands as B
from . import domains as D
from .rules import Finding


def _f(label, text, field, reason, weight, tier, category, family="sender") -> Finding:
    return Finding(label, text, None, None, reason, "anomaly", weight, category, tier, family, field,
                   "high" if tier == "confirmed" else ("medium" if weight >= 15 else "low"))


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""


def sender_findings(email: Optional[dict]) -> List[Finding]:
    if not email or not email.get("from"):
        return []
    raw = email["from"]
    name, addr = parseaddr(raw)
    dom = _domain(addr)
    if not dom:
        return []
    info = D.parse_host(dom)
    out = []
    claimed = B.brands_in_text(name)
    owners = B.official_for(info)
    free = D.is_freemail(dom)
    for b in claimed:
        if free:
            out.append(_f("SENDER_BRAND_MISMATCH", raw, "from",
                          f"Display name says {b.name} but the email comes from a free {info.registered} address",
                          45, "confirmed", "impersonation"))
            break
        if b.name not in owners:
            out.append(_f("SENDER_BRAND_MISMATCH", raw, "from",
                          f"Display name says {b.name} but the email comes from {info.registered}, "
                          f"which is not one of {b.name}'s domains", 45, "confirmed", "impersonation"))
            break
    imp = B.impersonation(info)
    if imp and not (imp[0] == "BRAND_OTHER_TLD" and info.suffix.split(".")[-1] not in D.RISKY_TLDS):
        label, brand, detail = imp
        out.append(_f("SENDER_LOOKALIKE", raw, "from", f"Sender domain imitates {brand.name}: {detail}", 50,
                      "confirmed", "impersonation"))
    shown = _domain(name) if "@" in name else ""
    if shown and D.parse_host(shown).registered != info.registered:
        out.append(_f("DISPLAY_NAME_SPOOF", raw, "from",
                      f"Display name shows {shown} but the real sender is {addr}", 45, "confirmed", "impersonation"))
    reply = parseaddr(email.get("reply_to") or "")[1]
    rdom = _domain(reply)
    if rdom and D.parse_host(rdom).registered != info.registered:
        to_free = D.is_freemail(rdom) and not free
        out.append(_f("REPLY_TO_MISMATCH", email["reply_to"], "reply_to",
                      f"Replies go to {D.parse_host(rdom).registered}, not the sender's {info.registered}"
                      + (" (a free email address)" if to_free else ""), 18 if to_free else 12, "heuristic",
                      "impersonation"))
    return out


def link_findings(links: List[dict]) -> List[Finding]:
    out = []
    for link in links:
        href, shown = link.get("href", ""), (link.get("text") or "").strip()
        target = D.parse_url(href)
        if not shown or not target.valid:
            continue
        written = D.find_urls(shown)
        if not written:
            continue
        claimed = D.parse_url(written[0][0])
        if claimed.valid and claimed.registered != target.registered:
            out.append(_f("LINK_TEXT_MISMATCH", href, "link",
                          f"Link text shows {claimed.registered} but it really goes to {target.registered or href}",
                          45, "confirmed", "suspicious_link", family="link"))
    return out


def check_email(email: Optional[dict], links: List[dict]) -> List[Finding]:
    """Findings with source="anomaly", family "sender" or "link", field "from" /
    "reply_to" / "link", and start/end None (they are not positions in the body).

    email: {"from", "reply_to", "subject"} or None; links: [{"text", "href"}].
    """
    return sender_findings(email) + link_findings(links)
