"""UPI and QR-code checks: the ways Indian payment scams ask you to pay while promising to pay you.

Owner: Ryan.
  - A UPI QR code ("upi://pay?...") always takes money out of the account that scans it. A
    message that says scan it to *receive* a refund, prize or cashback is a scam, every time.
  - Approving a "collect request" or entering your UPI PIN never receives money either.
  - Scam UPI IDs borrow a brand and a service word ("sbi.refund@ybl", "amazoncare@okaxis").
  - A QR code's payee name can claim a bank while the money goes to a personal UPI handle.
QR payloads come from images (src/pipeline/images.py); UPI IDs can also be written in any text.
"""
from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import parse_qs, unquote, urlsplit

from . import brands as B
from .rules import _NEGATION, Finding

_NEGATION_IN = re.compile(r"\b(?:never|not|don'?t|do\s+not|no\s+need)\b", re.I)

# Handles that ordinary people get from payment apps (PhonePe, Google Pay, Paytm, Amazon Pay, BHIM,
# WhatsApp...). A bank or company collecting money uses a merchant handle, not one of these.
CONSUMER_HANDLES = {
    "ybl", "ibl", "axl", "okaxis", "okhdfcbank", "oksbi", "okicici", "paytm", "ptyes", "ptaxis", "pthdfc", "ptsbi",
    "apl", "yapl", "rapl", "upi", "waaxis", "wahdfcbank", "wasbi", "waicici", "fam", "freecharge", "jupiteraxis",
    "slice", "naviaxis", "superyes", "kmbl", "abfspay", "airtel", "jio", "ikwik", "postbank",
}

_VPA = re.compile(r"\b([a-z0-9][a-z0-9._-]{1,63})@([a-z][a-z0-9]{1,30})\b(?!\.[a-z])", re.I)
_SERVICE = re.compile(r"refund|kyc|support|care|help|reward|cashback|prize|verify|claim|customer|service|helpdesk|"
                      r"offer|lottery|gift|bonus|desk|official|team", re.I)
_RECEIVE = re.compile(r"\b(?:receive|get|gets|credited|credit|refund|refunded|cash\s*back|cashback|prize|reward|won|"
                      r"winnings?|claim|lottery|bonus|payout|salary|deposit)\b", re.I)
SCAN_TO_RECEIVE = re.compile(
    r"\b(?:scan(?:ning)?\s+(?:the\s+|this\s+|our\s+|below\s+|attached\s+)?(?:qr|code|barcode)|"
    r"(?:approve|accept)\s+(?:the\s+|this\s+|my\s+|our\s+)?(?:upi\s+)?(?:collect|payment|money)\s*request|"
    r"enter\s+(?:your\s+)?(?:upi\s+)?(?:m-?)?pin)\b[^.!?\n]{0,60}?\bto\s+(?:receive|get|claim|credit)\b|"
    r"\b(?:receive|get|claim)\b[^.!?\n]{0,40}?\b(?:scan(?:ning)?\s+(?:the\s+|this\s+)?qr|approv\w+\s+(?:the\s+)?(?:collect\s+)?request)\b",
    re.I)


def _f(label, text, start, end, field, reason, weight, tier, category, family="link") -> Finding:
    return Finding(label, text, start, end, reason, "rule", weight, category, tier, family, field,
                   "high" if tier == "confirmed" else ("medium" if weight >= 15 else "low"))


def parse_upi(payload: str) -> Optional[dict]:
    """{"pa", "pn", "am", "tn"} from a "upi://pay?..." payload, or None."""
    p = (payload or "").strip()
    if not p.lower().startswith(("upi://pay", "upi://collect", "upi:/pay")):
        return None
    q = parse_qs(urlsplit(p).query, keep_blank_values=True)
    get = lambda k: unquote(q.get(k, [""])[0]).strip()  # noqa: E731
    return {"pa": get("pa").lower(), "pn": get("pn"), "am": get("am"), "tn": get("tn")}


def _vpa_brand(local: str) -> List[B.Brand]:
    spaced = re.sub(r"[._\-\d]+", " ", local)
    return [b for b in B.BRANDS if any(t in local for t in b.tokens) or b in B.brands_in_text(spaced)]


def text_findings(text: str) -> List[Finding]:
    """UPI IDs and scan-to-receive wording written in a message."""
    out = []
    for m in SCAN_TO_RECEIVE.finditer(text):
        if _NEGATION.search(text[max(0, m.start() - 40):m.start()]) or _NEGATION_IN.search(m.group(0)):
            continue  # "never scan a QR code to receive money" is the warning, not the scam
        out.append(_f("SCAN_TO_RECEIVE", m.group(0), m.start(), m.end(), "body",
                      "Says to scan a QR code, approve a request or enter your UPI PIN to receive money. "
                      "Those steps always send money, they never receive it", 30, "heuristic", "financial_scam",
                      family="content"))
    for m in _VPA.finditer(text):
        local, handle = m.group(1).lower(), m.group(2).lower()
        if handle not in CONSUMER_HANDLES:
            continue
        brands = _vpa_brand(local)
        if brands and _SERVICE.search(local):
            out.append(_f("UPI_ID_IMPERSONATION", m.group(0), m.start(), m.end(), "body",
                          f"The UPI ID {m.group(0)} borrows {brands[0].name}'s name with a word like 'refund' or "
                          f"'support', on a personal payment-app handle (@{handle})", 25, "heuristic", "impersonation"))
    return out


def qr_findings(payloads: List[str], text: str) -> List[Finding]:
    """Findings for UPI QR codes found in an image. Link QR codes are checked as links elsewhere."""
    out = []
    for p in payloads:
        upi = parse_upi(p)
        if not upi:
            continue
        label = f"UPI QR: pay {upi['pn'] or upi['pa']}" + (f" Rs {upi['am']}" if upi["am"] else "")
        if _RECEIVE.search(text) or _RECEIVE.search(upi["tn"]):
            out.append(_f("QR_PAY_TO_RECEIVE", p, None, None, "link",
                          "The message promises you money, but its QR code is a UPI payment code: scanning it sends "
                          f"money to {upi['pa'] or 'someone'}" + (f" (Rs {upi['am']})" if upi["am"] else "")
                          + ". You never scan a QR code to receive money", 50, "confirmed", "financial_scam"))
        handle = upi["pa"].rsplit("@", 1)[-1] if "@" in upi["pa"] else ""
        claimed = B.brands_in_text(upi["pn"])
        if claimed and handle in CONSUMER_HANDLES:
            out.append(_f("UPI_PAYEE_CLAIMS_BRAND", p, None, None, "link",
                          f"The QR code's payee name says {claimed[0].name}, but the money goes to {upi['pa']}, "
                          f"a personal payment-app ID", 25, "heuristic", "impersonation"))
        local = upi["pa"].split("@", 1)[0]
        brands = _vpa_brand(local)
        if brands and _SERVICE.search(local) and handle in CONSUMER_HANDLES and not claimed:
            out.append(_f("UPI_ID_IMPERSONATION", p, None, None, "link",
                          f"The QR code pays {upi['pa']}, which borrows {brands[0].name}'s name with a word like "
                          f"'refund' or 'support' on a personal payment-app handle", 25, "heuristic", "impersonation"))
        if not out or out[-1].text != p:
            out.append(_f("UPI_QR", p, None, None, "link", f"Contains a UPI payment QR code ({label}). "
                          "Scanning it sends money", 0, "heuristic", None))
    return out
