"""Detection engine: runs every detection layer over one message.

Owner: Armaan. Called by src/pipeline/analyze.py, which turns the result into
the API response. Each layer is isolated: if one raises, it is reported as
"failed" in coverage and the others still run.

The URL and text models (src/model/predict.py) run here as extra layers that
return tier "ml" findings; a model that is not installed is "unavailable".
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import anomaly, brands as B, domains as D, fuse as FU, rules, upi
from .fuse import FAILED, RAN, UNAVAILABLE, Context
from .main import PHONE_RX
from .rules import Finding
from src.model import predict

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


MIN_TEXT_WORDS = 3

# Other ways a message asks you to act: "txt MUSIC to 87121" short codes, and numbers
# written with spaces ("call 0844 861 85 85") that PHONE_RX doesn't match.
_CONTACT_RX = re.compile(
    r"\b(?:txt|text|sms|reply|send)\b(?:\W+\w+){0,3}?\W+to\s+\d{4,6}\b|"
    r"\b(?:call|ring|dial|whatsapp|contact|phone)\b[^.\n]{0,25}?\+?\d[\d\s-]{8,}\d",
    re.I)
_SEND_RX = re.compile(r"(?:share|send|tell|give|forward|reply|read\s+out)\b", re.I)
# Anything that asks you to hand over details, pay, log in, call or install. An email that does any of
# these never gets the first-party model discount, whoever sent it.
_ASK_LABELS = rules.REQUEST_LABELS | {"REMOTE_ACCESS", "CALLBACK_REQUEST", "REQUEST_WITH_LINK", "SCAN_TO_RECEIVE",
                                      "UPI_ID_IMPERSONATION", "UPI_PAYEE_CLAIMS_BRAND", "UPI_QR"}


def _ml_severity(p: float) -> str:
    return "high" if p >= 0.9 else "medium" if p >= 0.7 else "low"


def _model_layer(name: str, coverage: Dict[str, str], fn, *args):
    """Like _layer, but a model that isn't installed is "unavailable", not "failed"."""
    try:
        out = fn(*args)
    except Exception:  # noqa: BLE001
        logger.exception("%s failed", name)
        coverage[name] = FAILED
        return None
    coverage[name] = UNAVAILABLE if out is None else RAN
    return out


def _url_model(spots) -> Optional[Dict[str, float]]:
    if not predict.available("url"):
        return None
    urls = [u for u, *_ in spots]
    return dict(zip(urls, predict.url_proba(urls) or []))


def _text_model(text: str, kind: str) -> Optional[List[Finding]]:
    if not predict.available("text"):
        return None
    if kind == "url" or len(text.split()) < MIN_TEXT_WORDS:
        return []  # nothing for a language model to read; the layer still counts as checked
    p = predict.text_proba(text)
    if p is None or p < FU.TEXT_FLOOR:  # below the floor it adds no points, so it is not listed as evidence
        return []
    return [Finding("TEXT_MODEL", "(whole message)", None, None,
                    f"The text model rates the wording {p:.0%} likely to be phishing", "text-model", 0, None,
                    "ml", "ml", "body", _ml_severity(p), round(p, 4))]


def run(text: str, kind: str, email: Optional[dict], links: List[dict], max_urls: int = 50,
        qr: Optional[List[str]] = None) -> Detection:
    """qr: payloads of QR codes found in an uploaded image. A link QR code is checked like any
    other link; a UPI QR code is checked by src/detection/upi.py."""
    coverage = {"rules": UNAVAILABLE, "anomaly": UNAVAILABLE, "url_model": UNAVAILABLE, "text_model": UNAVAILABLE}
    qr = [p for p in (qr or []) if p and p.strip()]
    links = [{"text": l.get("text", ""), "href": D.unwrap_redirect(l.get("href", ""))} for l in links if l.get("href")]
    for p in qr:
        if D.find_urls(p) and not upi.parse_upi(p):
            links.append({"text": "QR code", "href": D.unwrap_redirect(D.find_urls(p)[0][0])})

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
        out += upi.text_findings(text) + upi.qr_findings(qr, text)
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
    sender = D.parse_host(email["from"].rsplit("@", 1)[-1].strip(" >").lower()) if email and "@" in (email.get("from") or "") else None
    # A sender we can lean on: a real organisation's domain (not free mail) with nothing wrong found about it.
    clean_sender = sender if sender is not None and sender.valid and not D.is_freemail(sender.registered) and \
        coverage["anomaly"] == RAN and not any(f.source == "anomaly" and f.family == "sender" for f in findings) else None
    if coverage["rules"] == RAN:
        findings += _layer("rules", coverage, rules.correlate, findings, claimed, spots, clean_sender)

    url_probs = _model_layer("url_model", coverage, _url_model, spots)
    findings += [f for f in _model_layer("text_model", coverage, _text_model, text, kind) or []]
    for u, s, e, fld in spots:
        p = (url_probs or {}).get(u)
        if p is not None and p >= FU.URL_FLOOR:
            findings.append(Finding("URL_MODEL", u, s, e, f"The URL model rates this link {p:.0%} likely to be phishing",
                                    "url-model", 0, "suspicious_link", "ml", "ml", fld, _ml_severity(p), round(p, 4)))

    infos = [D.parse_url(u) for u, *_ in spots]
    names = {b.name for b in claimed}
    # Consistency needs something to check: at least one link or a sender, all belonging to the named brand.
    consistent = bool(names) and bool(infos or sender) and all(B.official_for(i) & names for i in infos) and \
        (sender is None or bool(B.official_for(sender) & names))
    # A payment request is something to act on even without a link: the scammer follows up with how to pay.
    # An email can always be answered, and "reply with your details" scams need nothing else.
    # Asking you to send or share an OTP / PIN with someone is itself the thing to act on (you reply);
    # "update your KYC on our website" is not.
    actionable = kind == "email" or bool(spots) or bool(qr) or bool(PHONE_RX.search(text)) or bool(_CONTACT_RX.search(text)) or \
        any(f.label in ("REMOTE_ACCESS", "CALLBACK_REQUEST", "PAYMENT_REQUEST", "SCAN_TO_RECEIVE", "UPI_ID_IMPERSONATION")
            for f in findings) or \
        any(f.label == "CREDENTIAL_REQUEST" and _SEND_RX.match(f.text) for f in findings)
    # First-party email: the sender is clean and every link goes to the sender's own organisation (or to
    # mail trackers and footer links), no proven trick was found, and it asks for nothing.
    first_party = clean_sender is not None and \
        all(D.same_org(i, clean_sender) or D.is_mail_infra(i) for i in infos) and \
        not any(f.tier == "confirmed" for f in findings) and \
        not any(f.label in _ASK_LABELS for f in findings)

    flags_by_url: Dict[str, List[str]] = {}
    for f in findings:
        if f.family == "link" and f.source == "rule":
            flags_by_url.setdefault(f.text, []).append(f.label.lower())
    url_rows = [{"url": u, "score": None if url_probs is None else round(url_probs[u], 4), "flags": flags_by_url.get(u, [])}
                for u, *_ in spots]
    return Detection(findings, url_rows, Context(actionable, consistent, first_party), coverage, [b.name for b in claimed])
