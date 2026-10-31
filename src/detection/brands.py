"""Brand registry: who is commonly impersonated, and which domains they really use.

Owner: Armaan. Each brand lists:
  aliases  how messages name it ("state bank of india", "hdfc bank")
  tokens   strings an impersonating domain would borrow ("sbi", "paypal")
  domains  registered domains the brand really sends from / links to
  tlds     brand-owned top-level domains (".sbi")
  bank     True: a <token>.bank.in domain counts as official (RBI-restricted zone)

Keep this list honest: a missing official domain causes false alarms, and a
wrong one hides impersonation. Every entry should be checked against real
messages from that brand (see doc/HANDOFF.md).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set, Tuple

from . import domains as D


@dataclass(frozen=True)
class Brand:
    name: str
    aliases: Tuple[str, ...]
    tokens: Tuple[str, ...]
    domains: Tuple[str, ...]
    tlds: Tuple[str, ...] = ()
    bank: bool = False


BRANDS: List[Brand] = [
    Brand("SBI", ("sbi", "state bank of india", "state bank", "yono sbi", "yono", "onlinesbi"),
          ("sbi", "onlinesbi", "yonosbi", "statebank"),
          ("sbi.co.in", "onlinesbi.sbi", "sbicard.com", "sbilife.co.in", "sbimf.com", "sbisecurities.in"),
          tlds=("sbi",), bank=True),
    Brand("HDFC Bank", ("hdfc bank", "hdfc"), ("hdfc", "hdfcbank"),
          ("hdfcbank.com", "hdfcbank.net", "hdfc.com", "hdfcbk.io", "hdfclife.com", "hdfcsec.com"), bank=True),
    Brand("ICICI Bank", ("icici bank", "icici", "imobile"), ("icici", "icicibank"),
          ("icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com", "icicisecurities.com"),
          bank=True),
    Brand("Axis Bank", ("axis bank",), ("axisbank",), ("axisbank.com", "axisbank.co.in", "axisdirect.in"), bank=True),
    Brand("Kotak", ("kotak mahindra", "kotak"), ("kotak",), ("kotak.com", "kotaksecurities.com"), bank=True),
    Brand("PNB", ("punjab national bank", "pnb"), ("pnb", "pnbindia", "netpnb"), ("pnbindia.in", "netpnb.com"),
          bank=True),
    Brand("Bank of Baroda", ("bank of baroda", "bob world"), ("bankofbaroda", "bobworld"),
          ("bankofbaroda.in", "bankofbaroda.com"), bank=True),
    Brand("Canara Bank", ("canara bank",), ("canarabank",), ("canarabank.com", "canarabank.in"), bank=True),
    Brand("Union Bank of India", ("union bank of india",), ("unionbankofindia",), ("unionbankofindia.co.in",),
          bank=True),
    Brand("Paytm", ("paytm",), ("paytm",), ("paytm.com", "paytm.in", "paytmbank.com", "paytmmall.com", "paytm.me")),
    Brand("PhonePe", ("phonepe", "phone pe"), ("phonepe",), ("phonepe.com", "phon.pe")),
    Brand("Google", ("google pay", "gpay", "google account", "google"), ("google", "gpay", "gmail"),
          ("google.com", "google.co.in", "googlemail.com", "g.co", "goo.gl", "youtube.com", "withgoogle.com")),
    Brand("Amazon", ("amazon pay", "amazon", "prime video"), ("amazon", "amzn"),
          ("amazon.in", "amazon.com", "amazon.co.uk", "amazon.de", "amazonpay.in", "amzn.to", "amzn.in", "amzn.eu",
           "primevideo.com", "media-amazon.com")),
    Brand("Flipkart", ("flipkart",), ("flipkart",), ("flipkart.com", "fkrt.it", "fkrt.co")),
    Brand("Microsoft", ("microsoft", "office 365", "microsoft 365", "onedrive"), ("microsoft", "office365", "onedrive"),
          ("microsoft.com", "office.com", "office365.com", "microsoftonline.com", "microsoft365.com", "live.com",
           "outlook.com", "onedrive.com", "windows.com", "bing.com", "azure.com", "skype.com")),
    Brand("Apple", ("apple id", "apple support", "icloud", "itunes", "app store"), ("apple", "appleid", "icloud", "itunes"),
          ("apple.com", "icloud.com", "me.com")),
    Brand("Netflix", ("netflix",), ("netflix",), ("netflix.com",)),
    Brand("PayPal", ("paypal",), ("paypal",), ("paypal.com", "paypal.me", "paypalobjects.com")),
    Brand("Facebook", ("facebook",), ("facebook",), ("facebook.com", "fb.com", "fb.me", "facebookmail.com", "meta.com")),
    Brand("Instagram", ("instagram",), ("instagram",), ("instagram.com",)),
    Brand("WhatsApp", ("whatsapp",), ("whatsapp",), ("whatsapp.com", "whatsapp.net", "wa.me")),
    Brand("LinkedIn", ("linkedin",), ("linkedin",), ("linkedin.com", "lnkd.in")),
    Brand("IRCTC", ("irctc",), ("irctc",), ("irctc.co.in", "irctctourism.com")),
    Brand("India Post", ("india post", "indiapost"), ("indiapost",), ("indiapost.gov.in",)),
    Brand("Income Tax Department", ("income tax", "income-tax", "incometax"), ("incometax", "incometaxindia"),
          ("incometax.gov.in", "incometaxindia.gov.in")),
    Brand("EPFO", ("epfo", "provident fund"), ("epfo", "epfindia"), ("epfindia.gov.in",)),
    Brand("UIDAI", ("uidai", "aadhaar", "aadhar"), ("uidai", "aadhaar", "aadhar"), ("uidai.gov.in",)),
    Brand("NPCI", ("npci", "bhim"), ("npci", "bhimupi"), ("npci.org.in", "bhimupi.org.in")),
    Brand("Airtel", ("airtel",), ("airtel",), ("airtel.in", "airtel.com")),
    Brand("Jio", ("reliance jio", "jio"), ("jio", "myjio"), ("jio.com", "jiomart.com", "ril.com")),
    Brand("DHL", ("dhl",), ("dhl",), ("dhl.com", "dhl.co.in", "dhl.de")),
    Brand("FedEx", ("fedex",), ("fedex",), ("fedex.com",)),
    Brand("Blue Dart", ("blue dart", "bluedart"), ("bluedart",), ("bluedart.com",)),
    Brand("Delhivery", ("delhivery",), ("delhivery",), ("delhivery.com",)),
    Brand("Swiggy", ("swiggy",), ("swiggy",), ("swiggy.com", "swiggy.in")),
    Brand("Zomato", ("zomato",), ("zomato",), ("zomato.com",)),
]

# Payment gateways host bank pages on their own domains (hdfc.payu.in), so a
# brand in their subdomain is normal. Only the subdomain check skips them.
PAYMENT_GATEWAYS = {"payu.in", "payu.com", "billdesk.com", "razorpay.com", "ccavenue.com", "juspay.in",
                    "cashfree.com", "easebuzz.in", "instamojo.com", "paynimo.com", "atomtech.in", "payglocal.in"}

# Registered domains that contain a brand token but are not impersonation.
KNOWN_UNRELATED = {"amazonaws.com", "googleusercontent.com", "googleapis.com", "googlesyndication.com",
                   "googletagmanager.com", "google-analytics.com", "outlookindia.com"}

_ALIAS_RX = [(b, re.compile(r"(?<![\w-])(?:" + "|".join(re.escape(a) for a in sorted(b.aliases, key=len, reverse=True))
                            + r")(?![\w-])", re.I)) for b in BRANDS]
_OFFICIAL = {d: b for b in BRANDS for d in b.domains}


def by_name(name: str) -> Brand:
    return next(b for b in BRANDS if b.name == name)


def brands_in_text(text: str, skip: Iterable[Tuple[int, int]] = ()) -> List[Brand]:
    """Brands a message claims to be from / talks about, ignoring text inside *skip* spans (URLs)."""
    skip = list(skip)
    found = []
    for b, rx in _ALIAS_RX:
        if any(not any(s <= m.start() < e for s, e in skip) for m in rx.finditer(text)):
            found.append(b)
    return found


def official_for(info: D.UrlInfo) -> Set[str]:
    """Names of brands that really own this URL's domain. Empty for user-content hosts."""
    if not info.valid or info.is_ip or D.is_user_content(info):
        return set()
    names = set()
    b = _OFFICIAL.get(info.registered)
    if b:
        names.add(b.name)
    tld = info.suffix.split(".")[-1] if info.suffix else ""
    for b in BRANDS:
        if tld in b.tlds:
            names.add(b.name)
        if b.bank and info.suffix == "bank.in" and any(t in info.label for t in b.tokens):
            names.add(b.name)
    return names


def _tokens(s: str) -> List[str]:
    return [t for t in re.split(r"[^a-z]+", s.lower()) if t]


# Words glued to a brand name in combosquatting domains ("paypalsecure", "loginhdfc").
_COMBO_WORDS = {
    "secure", "security", "login", "signin", "verify", "verification", "support", "account", "accounts", "update",
    "kyc", "help", "helpdesk", "service", "services", "care", "online", "auth", "pay", "payment", "bank", "banking",
    "alert", "alerts", "reward", "rewards", "refund", "gift", "offer", "offers", "prize", "team", "official", "india",
    "net", "netbanking", "app", "web", "portal", "id", "customer", "billing", "wallet", "card", "cards", "cash",
    "cashback", "claim", "bonus", "unlock", "reset", "recovery", "drive", "docs", "mail", "cloud", "delivery", "track",
}


def _combo(part: str, token: str) -> bool:
    """part is token + a phishing word or a phishing word + token ("paypalsecure", "securesbi")."""
    if len(token) < 3 or part == token:
        return False
    if part.startswith(token):
        return part[len(token):] in _COMBO_WORDS
    if part.endswith(token):
        return part[:-len(token)] in _COMBO_WORDS
    return False


def impersonation(info: D.UrlInfo) -> Optional[Tuple[str, Brand, str]]:
    """(label, brand, detail) when the domain imitates a brand it doesn't belong to, else None.

    Labels: HOMOGRAPH_DOMAIN, TYPOSQUAT_DOMAIN, BRAND_IN_DOMAIN, BRAND_IN_SUBDOMAIN, and
    BRAND_OTHER_TLD (the brand's exact name on another ending, e.g. amazon.ca: often a real
    regional site, so callers treat it as a heuristic unless the ending is a risky one).
    """
    if not info.valid or info.is_ip or official_for(info) or info.registered in KNOWN_UNRELATED:
        return None
    label = info.label.lower()
    folded = D.skeletons(label)
    for b in BRANDS:
        # Typo targets: official labels that carry a brand token ("hdfcbank", not "windows").
        official_labels = {lab for lab in (D.parse_host(d).label for d in b.domains)
                           if any(t in lab for t in b.tokens)}
        for ol in official_labels:
            if label == ol:
                continue  # same name on another TLD (sbi.xyz) is caught below as BRAND_IN_DOMAIN
            if len(ol) >= 4 and ol in folded:
                kind = "HOMOGRAPH_DOMAIN" if info.idn else "TYPOSQUAT_DOMAIN"
                return kind, b, f"{info.unicode_host or info.host} imitates {ol}"
            if len(ol) >= 6 and label.isascii() and min(D.osa_distance(f, ol) for f in folded) <= (2 if len(ol) >= 10 else 1):
                return "TYPOSQUAT_DOMAIN", b, f"{info.host} is one or two letters away from {ol}"
    for b in BRANDS:
        if label in b.tokens or label in {D.parse_host(d).label for d in b.domains}:
            return "BRAND_OTHER_TLD", b, f"{info.registered} uses {b.name}'s name on a different ending (.{info.suffix})"
    # Also read the label with look-alikes folded, so "amaz0n-refund" splits into amazon + refund.
    parts = set(_tokens(label)).union(*(_tokens(f) for f in D.skeletons(label, keep_hyphens=True)))
    for b in BRANDS:
        for t in b.tokens:
            if t in parts or any(_combo(p, t) for p in parts):
                return "BRAND_IN_DOMAIN", b, f"{info.registered} uses the name {t} but is not one of {b.name}'s domains"
    if info.registered in PAYMENT_GATEWAYS:
        return None
    sub_parts = _tokens(info.subdomain)
    for b in BRANDS:
        for t in b.tokens:
            if t in sub_parts or any(_combo(p, t) for p in sub_parts) or any(d in info.subdomain for d in b.domains):
                return ("BRAND_IN_SUBDOMAIN", b,
                        f"{info.host} puts {t} in front of {info.registered}, which is not one of {b.name}'s domains")
    return None
