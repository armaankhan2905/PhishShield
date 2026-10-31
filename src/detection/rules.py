"""Rules engine: hand-written phishing signals over message text and URLs.

Owner: Armaan.

Every finding says what kind of evidence it is (doc/API.md, "Evidence"):
  tier    confirmed  a verifiable technical fact (lookalike domain, link text != real link)
          heuristic  a pattern that is often but not always phishing (urgency, shortener)
          ml         a model prediction (set by the model layers, not here)
  family  sender | link | content | ml   - independent sources of evidence
  field   body | subject | from | reply_to | link - where the evidence is

Content rules look for *requests* ("share your OTP"), not mentions: a message
that warns "never share your OTP" is not asking for it.

Usage:
    from src.detection.rules import analyze_rules, analyze_url
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import List, Optional, Sequence

from . import brands as B
from . import domains as D

READY = True

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


def _severity(tier: str, weight: int) -> str:
    if tier == "confirmed":
        return "high"
    return "medium" if weight >= 15 else "low"


# --- content rules ------------------------------------------------------------

_REQUEST = (r"(?:share|send|enter|provide|confirm|update|verify|validate|submit|re-?enter|reply\s+with|tell\s+us|"
            r"give|fill(?:\s+in)?|complete|upload|link)")
_SENSITIVE = (r"(?:otp|one[\s-]?time\s+pass(?:word|code)|m-?pin|upi\s+pin|atm\s+pin|pin|password|passcode|cvv|"
              r"(?:debit\s+|credit\s+|atm\s+)?card\s+(?:number|details|no\.?)|net\s*banking\s+(?:details|credentials|"
              r"password|id|user\s*id)|login\s+(?:details|credentials)|bank\s+(?:account\s+)?details|"
              r"account\s+(?:number|details)|aadhaa?r(?:\s+(?:number|card|details))?|pan\s+(?:card|number|details)|(?-i:PAN)|"
              r"kyc(?:\s+(?:details|documents))?|security\s+(?:code|questions?)|date\s+of\s+birth)")
_NEGATION = re.compile(r"\b(?:do\s+not|don'?t|dont|never|not|no\s+one|nobody|will\s+never|won'?t)\b[^.!?\n]{0,30}$", re.I)

# (label, pattern, category, weight, reason, negatable)
CONTENT_RULES = [
    ("CREDENTIAL_REQUEST",
     rf"\b{_REQUEST}\b(?:\W+\w+){{0,4}}?\W+{_SENSITIVE}\b|"
     r"\b(?:share|send|tell|give|forward|read\s+out)\s+(?:me\s+|us\s+)?(?:the\s+|that\s+|this\s+|your\s+)?"
     r"(?:\d\s*-?\s*digit\s+)?(?:code|verification\s+code)\b", "credential_harvesting", 20,
     "Asks you to share or enter sensitive details such as an OTP, PIN, password or card number", True),
    ("ACCOUNT_VERIFICATION",
     r"\b(?:verify|confirm|unlock|reactivate|restore|validate|re-?activate)\s+(?:your\s+)?(?:account|identity|profile|wallet)\b",
     "credential_harvesting", 12, "Asks you to verify or unlock your account", True),
    ("LOGIN_PROMPT",
     r"\b(?:log\s*in|login|sign\s*in)\s+(?:at|here|via|on|through|using)\b|\b(?:log\s*in|login|sign\s*in)\b[^.!?\n]{0,40}"
     r"\bto\s+(?:unlock|restore|reactivate|verify|avoid|continue|update)\b",
     "credential_harvesting", 12, "Asks you to log in through the message", True),
    ("KYC_PENDING",
     r"\bkyc\b[^.!?\n]{0,25}\b(?:pending|expired?|expiring|incomplete|not\s+updated|suspended|blocked|update\s+required)\b|"
     r"\b(?:pending|incomplete|expired)\s+kyc\b",
     "credential_harvesting", 12, "Says your KYC is pending or expired", False),
    ("PAYMENT_REQUEST",
     r"\b(?:pay|transfer|send|deposit)\b(?:\W+\w+){0,5}?\W+(?:rs\.?|inr|rupees|amount|fee|fees|charges?|fine|penalty|dues?)\b|"
     r"(?:rs\.?|₹|inr)\s?\d[\d,]*(?:\.\d+)?\s*(?:/-\s*)?(?:processing\s+|registration\s+|delivery\s+)?(?:fee|charges?|fine|penalty)\b",
     "financial_scam", 20, "Asks you to pay money or a fee", True),
    ("REMOTE_ACCESS",
     r"\b(?:anydesk|teamviewer|quick\s*support|rustdesk|airdroid|screen\s*share)\b|\.apk\b|\binstall\s+(?:this|the|our)\s+app\b",
     "credential_harvesting", 25, "Asks you to install a remote-access app or an APK file", False),
    ("THREAT",
     r"\b(?:account|card|sim|number|service|connection|electricity|power|wallet|upi|pan|aadhaa?r|net\s*banking|"
     r"banking|login|profile|mailbox|email)\b[^.!?\n]{0,30}"
     r"\b(?:will\s+be|has\s+been|is\s+being|is|are)\s+(?:temporarily\s+)?(?:blocked|suspended|deactivated|disconnected|"
     r"terminated|closed|frozen|restricted|cancelled|locked)\b|\b(?:legal\s+action|you\s+(?:will|may|can|shall)\s+be\s+arrested|"
     r"arrest\s+warrant|police\s+(?:case|complaint)|"
     r"fir\s+(?:will|has))\b",
     "urgency", 15, "Threatens to block your account or service, or with legal action", False),
    ("MONEY_BAIT",
     r"\b(?:you(?:'ve|\s+have)?\s+won|winner|lottery|lucky\s+draw|jackpot|prize|cash\s*back\s+of|reward\s+points?\s+"
     r"(?:will\s+)?expir\w*|refund\s+(?:is\s+)?(?:pending|approved|initiated|processed)|claim\s+your\s+(?:reward|refund|prize|gift))\b",
     "financial_scam", 15, "Offers a prize, reward or refund", False),
    ("URGENCY",
     r"\b(?:within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?|days?)|immediately|urgent(?:ly)?|today\s+itself|"
     r"last\s+(?:chance|warning|reminder)|act\s+now|expires?\s+(?:today|soon|tonight)|before\s+midnight|tonight|"
     r"(?:by|before|until)\s+today|today(?=\W*$))\b",
     "urgency", 10, "Pressures you to act quickly", False),
    ("CALLBACK_REQUEST",
     r"\b(?:call|contact|whatsapp|reach)\b(?:\W+\w+){0,4}?\W+(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b",
     "urgency", 10, "Asks you to call or message a phone number", False),
    ("CLICK_PROMPT",
     r"\b(?:click|tap)\s+(?:here|on\s+the\s+link|the\s+link|below|this\s+link)\b",
     None, 5, "Asks you to click a link", False),
    ("GENERIC_GREETING",
     r"\bdear\s+(?:customer|user|valued\s+customer|sir\s*/\s*madam|account\s*holder|member|client)\b",
     None, 3, "Uses a generic greeting instead of your name", False),

    # --- scam types common in India (2024-26) ---------------------------------------------------
    ("DIGITAL_ARREST",
     r"\bdigital\s+arrest\b|"
     # an agency, aimed at you ("your", "against you", "aapka"), with an arrest or case word - not news about others
     r"\b(?:cbi|ncb|narcotics|crime\s+branch|cyber\s*(?:cell|crime\s+(?:branch|department))|enforcement\s+directorate|"
     r"customs\s+(?:officer|department)|trai|(?:mumbai|delhi)\s+police)\b(?=[^.!?\n]{0,100}?\b(?:you|your|aap|aapka|aapke)\b)"
     r"[^.!?\n]{0,80}?\b(?:arrest\w*|warrant|money\s+laundering|"
     r"illegal|seized|drugs|case\s+(?:is\s+)?(?:registered|filed|against)|video\s+call|skype|verification\s+call)\b|"
     r"\b(?:aadhaa?r|pan|mobile\s+number|sim|bank\s+account)\b[^.!?\n]{0,40}?\b(?:linked|used|involved)\b[^.!?\n]{0,30}?"
     r"\b(?:money\s+laundering|illegal|crime|drugs|fraud\s+case|terror)\w*",
     "impersonation", 30, "Claims police, CBI, customs or another agency has a case against you (the 'digital arrest' "
     "scam). Real agencies never do this over calls or messages", False),
    ("TASK_JOB_SCAM",
     r"\b(?:like|subscribe(?:\s+to)?|rate|review)\s+(?:\w+\s+){0,2}(?:youtube\s+)?(?:videos?|channels?|hotels?|products?|"
     r"restaurants?|posts?|reviews?)\b[^.!?\n]{0,50}?\b(?:earn|paid|income|commission|salary|rs\.?|₹|inr)\b|"
     r"\b(?:prepaid|telegram|merchant)\s+tasks?\b|\btask[\s-]+based\s+(?:job|work|income)\b|"
     r"\b(?:part[\s-]?time|work\s+from\s+home|home[\s-]+based)\s+(?:job|work|opportunity)\b[^.!?\n]{0,60}?"
     r"\b(?:earn|daily|per\s+day|per\s+task|rs\.?\s?\d|₹\s?\d)",
     "financial_scam", 30, "Offers easy money for simple online tasks (the 'task job' scam: small payouts first, "
     "then you're asked to pay in)", False),
    ("PARCEL_HOLD",
     r"\b(?:parcel|package|courier|shipment|consignment|delivery)\b[^.!?\n]{0,50}?\b(?:on\s+hold|held|seized|stuck|"
     r"returned|undeliver\w*|failed|suspended|contains?\s+(?:illegal|drugs|contraband))\b",
     "urgency", 12, "Says a parcel or courier is held, seized or undelivered", False),
    ("ELECTRICITY_CUT",
     r"\b(?:electricity|power|bijli|light)\s*(?:bill|connection|supply|meter)?\b[^.!?\n]{0,60}?\b(?:will\s+be\s+)?"
     r"(?:disconnect\w*|cut\s*off|cut|kat\s+(?:jayegi|jaegi|dega))\b",
     "urgency", 15, "Threatens to cut your electricity", False),
    ("LOAN_FEE",
     r"\b(?:instant|pre-?approved|personal|quick)\s+loan\b[^.!?\n]{0,70}?\b(?:approved|sanctioned|disburs\w*|processing\s+fee|"
     r"without\s+(?:cibil|documents|credit\s+check))\b|\bloan\b[^.!?\n]{0,40}?\b(?:processing|registration|insurance)\s+(?:fee|charges?)\b",
     "financial_scam", 15, "Offers an instant or pre-approved loan, or asks a fee to release one", False),

    # --- Hinglish -------------------------------------------------------------------------------
    ("THREAT_HINGLISH",
     r"\b(?:account|a/c|khata|sim|number|card|bijli|connection|upi|wallet)\b[^.!?\n]{0,30}?\b(?:band|block|bandh|suspend)\s+"
     r"(?:ho\s+ja(?:y|)ega|ho\s+jaega|ho\s+jayega|kar\s+di(?:y|)a\s+ja(?:y|)ega|hoga|ho\s+gaya\s+hai)\b",
     "urgency", 15, "Threatens to block your account or service (in Hinglish)", False),
    ("URGENCY_HINGLISH",
     r"\b(?:turant|jaldi\s+(?:karein|karo|kare)|abhi\s+(?:karein|karo|kare|update|verify)|aaj\s+hi)\b",
     "urgency", 10, "Pressures you to act quickly (in Hinglish)", False),
    ("CREDENTIAL_REQUEST_HINGLISH",
     r"\b(?:otp|pin|upi\s+pin|password|cvv|card\s+(?:number|details))\b[^.!?\n]{0,25}?\b(?:bhejo|bhejein|bhej\s+do|bhejiye|"
     r"bataiye|batao|bata\s+do|share\s+(?:karo|karein|kare|kijiye)|dijiye|de\s+do)\b",
     "credential_harvesting", 20, "Asks you to send or tell an OTP, PIN or password (in Hinglish)", True),
    ("KYC_HINGLISH",
     r"\bkyc\b[^.!?\n]{0,25}?\b(?:update\s+(?:karein|karo|kare|kijiye)|pending\s+hai|nahi\s+hu(?:a|i)|expire\s+ho)\b",
     "credential_harvesting", 12, "Says your KYC must be updated (in Hinglish)", False),
    ("PAYMENT_REQUEST_HINGLISH",
     r"(?:rs\.?|₹|inr)\s?\d[\d,]*(?:\s*(?:ka|ki|ke))?\s*(?:\w+\s+){0,2}?(?:bhejo|bhejein|bhej\s+do|jama\s+(?:karo|karein|kare)|"
     r"pay\s+(?:karo|karein|kare)|transfer\s+(?:karo|karein)|bharo|bharein|de\s+do)\b|"
     r"\b(?:fee|charge|charges|shulk)\b[^.!?\n]{0,25}?\b(?:bhejo|bhejein|jama\s+karo|pay\s+karo|bharo|bharein)\b",
     "financial_scam", 20, "Asks you to pay money or a fee (in Hinglish)", True),
    ("PAYMENT_REQUEST_HINDI",
     r"(?:₹|रुपये|रु\.?|Rs\.?)\s*[\d,]+[^।.!?\n]{0,20}?(?:भेजें|भेजो|जमा\s*करें|भुगतान\s*करें|ट्रांसफर\s*करें)|"
     r"(?:शुल्क|फीस)[^।.!?\n]{0,25}?(?:भेजें|जमा\s*करें|भुगतान\s*करें)",
     "financial_scam", 20, "Asks you to pay money or a fee (in Hindi)", True),
    ("MONEY_BAIT_HINGLISH",
     r"\b(?:aapne|apne|aap\s+ne)\s+(?:\w+\s+){0,3}jeet[ae]\b|\b(?:inaam|lottery\s+lagi|lucky\s+draw\s+mein)\b",
     "financial_scam", 15, "Says you've won a prize (in Hinglish)", False),

    # --- Hindi (Devanagari; \b doesn't work with Devanagari vowel signs, so no word boundaries) -----
    ("THREAT_HINDI",
     r"(?:खाता|खाते|अकाउंट|सिम|बिजली|कनेक्शन|कार्ड)[^।.!?\n]{0,30}?(?:बंद|ब्लॉक|निलंबित)\s*(?:हो\s*जाएगा|कर\s*दिया\s*जाएगा|हो\s*जाएगी|होगा|कर\s*दी\s*जाएगी)",
     "urgency", 15, "Threatens to block your account or service (in Hindi)", False),
    ("URGENCY_HINDI", r"(?:तुरंत|तत्काल|आज\s*ही|जल्दी\s*करें|अंतिम\s*चेतावनी)",
     "urgency", 10, "Pressures you to act quickly (in Hindi)", False),
    ("CREDENTIAL_REQUEST_HINDI",
     r"(?:ओटीपी|OTP|पिन|पासवर्ड|सीवीवी|कार्ड\s*नंबर)[^।.!?\n]{0,25}?(?:भेजें|भेजो|बताएं|बताओ|साझा\s*करें|शेयर\s*करें|दें|दीजिए)",
     "credential_harvesting", 20, "Asks you to send or tell an OTP, PIN or password (in Hindi)", True),
    ("KYC_HINDI", r"(?:केवाईसी|KYC)[^।.!?\n]{0,25}?(?:अपडेट|लंबित|पेंडिंग|अधूरा|समाप्त)",
     "credential_harvesting", 12, "Says your KYC must be updated (in Hindi)", False),
    ("MONEY_BAIT_HINDI", r"(?:इनाम|लॉटरी|आपने\s*[^।\n]{0,20}जीत|लकी\s*ड्रॉ)",
     "financial_scam", 15, "Says you've won a prize (in Hindi)", False),
]
# Hindi and Hinglish put "don't" after the request ("OTP kisi ko mat bhejo", "OTP किसी को न बताएं").
_NEGATION_AFTER = re.compile(r"\b(?:mat|na\s+kar\w*|nahi|kabhi\s+nahi)\b|(?:मत|न\s|नहीं|कभी\s*न)", re.I)
_COMPILED = [(lab, re.compile(rx, re.I), cat, w, reason, neg) for lab, rx, cat, w, reason, neg in CONTENT_RULES]
REQUEST_LABELS = {"CREDENTIAL_REQUEST", "ACCOUNT_VERIFICATION", "LOGIN_PROMPT", "KYC_PENDING", "PAYMENT_REQUEST",
                  "CREDENTIAL_REQUEST_HINGLISH", "CREDENTIAL_REQUEST_HINDI", "KYC_HINGLISH", "KYC_HINDI", "LOAN_FEE",
                  "PAYMENT_REQUEST_HINGLISH", "PAYMENT_REQUEST_HINDI"}


def content_findings(text: str, skip: Sequence[tuple] = ()) -> List[Finding]:
    out = []
    for label, rx, cat, weight, reason, negatable in _COMPILED:
        for m in rx.finditer(text):
            if any(s <= m.start() < e for s, e in skip):
                continue
            if negatable and (_NEGATION.search(text[max(0, m.start() - 40):m.start()]) or
                              _NEGATION_AFTER.search(text[m.start():m.end() + 12])):
                continue
            out.append(Finding(label, m.group(0), m.start(), m.end(), reason, "rule", weight, cat,
                               "heuristic", "content", "body", _severity("heuristic", weight)))
    return out


# --- URL rules ----------------------------------------------------------------

def _link(label, url, start, end, field, reason, weight, tier, category="suspicious_link") -> Finding:
    return Finding(label, url, start, end, reason, "rule", weight, category, tier, "link", field,
                   _severity(tier, weight))


def url_findings(url: str, start: Optional[int] = None, end: Optional[int] = None, field: str = "body") -> List[Finding]:
    """Findings for one URL. *start*/*end* locate it in the body; field "link" when it isn't there."""
    info = D.parse_url(url)
    f = lambda *a, **k: _link(a[0], url, start, end, field, *a[1:], **k)  # noqa: E731
    out: List[Finding] = []
    if info.scheme in ("javascript", "data", "vbscript", "file"):
        return [f("SCRIPT_URL", f"Link uses a {info.scheme}: address, which can run code or hide content", 45, "confirmed")]
    if not info.valid:
        return [f("MALFORMED_URL", "Link address could not be read as a normal web address", 5, "heuristic")]
    if info.userinfo:
        out.append(f("USERINFO_IN_URL", f"Link hides its real destination ({info.host}) after an @ sign", 40, "confirmed"))
    if info.is_ip:
        out.append(f("IP_HOST", f"Link goes to a raw IP address ({info.registered}) instead of a named website", 35, "confirmed"))
    imp = B.impersonation(info)
    if imp:
        label, brand, detail = imp
        if label == "BRAND_OTHER_TLD" and info.suffix.split(".")[-1] not in D.RISKY_TLDS:
            out.append(f(label, f"Link may not belong to {brand.name}: {detail}", 10, "heuristic", category="impersonation"))
        else:
            weight = {"HOMOGRAPH_DOMAIN": 55, "TYPOSQUAT_DOMAIN": 50}.get(label, 45)
            out.append(f(label, f"Link imitates {brand.name}: {detail}", weight, "confirmed", category="impersonation"))
    elif info.idn and len(info.scripts - {"LATIN"}) and "LATIN" in info.scripts:
        out.append(f("MIXED_SCRIPT_DOMAIN", f"Domain mixes alphabets ({info.unicode_host}), a common disguise", 40, "confirmed",
                     category="impersonation"))
    elif info.idn:
        out.append(f("IDN_DOMAIN", f"Domain uses non-Latin characters ({info.unicode_host} / {info.host})", 10, "heuristic"))
    if D.is_shortener(info):
        out.append(f("SHORTENER", f"Link is shortened ({info.registered}), hiding where it goes", 10, "heuristic"))
    if D.is_user_content(info):
        out.append(f("FREE_HOSTING", f"Link is on a free hosting or form service ({info.registered}) where anyone can publish",
                     12, "heuristic"))
    if not info.is_ip and info.suffix.split(".")[-1] in D.RISKY_TLDS:
        out.append(f("RISKY_TLD", f"Domain ends in .{info.suffix}, which is often used for throwaway sites", 8, "heuristic"))
    if info.subdomain.count(".") >= 2:
        out.append(f("DEEP_SUBDOMAINS", f"Address has many subdomain levels ({info.host})", 8, "heuristic"))
    if info.port not in (None, 80, 443):
        out.append(f("NONSTANDARD_PORT", f"Link uses an unusual port ({info.port})", 8, "heuristic"))
    if info.scheme == "http" and url.lower().startswith("http://"):
        out.append(f("NO_HTTPS", "Link is not encrypted (http://). This alone does not mean it is unsafe", 4, "heuristic"))
    return out


def analyze_url(url: str) -> List[str]:
    """Red-flag names for one URL, e.g. ["ip_host", "risky_tld"]."""
    return [f.label.lower() for f in url_findings(url)]


def analyze_rules(text: str) -> List[Finding]:
    """Content findings plus findings for every URL written in *text*; spans index into *text*."""
    urls = D.find_urls(text)
    out = content_findings(text, skip=[(s, e) for _, s, e in urls])
    for url, s, e in urls:
        out += url_findings(url, s, e, "body")
    return out


# --- cross-checks -------------------------------------------------------------

def correlate(findings: List[Finding], claimed: List[B.Brand], url_spots: List[tuple],
              sender: Optional[D.UrlInfo] = None) -> List[Finding]:
    """Evidence that only appears when content and links are looked at together.

    url_spots: (url, start, end, field) for every link in the message.
    sender: the email's sender domain when nothing about the sender looks wrong. A link to
    the sender's own site is not "unverified" just because the email mentions other brands
    (a newsletter listing Flipkart and Amazon competitions); requests are still checked.
    """
    out = []
    asks = any(f.label in REQUEST_LABELS for f in findings)
    names = ", ".join(b.name for b in claimed)
    for url, s, e, field in url_spots:
        info = D.parse_url(url)
        if not info.valid or B.official_for(info):
            continue
        own = sender is not None and (D.same_org(info, sender) or D.is_mail_infra(info))
        short = D.is_shortener(info)
        if asks and claimed:
            out.append(_link("REQUEST_TO_UNOFFICIAL_LINK", url, s, e, field,
                             f"Mentions {names} and asks for details or payment, but the link goes to {info.registered}, "
                             f"which is not one of their domains", 45, "confirmed", "credential_harvesting"))
        elif asks:
            out.append(_link("REQUEST_WITH_LINK", url, s, e, field,
                             f"Asks for details or payment through a link to {info.registered}", 15, "heuristic",
                             "credential_harvesting"))
        elif own:
            continue
        elif claimed and short:
            out.append(_link("BRAND_SHORT_LINK", url, s, e, field,
                             f"Mentions {names} but uses a shortened link ({info.registered})", 10, "heuristic",
                             "impersonation"))
        elif claimed:
            out.append(_link("BRAND_LINK_UNVERIFIED", url, s, e, field,
                             f"Mentions {names} but links to {info.registered}, which is not one of their domains",
                             15, "heuristic", "impersonation"))
    return out
