"""URL and domain utilities: parsing, registered domains, lookalike helpers.

Registered domains come from the Public Suffix List snapshot bundled with
tldextract. It is never refreshed over the network at runtime, so parsing a
URL never contacts anything. URLs are only parsed here, never fetched.

Usage:
    from src.detection.domains import parse_url, find_urls
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlsplit

import tldextract

from .main import URL_RX, URL_TRAILING

# Offline: bundled PSL snapshot only. Private suffixes (github.io, web.app, ...)
# make each user site its own registered domain. bank.in is RBI's bank-only zone.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                 include_psl_private_domains=True, extra_suffixes=["bank.in"])

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "buff.ly",
    "rebrand.ly", "tiny.cc", "s.id", "v.gd", "t.ly", "bl.ink", "surl.li", "shorturl.asia", "qrco.de",
    "tny.im", "short.gy", "urlz.fr", "clck.ru", "u.to", "shrtco.de",
}

# Hosts where anyone can publish a page. Never evidence of identity, in either direction.
USER_CONTENT = {
    "github.io", "firebaseapp.com", "web.app", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    "r2.dev", "glitch.me", "repl.co", "replit.app", "herokuapp.com", "onrender.com", "ngrok.io",
    "ngrok-free.app", "ngrok.app", "trycloudflare.com", "blogspot.com", "wixsite.com", "weebly.com",
    "webflow.io", "000webhostapp.com", "sites.google.com", "docs.google.com", "forms.gle",
    "script.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "googleusercontent.com", "amazonaws.com", "blob.core.windows.net", "web.core.windows.net",
    "dropboxusercontent.com", "notion.site", "typeform.com", "jotform.com", "framer.app", "carrd.co",
    "godaddysites.com", "square.site", "ipfs.io", "dweb.link",
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.in", "ymail.com", "rocketmail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "rediffmail.com", "aol.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com", "yandex.ru",
    "tutanota.com", "zohomail.in",
}

# Cheap or abuse-heavy TLDs. Only ever a weak heuristic.
RISKY_TLDS = {
    "xyz", "top", "zip", "mov", "click", "link", "buzz", "info", "icu", "cyou", "rest", "sbs", "cfd",
    "monster", "quest", "loan", "work", "fit", "gq", "ml", "cf", "tk", "ga", "live", "online", "site",
    "shop", "vip", "win", "bid", "lol", "country", "kim", "support", "help",
}

# Endings that look like TLDs but are usually file names in plain text.
_FILE_LIKE = {"md", "py", "sh", "js", "rs", "pl", "zip", "mov", "txt", "pdf", "exe", "apk", "doc", "png", "jpg"}

_BARE_DOMAIN = re.compile(
    r"(?<![@\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})"
    r"(?::\d{2,5})?(?:/[^\s<>\"']*)?",
    re.I,
)

# Latin look-alikes from Cyrillic / Greek and common digit swaps.
_CONFUSABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d",
    "ѕ": "s", "һ": "h", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "ı": "i", "ł": "l", "α": "a", "ο": "o",
    "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "ε": "e", "υ": "u", "0": "o", "3": "e", "4": "a",
    "5": "s", "7": "t", "$": "s", "@": "a",
})


@dataclass
class UrlInfo:
    url: str
    valid: bool = False
    scheme: str = ""
    host: str = ""             # lower-case, as written (punycode stays punycode)
    unicode_host: str = ""     # IDN decoded for display and look-alike checks
    port: Optional[int] = None
    userinfo: bool = False     # "user@" before the host
    subdomain: str = ""
    label: str = ""            # registrable label: "paypal" in login.paypal.com
    suffix: str = ""
    registered: str = ""       # label + suffix, or the IP / host when there is none
    is_ip: bool = False
    idn: bool = False
    scripts: Set[str] = field(default_factory=set)


def _to_unicode(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna") if "xn--" in host else host
    except UnicodeError:
        return host


def _scripts(text: str) -> Set[str]:
    out = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            out.add(name.split(" ")[0] if name else "UNKNOWN")
    return out


def _parse_ip(host: str) -> Optional[ipaddress._BaseAddress]:
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", h, re.I):  # 0xC0A80001 / 3232235777 style
        try:
            return ipaddress.ip_address(int(h, 0))
        except ValueError:
            return None
    return None


@lru_cache(maxsize=4096)
def parse_url(url: str) -> UrlInfo:
    info = UrlInfo(url=url)
    raw = url.strip()
    if not raw:
        return info
    candidate = raw if re.match(r"^[a-z][a-z0-9+.-]*:", raw, re.I) else "http://" + raw
    try:
        parts = urlsplit(candidate)
        info.scheme = parts.scheme.lower()
        info.port = parts.port
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError:
        return info
    info.userinfo = "@" in parts.netloc
    if info.scheme in ("javascript", "data", "vbscript", "file"):
        info.valid = True
        return info
    if not host:
        return info
    info.host = host
    info.unicode_host = _to_unicode(host)
    info.idn = "xn--" in host or not host.isascii()
    ip = _parse_ip(host)
    if ip is not None:
        info.is_ip, info.registered, info.valid = True, str(ip), True
        return info
    ext = _EXTRACT(info.unicode_host)
    info.subdomain, info.label, info.suffix = ext.subdomain, ext.domain, ext.suffix
    info.registered = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host
    info.valid = bool(ext.domain and ext.suffix)
    info.scripts = _scripts(info.unicode_host)
    return info


def parse_host(domain: str) -> UrlInfo:
    return parse_url(domain.strip().lower())


def host_matches(info: UrlInfo, names: Set[str]) -> bool:
    """True when the host or its registered domain is one of *names* (or under one)."""
    host = info.unicode_host or info.host
    return any(host == n or host.endswith("." + n) for n in names) or info.registered in names or info.suffix in names


def is_shortener(info: UrlInfo) -> bool:
    return host_matches(info, SHORTENERS)


def is_user_content(info: UrlInfo) -> bool:
    return host_matches(info, USER_CONTENT)


def is_freemail(domain: str) -> bool:
    return parse_host(domain).registered in FREEMAIL


def find_urls(text: str) -> List[Tuple[str, int, int]]:
    """URLs in *text* as (url, start, end): scheme/www links, then bare domains like sbi-kyc.xyz/login."""
    found = []
    for m in URL_RX.finditer(text):
        value = m.group(0).rstrip(URL_TRAILING)
        found.append((value, m.start(), m.start() + len(value)))
    taken = [(s, e) for _, s, e in found]
    for m in _BARE_DOMAIN.finditer(text):
        s = m.start()
        if any(a <= s < b for a, b in taken):
            continue
        value = m.group(0).rstrip(URL_TRAILING)
        info = parse_url(value)
        if not info.valid or info.is_ip or info.suffix.split(".")[-1].lower() in _FILE_LIKE:
            continue
        found.append((value, s, s + len(value)))
    return sorted(found, key=lambda t: t[1])


def unwrap_redirect(href: str) -> str:
    """https://www.google.com/url?q=REAL -> REAL (Gmail wraps links this way). Anything else unchanged."""
    try:
        parts = urlsplit(href)
    except ValueError:
        return href
    host = (parts.hostname or "").lower()
    if host in ("google.com", "www.google.com", "www.google.co.in", "google.co.in") and parts.path == "/url":
        qs = parse_qs(parts.query)
        inner = (qs.get("q") or qs.get("url") or [""])[0]
        if inner.lower().startswith(("http://", "https://")):
            return inner
    return href


def skeletons(label: str, keep_hyphens: bool = False) -> Set[str]:
    """Look-alike-folded forms of a domain label ("paypa1" -> "paypal", "rnicrosoft" -> "microsoft")."""
    s = unicodedata.normalize("NFKC", label.lower()).translate(_CONFUSABLE)
    if not keep_hyphens:
        s = s.replace("-", "")
    forms = {s.replace("1", "l"), s.replace("1", "i")}
    return forms | {f.replace("rn", "m").replace("vv", "w") for f in forms}


def osa_distance(a: str, b: str) -> int:
    """Edit distance counting adjacent swaps as one edit (optimal string alignment)."""
    if a == b:
        return 0
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]
