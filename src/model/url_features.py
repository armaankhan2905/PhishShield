"""Lexical features for the URL model. Computed from the URL text only: nothing is fetched.

Owner: Govind. Used identically at training time (train_url.py) and at
prediction time (predict.py). URLs are canonicalised first (scheme and leading
www. removed), because the training corpora differ in how often they include them.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List

from src.detection import domains as D
from src.model.prepare import canonical_url

KEYWORDS = ("login", "signin", "verify", "secure", "account", "update", "bank", "confirm", "password", "webscr",
            "wp-", "admin", "kyc", "free", "bonus", "gift", "reward", "billing", "support", "auth", "session", "token")

FEATURES: List[str] = [
    "len", "host_len", "path_len", "query_len", "dots_host", "hyphens_host", "digits_host", "digit_ratio_host",
    "host_entropy", "url_entropy", "subdomain_levels", "is_ip", "has_at", "has_port", "idn", "risky_tld",
    "suffix_len", "label_len", "path_segments", "query_params", "special_chars", "double_slash_path",
    "path_ext_php", "path_ext_html", "path_ext_exe", "shortener", "user_content", "upper_ratio", "pct_encoded",
    "keyword_hits", "long_token", "hex_token",
] + [f"kw_{k}" for k in KEYWORDS]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def features(url: str) -> Dict[str, float]:
    c = canonical_url(url)
    info = D.parse_url(c)
    host, _, rest = c.partition("/")
    path, _, query = ("/" + rest).partition("?")
    low = c.lower()
    tokens = re.split(r"[/?=&._-]+", rest)
    f = {
        "len": len(c), "host_len": len(host), "path_len": len(path), "query_len": len(query),
        "dots_host": host.count("."), "hyphens_host": host.count("-"),
        "digits_host": sum(ch.isdigit() for ch in host),
        "digit_ratio_host": sum(ch.isdigit() for ch in host) / max(1, len(host)),
        "host_entropy": _entropy(host), "url_entropy": _entropy(c),
        "subdomain_levels": info.subdomain.count(".") + 1 if info.subdomain else 0,
        "is_ip": float(info.is_ip), "has_at": float("@" in c), "has_port": float(info.port not in (None, 80, 443)),
        "idn": float(info.idn), "risky_tld": float(info.suffix.split(".")[-1] in D.RISKY_TLDS if info.suffix else 0),
        "suffix_len": len(info.suffix), "label_len": len(info.label),
        "path_segments": path.count("/"), "query_params": query.count("&") + (1 if query else 0),
        "special_chars": sum(ch in "%=&~_+!$*,;" for ch in c), "double_slash_path": float("//" in path),
        "path_ext_php": float(".php" in path.lower()), "path_ext_html": float(bool(re.search(r"\.html?\b", path.lower()))),
        "path_ext_exe": float(bool(re.search(r"\.(exe|apk|scr|zip|rar)\b", path.lower()))),
        "shortener": float(D.is_shortener(info)) if info.valid else 0.0,
        "user_content": float(D.is_user_content(info)) if info.valid else 0.0,
        "upper_ratio": sum(ch.isupper() for ch in rest) / max(1, len(rest)),
        "pct_encoded": float(c.count("%")),
        "long_token": float(max((len(t) for t in tokens), default=0)),
        "hex_token": float(bool(re.search(r"[0-9a-f]{16,}", low))),
    }
    hits = 0
    for k in KEYWORDS:
        v = float(k in low)
        f[f"kw_{k}"] = v
        hits += v
    f["keyword_hits"] = hits
    return f


def matrix(urls: List[str]) -> List[List[float]]:
    return [[row[name] for name in FEATURES] for row in map(features, urls)]
