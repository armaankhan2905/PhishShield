"""Detection layer: regex + checksum detectors for PII/PCI spans.

Labels match the NER model's label set (src/model/train.py):
CARD, PHONE, PAN, EMAIL, IP, URL, OTP (PERSON / ENTITY come from the model).

Usage:
    from src.detection import detect
    python -m src.detection.main
"""
from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


@dataclass
class DetectionResult:
    text: str
    label: str
    start: int
    end: int
    confidence: float = 1.0
    source: str = "pattern"  # "pattern" or "model"

    def __post_init__(self):
        if self.end <= self.start:
            raise ValueError("end must be > start")


# --- patterns ---------------------------------------------------------------

# 13-19 digits, optionally grouped by single spaces or dashes.
CARD_RX = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
# Indian mobile (optional +91 / 0 prefix) or generic +CC international number.
PHONE_RX = re.compile(
    r"(?<![\w+])(?:"
    r"(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}"
    r"|\+\d{1,3}[\s-]?\(?\d{1,4}\)?(?:[\s-]?\d{2,4}){2,4}"
    r")(?!\d)"
)
PAN_RX = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
# TLD length >= 1 so short test/canary addresses (x@y.z) are still redacted.
EMAIL_RX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]+\b")
IP_RX = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
URL_RX = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
# A 4-8 digit code shortly after an OTP-ish keyword.
OTP_RX = re.compile(
    r"\b(?:otp|one[\s-]?time[\s-]?(?:password|passcode|code)|verification\s+code|"
    r"security\s+code|passcode|auth(?:entication)?\s+code|pin)\b[^\d\n]{0,20}?(?<!\d)(\d{4,8})(?!\d)",
    re.IGNORECASE,
)

URL_TRAILING = ".,;:!?)]}'\""


# --- validators -------------------------------------------------------------

def card_luhn_valid(value: str) -> bool:
    """Return True if the digit string passes the Luhn checksum."""
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def ip_valid(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and int(p) <= 255 for p in parts)


# --- detectors --------------------------------------------------------------

# A detector returns (results, rejected) where rejected counts regex matches
# that failed validation (e.g. Luhn checksum).
Detector = Callable[[str], Tuple[List[DetectionResult], int]]


def _simple(rx: re.Pattern, label: str, conf: float,
            check: Optional[Callable[[str], bool]] = None) -> Detector:
    def run(text: str):
        found, rejected = [], 0
        for m in rx.finditer(text):
            if check is None or check(m.group(0)):
                found.append(DetectionResult(m.group(0), label, m.start(), m.end(), conf))
            else:
                rejected += 1
        return found, rejected
    return run


def _urls(text: str):
    found = []
    for m in URL_RX.finditer(text):
        value = m.group(0).rstrip(URL_TRAILING)
        found.append(DetectionResult(value, "URL", m.start(), m.start() + len(value), 0.9))
    return found, 0


def _otps(text: str):
    return [DetectionResult(m.group(1), "OTP", m.start(1), m.end(1), 0.85)
            for m in OTP_RX.finditer(text)], 0


# Order is priority: when spans overlap, the earlier detector wins.
# (name, label, method, detector)
DETECTORS: list[Tuple[str, str, str, Detector]] = [
    ("url", "URL", "regex: http(s):// or www.", _urls),
    ("email", "EMAIL", "regex: local@domain.tld", _simple(EMAIL_RX, "EMAIL", 0.95)),
    ("card", "CARD", "regex 13-19 digits + Luhn checksum", _simple(CARD_RX, "CARD", 0.95, card_luhn_valid)),
    ("pan", "PAN", "regex: AAAAA9999A (Indian PAN)", _simple(PAN_RX, "PAN", 0.9)),
    ("ip", "IP", "regex dotted quad + octet <= 255", _simple(IP_RX, "IP", 0.9, ip_valid)),
    ("phone", "PHONE", "regex: Indian mobile / +CC international", _simple(PHONE_RX, "PHONE", 0.85)),
    ("otp", "OTP", "4-8 digits after OTP/PIN/code keyword", _otps),
]


def _overlaps(a: DetectionResult, b: DetectionResult) -> bool:
    return a.start < b.end and b.start < a.end


def detect_trace(text: str, model_results: Iterable[DetectionResult] | None = None
                 ) -> Tuple[List[DetectionResult], Dict[str, Any]]:
    """Like detect(), but also returns a per-stage trace for the demo UI."""
    stages = []
    candidates: list[DetectionResult] = []
    for name, label, method, det in DETECTORS:
        t0 = time.perf_counter()
        found, rejected = det(text)
        stages.append({"name": name, "label": label, "method": method,
                       "matches": len(found), "rejected": rejected,
                       "ms": (time.perf_counter() - t0) * 1000})
        candidates.extend(found)
    n_pattern = len(candidates)
    candidates.extend(model_results or [])

    t0 = time.perf_counter()
    accepted: list[DetectionResult] = []
    for cand in candidates:
        if not any(_overlaps(cand, a) for a in accepted):
            accepted.append(cand)
    accepted.sort(key=lambda r: r.start)
    merge = {"candidates": len(candidates), "pattern": n_pattern,
             "model": len(candidates) - n_pattern,
             "dropped_overlap": len(candidates) - len(accepted),
             "kept": len(accepted), "ms": (time.perf_counter() - t0) * 1000}
    return accepted, {"detectors": stages, "merge": merge}


def detect(text: str, model_results: Iterable[DetectionResult] | None = None) -> List[DetectionResult]:
    """Detect sensitive spans in *text*.

    Returns non-overlapping results sorted by start offset. Optional
    *model_results* (e.g. from the NER classifier) are merged after the
    pattern detectors, so patterns win on overlap.
    """
    return detect_trace(text, model_results)[0]


def main() -> None:
    sample = ("Card 4532 0151 1283 0366, phone +91 98765 43210, OTP is 126225, "
              "email a@b.com, PAN ABCDE1234F, ip 8.8.8.8, see https://example.com/x.")
    print("Input:", sample)
    for r in detect(sample):
        print(f"  [{r.label:6s}] {r.text!r} start={r.start} end={r.end} conf={r.confidence:.2f}")


if __name__ == "__main__":
    sys.exit(main())
