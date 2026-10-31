"""Undo the tricks scammers use to slip past filters, before any check runs.

Owner: Armaan. fold(text) returns two views of the message plus a map back to the original:
  text   invisible characters removed, Unicode "styled" letters made plain (NFKC: 𝐒𝐁𝐈, ＳＢＩ -> SBI),
         and disguised links restored (hxxp:// -> http://, sbi-kyc[.]xyz -> sbi-kyc.xyz). Links are
         read from this view, so a look-alike letter inside a domain is still seen and still counts
         as proven impersonation.
  words  the same, with look-alike letters inside English words folded to Latin (Cyrillic "а" in
         "аccount") and digit swaps undone ("v3rify" -> "verify", "l0gin" -> "login"). Wording rules,
         brand names and the text model read this view. It has the same length as `text`.
Every finding found in either view is mapped back to positions in the original message, so
highlights land on what the user actually received. Using any of these tricks is itself evidence:
`tricks` lists what was found and engine.py turns it into an OBFUSCATION finding.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List

# Characters with no visible width that are used to split words ("re​fund") past keyword filters.
INVISIBLE = {0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x00AD,
             0x180E, 0x034F, 0x061C, 0x115F, 0x1160, 0x3164, 0xFFA0}
# Emoji use U+200D (zero-width joiner) and U+FE0F legitimately; those are only a trick between letters.
_EMOJI_GLUE = {0x200D, 0xFE0E, 0xFE0F}

# Look-alike letters from other alphabets, folded to Latin only inside words that are otherwise Latin.
CONFUSABLE: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ь": "b", "к": "k", "м": "m", "т": "t", "н": "h", "в": "b",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "ε": "e", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X", "ɡ": "g", "ı": "i", "ɑ": "a",
}
# Digits and symbols swapped into words. Only applied between two letters ("v3rify", "acc0unt"), and
# only when the result is a word scams use, so "h1n1" or "w3c" stay as they are.
LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
SCAM_WORDS = re.compile(
    r"verif|account|login|log-?in|signin|password|passcode|bank|update|kyc|otp|refund|payment|paypal|wallet|secure|"
    r"suspend|block|confirm|reward|prize|winner|lottery|cashback|aadhaa?r|upi|amazon|paytm|phonepe|google|apple|"
    r"microsoft|netflix|sbi|hdfc|icici|axis|urgent|claim|offer|credit|debit|card|customer|support|helpdesk")

_DEFANG = [
    (re.compile(r"\bhxxps\b", re.I), "https"),
    (re.compile(r"\bhxxp\b", re.I), "http"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
]


@dataclass
class Folded:
    text: str                   # links and UPI IDs are read from this
    words: str                  # wording rules, brands and the text model read this (same length as text)
    orig: List[int]             # orig[i]: index in the original message of text[i]; orig[len(text)] = len(original)
    tricks: Dict[str, int] = field(default_factory=dict)  # trick name -> how many

    def start(self, i):
        return None if i is None else self.orig[min(max(i, 0), len(self.orig) - 1)]

    def end(self, i):
        if i is None:
            return None
        if i <= 0:
            return self.orig[0]
        return self.orig[min(i - 1, len(self.orig) - 2)] + 1 if len(self.orig) > 1 else 0


def _is_letter(ch: str) -> bool:
    return ch.isalpha()


def fold(original: str) -> Folded:
    tricks: Dict[str, int] = {}
    chars: List[str] = []
    orig: List[int] = []

    # 1. invisible characters (but leave emoji glue alone unless it sits between letters)
    for i, ch in enumerate(original):
        cp = ord(ch)
        if cp in INVISIBLE or cp in _EMOJI_GLUE:
            prev_letter = i > 0 and _is_letter(original[i - 1])
            next_letter = i + 1 < len(original) and _is_letter(original[i + 1])
            if cp in _EMOJI_GLUE and not (prev_letter and next_letter):
                chars.append(ch)
                orig.append(i)
                continue
            if prev_letter or next_letter:
                tricks["invisible"] = tricks.get("invisible", 0) + 1
            continue
        # 2. styled letters: NFKC turns 𝐒, Ｓ, ⓢ... into S. One character can become several.
        folded = unicodedata.normalize("NFKC", ch) if ord(ch) > 127 else ch
        if folded != ch and folded.isascii() and folded.isalpha() and len(folded) == 1 and ch.isalpha():
            tricks["styled"] = tricks.get("styled", 0) + 1  # 𝐒 / Ｓ / ⓢ; not "ﬁ" ligatures or superscript digits
        for c in folded:
            chars.append(c)
            orig.append(i)
    text = "".join(chars)

    # 3. disguised links: hxxp://, [.] / (dot)
    for rx, repl in _DEFANG:
        out_chars: List[str] = []
        out_orig: List[int] = []
        last = 0
        hits = 0
        for m in rx.finditer(text):
            out_chars.extend(text[last:m.start()])
            out_orig.extend(orig[last:m.start()])
            out_chars.extend(repl)
            out_orig.extend([orig[m.start()]] * len(repl))
            last = m.end()
            hits += 1
        if hits:
            out_chars.extend(text[last:])
            out_orig.extend(orig[last:])
            text, orig = "".join(out_chars), out_orig
            tricks["disguised_link"] = tricks.get("disguised_link", 0) + hits
    orig = orig + [len(original)]

    # 4. words view: look-alike letters and digit swaps inside words (1:1, same length).
    #    Links and email/UPI addresses keep their letters exactly as they are.
    from .domains import find_urls  # here, not at the top: domains.py is imported by most modules
    keep = [(s, e) for _, s, e in find_urls(text)] + [m.span() for m in re.finditer(r"\S+@\S+", text)]
    w = list(text)
    for m in re.finditer(r"[^\s.,;:!?()\[\]{}<>\"'/\\|]+", text):
        token = m.group(0)
        if any(s <= m.start() < e for s, e in keep):
            continue
        latin = sum(1 for c in token if "a" <= c.lower() <= "z")
        foreign = [i for i, c in enumerate(token) if c in CONFUSABLE]
        if foreign and latin:
            for i in foreign:
                w[m.start() + i] = CONFUSABLE[token[i]]
            tricks["lookalike_letters"] = tricks.get("lookalike_letters", 0) + 1
        if latin >= 2:
            cand = list(w[m.start():m.end()])
            swapped = False
            for i in range(1, len(token) - 1):
                c = token[i]
                if c in LEET and token[i - 1].isalpha() and (token[i + 1].isalpha() or token[i + 1] in LEET):
                    cand[i] = LEET[c]
                    swapped = True
            if swapped and SCAM_WORDS.search("".join(cand).lower()):
                w[m.start():m.end()] = cand
                tricks["digit_swap"] = tricks.get("digit_swap", 0) + 1
    return Folded(text, "".join(w), orig, tricks)


TRICK_NAMES = {
    "invisible": "invisible characters inside words",
    "styled": "styled look-alike letters (like 𝐒𝐁𝐈)",
    "disguised_link": "a disguised link (hxxp:// or [.])",
    "lookalike_letters": "letters from another alphabet that look like English ones",
    "digit_swap": "numbers swapped in for letters (like v3rify)",
}
