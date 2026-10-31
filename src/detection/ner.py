"""Optional local NER layer: Samanyu's fine-tuned classifier (models/pii_classifier).

Loaded lazily and only if the model directory and transformers/torch are
present; otherwise the pattern layer serves alone and status() says why.
Set PRIVACYLENS_NER=0 to disable.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import List, Optional

from .main import (CARD_RX, EMAIL_RX, PAN_RX, PHONE_RX, URL_RX, DetectionResult,
                   card_luhn_valid, ip_valid)

logger = logging.getLogger(__name__)

MODELS = Path(__file__).resolve().parents[2] / "models"
MODEL_DIR = MODELS / "pii_classifier"
# train_v2.py saves weights only; the tokenizer is the base model's.
BASE_DIR = MODELS / "google-bert_bert-base-uncased"
MIN_SCORE = 0.6

_lock = threading.Lock()
_pipe = None
_status = {"state": "unloaded", "detail": "", "load_ms": None}


def _load() -> None:
    global _pipe
    if os.environ.get("PRIVACYLENS_NER", "1") == "0":
        _status.update(state="disabled", detail="PRIVACYLENS_NER=0")
        return
    if not (MODEL_DIR / "model.safetensors").exists() and not (MODEL_DIR / "pytorch_model.bin").exists():
        _status.update(state="missing",
                       detail="No trained weights in models/pii_classifier (run src/model/train_v2.py)")
        return
    tok_dir = MODEL_DIR if (MODEL_DIR / "tokenizer_config.json").exists() else BASE_DIR
    if not (tok_dir / "vocab.txt").exists():
        _status.update(state="missing", detail=f"No tokenizer found in {tok_dir.name}")
        return
    try:
        from transformers import pipeline  # heavy import, only when a model exists
    except Exception as exc:  # noqa: BLE001
        _status.update(state="missing", detail=f"transformers not installed: {exc}")
        return
    t0 = time.perf_counter()
    try:
        _pipe = pipeline("token-classification", model=str(MODEL_DIR),
                         tokenizer=str(tok_dir), aggregation_strategy="simple", device=-1)
    except Exception as exc:  # noqa: BLE001
        _status.update(state="error", detail=str(exc)[:200])
        return
    _status.update(state="loaded", detail=str(MODEL_DIR.name),
                   load_ms=(time.perf_counter() - t0) * 1000)
    logger.info("NER model loaded from %s", MODEL_DIR)


def _whole_word(text: str, start: int, end: int) -> bool:
    before = text[start - 1] if start > 0 else " "
    after = text[end] if end < len(text) else " "
    return not (before.isalnum() or after.isalnum())


OTP_CONTEXT = re.compile(r"\b(otp|code|pin|passcode|password|verification|verify|one[\s-]?time)\b", re.I)


def _otp_ok(text: str, s: int, e: int) -> bool:
    # Unlike the pattern layer the keyword may come before OR after the code.
    window = text[max(0, s - 40):e + 40]
    return (text[s:e].isdigit() and 4 <= e - s <= 8 and _whole_word(text, s, e)
            and not (s > 0 and text[s - 1] in ",.-/:") and not (e < len(text) and text[e] in ",/:")
            and bool(OTP_CONTEXT.search(window)))


# The model proposes, the same rules as the pattern layer verify. Calibrated on
# a separate sample (seed 99) from the one the Evaluation page reports (seed 11).
VALIDATORS = {
    "CARD": lambda t, s, e: bool(CARD_RX.fullmatch(t[s:e])) and card_luhn_valid(t[s:e]),
    "PHONE": lambda t, s, e: bool(PHONE_RX.fullmatch(t[s:e])) and _whole_word(t, s, e),
    "EMAIL": lambda t, s, e: bool(EMAIL_RX.fullmatch(t[s:e])),
    "PAN": lambda t, s, e: bool(PAN_RX.fullmatch(t[s:e])),
    "IP": lambda t, s, e: ip_valid(t[s:e]) and _whole_word(t, s, e) and not t[e:e + 1] == ".",
    "URL": lambda t, s, e: bool(URL_RX.match(t[s:e])),
    "OTP": _otp_ok,
    # Names are capitalised words ("Priya Sharma"); rejects "move", "Pune office".
    "PERSON": lambda t, s, e: (_whole_word(t, s, e) and "@" not in t[max(0, s - 1):e + 1]
                               and all(w[:1].isupper() and w.replace("-", "").replace(".", "").isalpha()
                                       for w in t[s:e].split())),
}


def status(wait: bool = False) -> dict:
    """Model state. Loads on first call; while another thread is loading,
    returns 'loading' immediately (unless wait=True) so requests never stall."""
    if _status["state"] == "unloaded" and _lock.acquire(blocking=wait):
        try:
            if _status["state"] == "unloaded":
                _status.update(state="loading", detail="loading weights")
                _load()
        finally:
            _lock.release()
    elif wait and _status["state"] == "loading":
        with _lock:
            pass
    return dict(_status)


def predict(text: str) -> Optional[List[DetectionResult]]:
    """Model detections for *text*, or None when the model isn't available."""
    if status()["state"] != "loaded" or not text.strip():
        return None
    try:
        ents = _pipe(text)
    except Exception as exc:  # noqa: BLE001 - model failure must not take detection down
        logger.error("NER inference failed, falling back to patterns: %s", exc)
        _status.update(state="error", detail=f"inference failed: {str(exc)[:160]}")
        return None
    out = []
    for ent in ents:
        s, e, label = ent["start"], ent["end"], ent["entity_group"]
        if ent["score"] < MIN_SCORE or e <= s:
            continue
        check = VALIDATORS.get(label)
        if check is None or not check(text, s, e):
            continue
        out.append(DetectionResult(text[s:e], label, s, e, float(ent["score"]), "model"))
    return out


def raw_predict(text: str) -> list:
    """Unvalidated model spans (for evaluation only)."""
    if status()["state"] != "loaded" or not text.strip():
        return []
    return [DetectionResult(text[x["start"]:x["end"]], x["entity_group"], x["start"], x["end"],
                            float(x["score"]), "model")
            for x in _pipe(text) if x["score"] >= MIN_SCORE and x["end"] > x["start"]]
