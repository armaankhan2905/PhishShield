"""Lazy-loaded URL and text models for the detection engine.

Owner: Govind. Same pattern as the old PrivacyLens NER loader: a model loads on
first use, and if its file is missing or fails to load, status() says why and
the engine reports that layer as "unavailable" instead of guessing.

Env:
    PHISHSHIELD_MODELS=0       disable both models
    PHISHSHIELD_URL_MODEL=0    disable the URL model only
    PHISHSHIELD_TEXT_MODEL=0   disable the text model only
"""
from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

import src.model  # noqa: F401  (sets LOKY_MAX_CPU_COUNT before joblib loads)

logger = logging.getLogger(__name__)

MODELS = Path(__file__).resolve().parents[2] / "models"
FILES = {"url": MODELS / "url_model.joblib", "text": MODELS / "text_model.joblib"}
ENV = {"url": "PHISHSHIELD_URL_MODEL", "text": "PHISHSHIELD_TEXT_MODEL"}

_lock = threading.Lock()
_loaded: Dict[str, object] = {}
_status: Dict[str, dict] = {k: {"state": "unloaded", "detail": "", "version": None} for k in FILES}


def _enabled(kind: str) -> bool:
    return os.environ.get("PHISHSHIELD_MODELS", "1") != "0" and os.environ.get(ENV[kind], "1") != "0"


def _load(kind: str) -> None:
    if not _enabled(kind):
        _status[kind] = {"state": "disabled", "detail": f"{ENV[kind]}=0 or PHISHSHIELD_MODELS=0", "version": None}
        return
    path = FILES[kind]
    if not path.exists():
        _status[kind] = {"state": "missing", "detail": f"{path.name} not found (run python -m src.model.train_{kind})",
                         "version": None}
        return
    t0 = time.perf_counter()
    try:
        import joblib
        bundle = joblib.load(path)
        _loaded[kind] = bundle["model"]
    except Exception as exc:  # noqa: BLE001
        _status[kind] = {"state": "error", "detail": str(exc)[:200], "version": None}
        return
    _status[kind] = {"state": "loaded", "detail": path.name, "version": bundle.get("version"),
                     "load_ms": round((time.perf_counter() - t0) * 1000, 1)}
    logger.info("%s model loaded (%s)", kind, bundle.get("version"))


def status(kind: str) -> dict:
    """Load on first call; re-check the environment so tests can switch models off."""
    if not _enabled(kind):
        return {"state": "disabled", "detail": "switched off by environment", "version": None}
    if _status[kind]["state"] in ("unloaded", "disabled"):
        with _lock:
            if _status[kind]["state"] in ("unloaded", "disabled"):
                _load(kind)
    return dict(_status[kind])


def available(kind: str) -> bool:
    return status(kind)["state"] == "loaded"


def url_proba(urls: List[str]) -> Optional[List[float]]:
    """Calibrated phishing probability per URL, or None when the URL model isn't available."""
    if not urls or not available("url"):
        return None if not available("url") else []
    from src.model.url_features import matrix
    return [float(p) for p in _loaded["url"].predict_proba(matrix(urls))[:, 1]]


def text_proba(text: str) -> Optional[float]:
    """Calibrated phishing probability for a message, or None when the text model isn't available."""
    if not available("text"):
        return None
    return float(_loaded["text"].predict_proba([text])[:, 1][0])
