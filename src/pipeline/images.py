"""Screenshots and photos -> text and QR codes, entirely on this computer.

Owner: Ryan. Most Indian scams arrive as a WhatsApp or SMS screenshot, or as a QR code to
"scan to receive". This reads both:
  - QR codes with OpenCV's built-in detector (several tries: as is, grey, enlarged).
  - Text with RapidOCR (ONNX models bundled in the pip package, no network).
The image is decoded in memory and never stored. OCR is optional: if RapidOCR isn't installed
the QR codes are still read, and the response says the text couldn't be read.
"""
from __future__ import annotations

import logging
import threading
from typing import List, Optional

logger = logging.getLogger(__name__)

IMAGE_TYPES = (".png", ".jpg", ".jpeg", ".webp", ".bmp")
MAX_SIDE = 2400          # larger images are scaled down before OCR (screenshots are rarely bigger)
MIN_CONFIDENCE = 0.5     # OCR lines below this are dropped

_ocr = None
_ocr_lock = threading.Lock()
_ocr_error: Optional[str] = None


class ImageError(ValueError):
    """The image can't be read. Message is safe to show."""


def ocr_available() -> bool:
    return _engine() is not None


def _engine():
    global _ocr, _ocr_error
    if _ocr is None and _ocr_error is None:
        with _ocr_lock:
            if _ocr is None and _ocr_error is None:
                try:
                    from rapidocr_onnxruntime import RapidOCR
                    _ocr = RapidOCR()
                except Exception as exc:  # noqa: BLE001 - OCR is optional
                    _ocr_error = f"{type(exc).__name__}: {exc}"
                    logger.warning("OCR unavailable (%s); images will be read for QR codes only", _ocr_error)
    return _ocr


def _decode(data: bytes):
    import cv2
    import numpy as np
    img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ImageError("Couldn't read the image. Upload a PNG, JPG or WebP screenshot.")
    h, w = img.shape[:2]
    if max(h, w) > MAX_SIDE:
        scale = MAX_SIDE / max(h, w)
        img = cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
    return img


def read_qr(img) -> List[str]:
    """Payloads of every QR code found, in order, without duplicates."""
    import cv2
    det = cv2.QRCodeDetector()
    found: List[str] = []
    grey = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    tries = [img, grey]
    if max(img.shape[:2]) < 1200:
        tries.append(cv2.resize(grey, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC))
    for im in tries:
        try:
            ok, texts, _, _ = det.detectAndDecodeMulti(im)
        except cv2.error:
            ok, texts = False, []
        if not ok or not any(texts):
            try:
                single, _, _ = det.detectAndDecode(im)
                texts = [single]
            except cv2.error:
                texts = []
        for t in texts or []:
            if t and t not in found:
                found.append(t)
        if found:
            break
    return found


def read_text(img) -> Optional[str]:
    """OCR text in reading order (top to bottom, left to right), or None when OCR isn't available."""
    eng = _engine()
    if eng is None:
        return None
    with _ocr_lock:  # the ONNX session is shared; keep it to one image at a time
        result, _ = eng(img)
    lines = []
    for box, text, conf in result or []:
        try:
            conf = float(conf)
        except (TypeError, ValueError):
            conf = 0.0
        if conf >= MIN_CONFIDENCE and text.strip():
            top = min(p[1] for p in box)
            left = min(p[0] for p in box)
            height = max(p[1] for p in box) - top
            lines.append((top, left, height, text.strip()))
    lines.sort()
    # Boxes whose tops are within half a line of each other are one visual line.
    out, row, row_top = [], [], None
    for top, left, height, text in lines:
        if row and top - row_top > max(8, height * 0.5):
            out.append(" ".join(t for _, t in sorted(row)))
            row = []
        if not row:
            row_top = top
        row.append((left, text))
    if row:
        out.append(" ".join(t for _, t in sorted(row)))
    return "\n".join(out)


def read_image(data: bytes) -> dict:
    """{"text", "qr", "ocr"} where ocr is "ran" or "unavailable"."""
    img = _decode(data)
    qr = read_qr(img)
    text = read_text(img)
    return {"text": text or "", "qr": qr, "ocr": "unavailable" if text is None else "ran"}
