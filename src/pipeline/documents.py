"""PDF text extraction for uploads (src/pipeline/files.py). Text only, first MAX_PAGES pages;
nothing in the PDF is run, and the file is not stored."""
from __future__ import annotations

import io
import logging

from pypdf import PdfReader

logger = logging.getLogger(__name__)

MAX_BYTES = 10 * 1024 * 1024
MAX_PAGES = 30


class DocumentError(ValueError):
    """Upload can't be processed (not a PDF, too large, no text)."""


def extract_pages(data: bytes) -> list[str]:
    if len(data) > MAX_BYTES:
        raise DocumentError(f"PDF is larger than {MAX_BYTES // (1024 * 1024)} MB.")
    if not data.startswith(b"%PDF"):
        raise DocumentError("That file isn't a PDF.")
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            reader.decrypt("")
        pages = [(p.extract_text() or "").replace("\r\n", "\n").strip() for p in reader.pages[:MAX_PAGES]]
    except Exception as exc:  # noqa: BLE001 - pypdf raises many types on bad input
        raise DocumentError(f"Couldn't read the PDF: {exc}") from exc
    if not any(pages):
        raise DocumentError("No selectable text found. Scanned PDFs need OCR, which isn't supported yet.")
    return pages
