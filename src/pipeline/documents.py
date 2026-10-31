"""PDF documents: extract text page by page and sanitize each page.

Each page goes through the same sanitize() as a message (patterns + NER
model + fail-closed leak check). Raw page text is returned to the uploader
for display but is never stored server-side; only sanitized text is kept
(by the RAG index).

Run:
    python -m src.pipeline.documents some.pdf
"""
from __future__ import annotations

import io
import logging
import sys
import time
from collections import Counter

from pypdf import PdfReader

from src.pipeline.sanitize import sanitize

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


def process_pdf(data: bytes) -> dict:
    """Extract and sanitize every page. Raises SanitizationError (fail closed) or DocumentError."""
    t0 = time.perf_counter()
    pages = extract_pages(data)
    out, labels = [], Counter()
    for i, text in enumerate(pages, 1):
        r = sanitize(text).to_dict()
        r["page"] = i
        labels.update(d["label"] for d in r["detections"])
        out.append(r)
    return {
        "pages": out,
        "page_count": len(out),
        "truncated": len(PdfReader(io.BytesIO(data)).pages) > MAX_PAGES,
        "detections": sum(len(p["detections"]) for p in out),
        "by_label": dict(labels.most_common()),
        "leaked": sum(p["leaked"] for p in out),
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
    }


def main() -> None:
    res = process_pdf(open(sys.argv[1], "rb").read())
    print(f"{res['page_count']} pages, {res['detections']} detections {res['by_label']}, "
          f"leaked {res['leaked']}, {res['latency_ms']} ms")
    for p in res["pages"][:2]:
        print(f"--- page {p['page']}\n{p['sanitized'][:400]}")


if __name__ == "__main__":
    sys.exit(main())
