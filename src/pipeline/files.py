"""Uploaded files -> an analyze() request: .eml emails, PDFs and plain text.

Owner: Ryan. Nothing here renders or runs file content:
  - HTML email bodies are reduced to text with the standard-library parser:
    <script>, <style>, <head> and hidden elements are dropped, and each
    <a href> becomes a {text, href} link so link-text mismatches can be checked.
  - Attachments are listed by name only; they are never opened.
  - PDFs are read with pypdf (text only, first 30 pages).
Files are processed in memory and not stored.
"""
from __future__ import annotations

import email
import re
from email import policy
from email.utils import getaddresses
from html.parser import HTMLParser
from typing import List, Optional

from src.pipeline.documents import DocumentError, extract_pages

MAX_BYTES = 10 * 1024 * 1024
MAX_TEXT = 20_000
TEXT_TYPES = (".txt", ".text")


class FileError(ValueError):
    """The upload can't be analysed (wrong type, too large, unreadable). Message is safe to show."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# --- HTML -> text + links ------------------------------------------------------------

_SKIP = {"script", "style", "head", "title", "noscript", "template", "svg", "object", "iframe"}
_BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table", "section", "blockquote", "hr"}
_VOID = {"br", "hr", "img", "input", "meta", "link", "area", "base", "col", "embed", "source", "track", "wbr"}
_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])|opacity\s*:\s*0(?![.\d])", re.I)


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: List[str] = []
        self.links: List[dict] = []
        self.hidden_text = 0            # text blocks hidden with CSS / the hidden attribute (a filter-evasion trick)
        self._stack: List[tuple] = []   # (tag, hides)
        self._link: Optional[dict] = None

    def _hidden(self) -> bool:
        return any(h for _, h in self._stack)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        hides = tag in _SKIP or "hidden" in a or bool(_HIDDEN_STYLE.search(a.get("style") or ""))
        if tag in _BLOCK and not self._hidden():
            self.out.append("\n")
        if tag == "a" and a.get("href") and not self._hidden():
            self._link = {"text": "", "href": a["href"].strip()}
        if tag not in _VOID:
            self._stack.append((tag, hides))

    def handle_endtag(self, tag):
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break
        if tag == "a" and self._link is not None:
            self._link["text"] = " ".join(self._link["text"].split())[:500]
            self.links.append(self._link)
            self._link = None
        if tag in _BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if self._hidden():
            if data.strip() and not any(t in _SKIP for t, _ in self._stack):
                self.hidden_text += 1
            return
        self.out.append(data)
        if self._link is not None:
            self._link["text"] += data


def html_to_text(html: str) -> tuple:
    """(text, links, hidden_text_blocks) from an HTML document, without running anything in it."""
    p = _Text()
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001 - malformed HTML still yields what was parsed
        pass
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(p.out))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    links = [l for l in p.links if l["href"].lower().startswith(("http://", "https://"))]
    return text, links, p.hidden_text


# --- .eml ------------------------------------------------------------------------------

def _addr(value) -> str:
    pairs = getaddresses([str(value or "")])
    if not pairs or not pairs[0][1]:
        return ""
    name, addr = pairs[0]
    return f"{name} <{addr}>" if name else addr


def parse_eml(data: bytes) -> dict:
    try:
        msg = email.message_from_bytes(data, policy=policy.default)
    except Exception as exc:  # noqa: BLE001
        raise FileError(f"Couldn't read the email file: {type(exc).__name__}") from exc
    if not (msg.get("From") or msg.get("Subject")) or not msg.get_content_type():
        raise FileError("That doesn't look like an email file (.eml). Save the email with 'Download message' and upload that.")
    plain = html = None
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename():
            attachments.append(part.get_filename() or part.get_content_type())
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:  # noqa: BLE001 - unknown charset etc.
            continue
        if ctype == "text/plain" and plain is None:
            plain = content
        elif ctype == "text/html" and html is None:
            html = content
    links, hidden = [], 0
    if html:
        html_text, links, hidden = html_to_text(html)
    text = (plain or "").strip() or (html_text if html else "")
    return {
        "text": text[:MAX_TEXT],
        "kind": "email",
        "email": {"from": _addr(msg.get("From")), "reply_to": _addr(msg.get("Reply-To")),
                  "subject": str(msg.get("Subject") or "")[:1000]},
        "links": links[:500],
        "file": {"type": "eml", "attachments": attachments[:20], "hidden_html_blocks": hidden,
                 "truncated": len(text) > MAX_TEXT},
    }


# --- entry point ------------------------------------------------------------------------

def from_upload(name: str, data: bytes) -> dict:
    """An analyze() request plus a "file" summary. Raises FileError with a user-facing message."""
    if len(data) > MAX_BYTES:
        raise FileError(f"The file is larger than {MAX_BYTES // (1024 * 1024)} MB.", 413)
    if not data.strip():
        raise FileError("The file is empty.")
    lower = (name or "").lower()
    if lower.endswith(".eml") or (not lower.endswith((".pdf",) + TEXT_TYPES) and re.match(rb"(?i)(received|return-path|from|delivered-to|mime-version|message-id):", data[:200])):
        req = parse_eml(data)
    elif lower.endswith(".pdf") or data.startswith(b"%PDF"):
        try:
            pages = extract_pages(data)
        except DocumentError as exc:
            raise FileError(str(exc)) from exc
        text = "\n\n".join(p for p in pages if p)
        req = {"text": text[:MAX_TEXT], "kind": "auto", "email": None, "links": [],
               "file": {"type": "pdf", "pages": len(pages), "truncated": len(text) > MAX_TEXT}}
    elif lower.endswith(TEXT_TYPES):
        text = data.decode("utf-8", errors="replace")
        req = {"text": text[:MAX_TEXT], "kind": "auto", "email": None, "links": [],
               "file": {"type": "txt", "truncated": len(text) > MAX_TEXT}}
    else:
        raise FileError("Upload an email (.eml), a PDF or a text file (.txt).", 415)
    if not req["text"].strip() and not req["links"]:
        raise FileError("No readable text was found in the file.")
    req["file"]["name"] = (name or "upload").rsplit("/", 1)[-1].rsplit("\\", 1)[-1][:120]
    return req
