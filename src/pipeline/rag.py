"""Private RAG: retrieval-augmented answers over sanitized documents only.

  ingest   document -> sanitize() (patterns + NER model) -> chunk -> BM25 index
  ask      question -> sanitize() -> BM25 retrieve -> local LLM (Ollama) or
           extractive fallback -> output scan (sanitize the answer again)

Raw text never enters the index or the LLM prompt: both only ever see
[REDACTED:TYPE] placeholders. Each visitor (X-PL-Session id) gets a
separate in-memory index that expires after 3 idle hours.

Config (env): OLLAMA_URL (default http://localhost:11434), RAG_MODEL
(default qwen2.5:3b), RAG_LLM=0 to force the extractive fallback.

Run:
    python -m src.pipeline.rag some.pdf "who is the account holder?"
"""
from __future__ import annotations

import math
import os
import re
import sys
import threading
import time
import uuid
from collections import Counter

import requests

from src.pipeline.sanitize import sanitize

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
RAG_MODEL = os.environ.get("RAG_MODEL", "qwen2.5:3b")
CHUNK_CHARS, CHUNK_OVERLAP = 700, 120

_TOKEN = re.compile(r"\[REDACTED:[A-Z]+\]|[a-z0-9]+", re.I)
_STOP = set("a an and are as at be but by for from has have he her his i if in into is it its of on or our she "
            "so that the their them there they this to was we were what when where which who will with you your".split())


def tokens(text: str) -> list[str]:
    out = []
    for t in _TOKEN.findall(text.lower()):
        if t.startswith("[redacted:"):
            out.append(t.upper())  # placeholders are indexed as their own tokens
        elif t not in _STOP and len(t) > 1:
            out.append(t)
    return out


# Words in a question that point at a redacted value, so "what was the OTP?"
# retrieves the chunk containing [REDACTED:OTP].
PLACEHOLDER_WORDS = {
    "OTP": "otp passcode password pin code verification",
    "EMAIL": "email mail e-mail",
    "PHONE": "phone mobile number contact call landline helpline whatsapp",
    "CARD": "card credit debit",
    "PAN": "pan tax",
    "IP": "ip address login device",
    "URL": "url link website site",
    "PERSON": "name holder person who nominee manager",
}
_WORD_TO_PH = {w: f"[REDACTED:{lab}]" for lab, ws in PLACEHOLDER_WORDS.items() for w in ws.split()}


def query_tokens(text: str) -> list[str]:
    toks = tokens(text)
    words = {t for t in _TOKEN.findall(text.lower())}  # include stop words like "who"
    return toks + sorted({_WORD_TO_PH[w] for w in words if w in _WORD_TO_PH})


def chunk(text: str, size: int = CHUNK_CHARS, overlap: int = CHUNK_OVERLAP) -> list[str]:
    text = re.sub(r"[ \t]+", " ", text).strip()
    if len(text) <= size:
        return [text] if text else []
    out, start = [], 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):  # end on a sentence or line break when possible
            cut = max(text.rfind(". ", start + size // 2, end), text.rfind("\n", start + size // 2, end))
            if cut > 0:
                end = cut + 1
        out.append(text[start:end].strip())
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return [c for c in out if c]


class Index:
    """In-memory BM25 index over sanitized chunks."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.docs: dict[str, dict] = {}
        self.chunks: list[dict] = []  # {doc_id, page, text, toks, tf}
        self.df: Counter = Counter()

    def add(self, name: str, pages_sanitized: list[str], redactions: int, kind: str) -> dict:
        # Re-uploading a document with the same name replaces it instead of duplicating it.
        for old in [d["id"] for d in self.docs.values() if d["name"] == name and d["kind"] == kind]:
            self.remove(old)
        doc_id = uuid.uuid4().hex[:10]
        new = []
        for p, text in enumerate(pages_sanitized, 1):
            for c in chunk(text):
                toks = tokens(c)
                new.append({"doc_id": doc_id, "page": p, "text": c, "toks": toks, "tf": Counter(toks)})
        with self.lock:
            self.chunks.extend(new)
            for c in new:
                self.df.update(set(c["toks"]))
            self.docs[doc_id] = {"id": doc_id, "name": name, "kind": kind, "pages": len(pages_sanitized),
                                 "chunks": len(new), "redactions": redactions, "added": time.time()}
        return self.docs[doc_id]

    def remove(self, doc_id: str) -> bool:
        with self.lock:
            if doc_id not in self.docs:
                return False
            del self.docs[doc_id]
            self.chunks = [c for c in self.chunks if c["doc_id"] != doc_id]
            self.df = Counter()
            for c in self.chunks:
                self.df.update(set(c["toks"]))
        return True

    def clear(self) -> None:
        with self.lock:
            self.docs.clear(); self.chunks.clear(); self.df.clear()

    def search(self, query: str, k: int = 4, k1: float = 1.5, b: float = 0.75) -> list[dict]:
        q = query_tokens(query)
        with self.lock:
            n = len(self.chunks)
            if not n or not q:
                return []
            avg = sum(len(c["toks"]) for c in self.chunks) / n
            scored = []
            for c in self.chunks:
                s = 0.0
                for t in q:
                    f = c["tf"].get(t, 0)
                    if f:
                        idf = math.log(1 + (n - self.df[t] + 0.5) / (self.df[t] + 0.5))
                        s += idf * f * (k1 + 1) / (f + k1 * (1 - b + b * len(c["toks"]) / avg))
                if s > 0:
                    scored.append((s, c))
            scored.sort(key=lambda x: -x[0])
            return [{"doc_id": c["doc_id"], "doc": self.docs[c["doc_id"]]["name"], "page": c["page"],
                     "text": c["text"], "score": round(s, 3)} for s, c in scored[:k]]


# ---- one private index per visitor ----------------------------------------
# The browser sends a random id (X-PL-Session); each id gets its own index,
# so visitors of a shared deployment never see each other's documents.
SESSION_RX = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
LOCAL = "local"  # CLI / requests without an id
MAX_SESSIONS, SESSION_TTL, MAX_DOCS = 500, 3 * 3600, 20


class TooManyDocuments(ValueError):
    pass


class Sessions:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.items: dict[str, list] = {}  # sid -> [Index, last_used]

    def get(self, sid: str | None) -> Index:
        sid = sid if sid and SESSION_RX.match(sid) else LOCAL
        now = time.time()
        with self.lock:
            for k in [k for k, (_, t) in self.items.items() if now - t > SESSION_TTL]:
                del self.items[k]
            if sid not in self.items and len(self.items) >= MAX_SESSIONS:
                del self.items[min(self.items, key=lambda k: self.items[k][1])]
            entry = self.items.setdefault(sid, [Index(), now])
            entry[1] = now
            return entry[0]

    def __len__(self) -> int:
        return len(self.items)


SESSIONS = Sessions()


def index_for(sid: str | None = None) -> Index:
    return SESSIONS.get(sid)


def _add(sid, name, pages, redactions, kind) -> dict:
    idx = index_for(sid)
    if len(idx.docs) >= MAX_DOCS and not any(d["name"] == name for d in idx.docs.values()):
        raise TooManyDocuments(f"Your knowledge base holds up to {MAX_DOCS} documents. Remove one first.")
    return idx.add(name, pages, redactions, kind)


def ingest_pages(name: str, sanitized_pages: list[str], redactions: int, kind: str = "pdf", sid: str | None = None) -> dict:
    return _add(sid, name, sanitized_pages, redactions, kind)


def ingest_text(name: str, text: str, sid: str | None = None) -> dict:
    r = sanitize(text)
    return {**_add(sid, name, [r.sanitized], len(r.detections), "message"), "sanitize": r.to_dict()}


# ---- generation ---------------------------------------------------------------

SYSTEM = ("You answer questions using only the provided context from the user's documents. "
          "Sensitive values in the context were replaced with placeholders like [REDACTED:EMAIL] "
          "before you saw them. Never guess or invent a redacted value; if the answer is a redacted "
          "value, say it is redacted and give its type, e.g. [REDACTED:PHONE]. If the context does "
          "not contain the answer, say so. Be concise and cite pages like (p. 2).")


def llm_status() -> dict:
    if os.environ.get("RAG_LLM", "1") == "0":
        return {"available": False, "detail": "disabled (RAG_LLM=0)"}
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=1.5)
        names = [m["name"] for m in r.json().get("models", [])]
        if RAG_MODEL in names:
            return {"available": True, "model": RAG_MODEL, "detail": "Ollama, on this machine"}
        return {"available": False, "detail": f"Ollama running but model {RAG_MODEL} isn't pulled"}
    except Exception:  # noqa: BLE001
        return {"available": False, "detail": "Ollama isn't reachable from this server"}


def _generate(question: str, hits: list[dict]) -> tuple[str, dict]:
    status = llm_status()
    if status["available"]:
        ctx = "\n\n".join(f"[{h['doc']} p. {h['page']}]\n{h['text']}" for h in hits)
        try:
            r = requests.post(f"{OLLAMA_URL}/api/chat", timeout=90, json={
                "model": RAG_MODEL, "stream": False, "options": {"temperature": 0.1, "num_ctx": 4096},
                "messages": [{"role": "system", "content": SYSTEM},
                             {"role": "user", "content": f"Context:\n{ctx}\n\nQuestion: {question}"}]})
            r.raise_for_status()
            return r.json()["message"]["content"].strip(), {"kind": "llm", **status}
        except Exception as exc:  # noqa: BLE001
            status = {"available": False, "detail": f"LLM call failed: {str(exc)[:120]}"}
    # Extractive fallback: the best-matching sentences from the top passage.
    q = set(query_tokens(question))
    sents = re.split(r"(?<=[.!?])\s+|\n", hits[0]["text"])
    ranked = sorted(sents, key=lambda s: -len(q & set(tokens(s))))
    best = [s.strip() for s in ranked[:2] if s.strip()]
    answer = " ".join(best) + f" (p. {hits[0]['page']})"
    return answer, {"kind": "extractive", **status}


def ask(question: str, k: int = 4, sid: str | None = None) -> dict:
    index = index_for(sid)
    t0 = time.perf_counter()
    q = sanitize(question)  # the question itself can contain PII
    t_q = time.perf_counter()
    hits = index.search(q.sanitized, k)
    t_r = time.perf_counter()
    if not hits:
        answer, gen = ("Nothing in the indexed documents matches that question." if index.chunks
                       else "No documents indexed yet. Upload a PDF or add a message first."), {"kind": "none"}
    else:
        answer, gen = _generate(q.sanitized, hits)
    t_g = time.perf_counter()
    scan = sanitize(answer)  # output scan: anything value-shaped in the answer gets redacted too
    t_s = time.perf_counter()
    return {
        "question": q.to_dict(),
        "retrieved": hits,
        "answer": scan.sanitized,
        "answer_redactions": len(scan.detections),
        "generator": gen,
        "timings_ms": {"sanitize_question": round((t_q - t0) * 1000, 1), "retrieve": round((t_r - t_q) * 1000, 2),
                       "generate": round((t_g - t_r) * 1000, 1), "output_scan": round((t_s - t_g) * 1000, 1),
                       "total": round((t_s - t0) * 1000, 1)},
        "index": {"docs": len(index.docs), "chunks": len(index.chunks)},
    }


def main() -> None:
    from src.pipeline.documents import process_pdf
    doc = process_pdf(open(sys.argv[1], "rb").read())
    ingest_pages(os.path.basename(sys.argv[1]), [p["sanitized"] for p in doc["pages"]], doc["detections"])
    res = ask(sys.argv[2] if len(sys.argv) > 2 else "What is this document about?")
    print("Q (sanitized):", res["question"]["sanitized"])
    for h in res["retrieved"]:
        print(f"  [{h['score']}] p.{h['page']}: {h['text'][:100]}")
    print("A:", res["answer"], "|", res["generator"], res["timings_ms"])


if __name__ == "__main__":
    sys.exit(main())
