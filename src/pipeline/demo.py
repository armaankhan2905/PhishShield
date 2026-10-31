"""PhishShield server: the web app pages and the analysis API.

Endpoints:
  GET  /                      analyse page (demo/index.html)
  GET  /results               measured results (demo/results.html)
  GET  /how-it-works          how a message is checked (demo/how.html)
  GET  /static/*              page assets
  GET  /shared/*              extension/shared: result logic shared by the web app and the extension
  POST /api/analyze           message / URL / email -> score, verdict, findings (doc/API.md)
  POST /api/analyze/file      .eml / .pdf / .txt / image upload -> the same, plus the text that was analysed
  POST /api/explain           same body as /api/analyze -> explanation from the local AI model, or the template
  POST /api/sanitize          {"text"} -> personal data redacted
  GET  /api/eval              data/eval.json and calibration summary, for the results page
  GET  /api/health            {"ok", "mode", "models", "explainer"}
  GET  /extension             install page for the Chrome extension (demo/extension.html)
  GET  /api/extension         {"version", "download", "store_url"}
  GET  /download/phishshield-extension.zip   the extension, ready for "Load unpacked"

Modes (PHISHSHIELD_MODE): "local" (default, the server runs on the user's machine) or
"hosted" (messages arrive over the network: the UI says so, explanations use the template).
Nothing in this server stores or logs message text.

Run (from repo root):
    python -m src.pipeline.demo            # http://localhost:8000
    python -m src.pipeline.demo --dev      # + extension test pages under /dev/extension/
    PORT=9000 python -m src.pipeline.demo
"""
from __future__ import annotations

import io
import json
import logging
import os
import re
import sys
import threading
import zipfile
from pathlib import Path
from typing import List, Literal, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from src.model import predict
from src.pipeline import explain, files
from src.pipeline.analyze import analyze, mode
from src.pipeline.sanitize import SanitizationError, sanitize

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "demo"
DATA = ROOT / "data"
PAGES = {"results": "results.html", "how-it-works": "how.html", "extension": "extension.html"}
OLD_PAGES = {"evaluation": "/results", "training": "/results", "pipeline": "/how-it-works", "ask": "/"}
MAX_CHARS = 20_000

app = FastAPI(title="PhishShield", docs_url=None, redoc_url=None)


@app.middleware("http")
async def no_stale_pages(request, call_next):
    # Pages and assets change on every deploy; make browsers revalidate.
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache"
    return response


class SanitizeRequest(BaseModel):
    text: str = Field(default="", max_length=MAX_CHARS)
    typed: bool = True


class EmailMeta(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    from_: str = Field(default="", alias="from", max_length=500)
    reply_to: str = Field(default="", max_length=500)
    subject: str = Field(default="", max_length=1_000)


class Link(BaseModel):
    text: str = Field(default="", max_length=2_000)
    href: str = Field(max_length=4_000)


class AnalyzeRequest(BaseModel):
    text: str = Field(default="", max_length=MAX_CHARS)
    kind: Literal["auto", "email", "sms", "url"] = "auto"
    email: Optional[EmailMeta] = None
    links: List[Link] = Field(default_factory=list, max_length=500)
    qr: List[str] = Field(default_factory=list, max_length=10)  # QR payloads read from an uploaded image


def _extension_origins() -> str:
    """CORS for the extension's background worker. PHISHSHIELD_EXTENSION_IDS (comma-separated)
    locks it to published extension IDs; otherwise any extension ID is allowed (local development)."""
    ids = [i.strip() for i in os.environ.get("PHISHSHIELD_EXTENSION_IDS", "").split(",") if re.fullmatch(r"[a-p]{32}", i.strip())]
    return r"^chrome-extension://(?:" + "|".join(ids) + r")$" if ids else r"^chrome-extension://[a-p]{32}$"


app.add_middleware(CORSMiddleware, allow_origin_regex=_extension_origins(), allow_methods=["GET", "POST"],
                   allow_headers=["Content-Type"])
app.mount("/static", StaticFiles(directory=DEMO / "static"), name="static")
app.mount("/shared", StaticFiles(directory=ROOT / "extension" / "shared"), name="shared")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(DEMO / "index.html", media_type="text/html")


@app.get("/{page}")
def subpage(page: str):
    if page in OLD_PAGES:
        return RedirectResponse(OLD_PAGES[page], status_code=301)
    if page not in PAGES:
        raise HTTPException(status_code=404)
    return FileResponse(DEMO / PAGES[page], media_type="text/html")


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "mode": mode(), "models": {k: predict.status(k)["state"] for k in ("url", "text")},
            "explainer": explain.status()}


@app.on_event("startup")
def _warm_up() -> None:
    # Load the models and probe Ollama off the request path so the first analysis isn't slow.
    def run():
        for k in ("url", "text"):
            predict.status(k)
        explain.status()
    threading.Thread(target=run, name="warmup", daemon=True).start()


def _request(req: AnalyzeRequest) -> tuple:
    if not req.text.strip() and not req.links and not req.qr:
        raise HTTPException(status_code=422, detail="Send some text or links to analyse.")
    email = req.email.model_dump(by_alias=True) if req.email else None
    return req.text, req.kind, email, [link.model_dump() for link in req.links], [q[:2000] for q in req.qr]


@app.post("/api/analyze")
def api_analyze(req: AnalyzeRequest) -> dict:
    return analyze(*_request(req))


@app.post("/api/analyze/file")
def api_analyze_file(file: UploadFile = File(...)) -> dict:
    data = file.file.read(files.MAX_BYTES + 1)
    try:
        req = files.from_upload(file.filename or "upload", data)
    except files.FileError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc))
    result = analyze(req["text"], req["kind"], req["email"], req["links"], req.get("qr"))
    # The uploader gets back the text that was analysed (for highlighting); it isn't stored.
    return {**result, "file": req["file"], "text": req["text"], "email": req["email"], "links": req["links"],
            "qr": req.get("qr", [])}


@app.post("/api/explain")
def api_explain(req: AnalyzeRequest) -> dict:
    result = analyze(*_request(req))
    ranked = sorted((f for f in result["findings"] if f["contribution"] > 0), key=lambda f: -f["contribution"])
    out = explain.llm(result["verdict"], result["score"], result["confidence"], [f["reason"] for f in ranked],
                      explain.domains_in(ranked), result["sanitized"] or "")
    return {"explanation": out.get("text") or result["explanation"], "source": out["source"],
            "detail": out.get("detail"), "model": out.get("model"), "ms": out.get("ms"),
            "verdict": result["verdict"], "score": result["score"]}


@app.post("/api/sanitize")
def api_sanitize(req: SanitizeRequest) -> dict:
    try:
        return sanitize(req.text, typed=req.typed).to_dict()
    except SanitizationError as exc:
        # Fail closed: never echo raw input back when sanitization failed.
        logger.error("sanitization blocked: %s", type(exc).__name__)
        raise HTTPException(status_code=422, detail="Blocked: input could not be safely sanitized.")


@app.get("/api/eval")
def api_eval() -> dict:
    """Measured results for the results page. Every number comes from src/eval/phish_bench.py."""
    path = DATA / "eval.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="No evaluation yet. Run: python -m src.eval.phish_bench")
    out = json.loads(path.read_text(encoding="utf-8"))
    cal = DATA / "calibration.json"
    if cal.exists():
        c = json.loads(cal.read_text(encoding="utf-8"))
        out["calibration"] = {k: c.get(k) for k in ("chosen", "chosen_val", "fpr_limit", "grid", "n_text", "n_url")}
    out["model_cards"] = {}
    for kind in ("url", "text"):
        meta = ROOT / "models" / f"{kind}_model.json"
        if meta.exists():
            m = json.loads(meta.read_text(encoding="utf-8"))
            out["model_cards"][kind] = {k: m.get(k) for k in ("version", "train_n", "val_n", "val_calibrated", "C", "iterations")}
    return out


EXTENSION = ROOT / "extension"
EXTENSION_SKIP = {"dev", "test"}  # test pages and unit tests aren't part of the installed extension


def _extension_version() -> str:
    return json.loads((EXTENSION / "manifest.json").read_text(encoding="utf-8"))["version"]


@app.get("/api/extension")
def api_extension() -> dict:
    """What the install page needs. PHISHSHIELD_EXTENSION_STORE_URL, once the extension is on the
    Chrome Web Store, turns the page's download button into a one-click "Add to Chrome"."""
    store = os.environ.get("PHISHSHIELD_EXTENSION_STORE_URL", "").strip()
    return {"version": _extension_version(), "download": "/download/phishshield-extension.zip",
            "store_url": store if store.startswith("https://chromewebstore.google.com/") else None}


@app.get("/download/phishshield-extension.zip")
def download_extension() -> Response:
    """The extension folder as a zip with one top-level folder, ready for chrome://extensions > Load unpacked."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(EXTENSION.rglob("*")):
            rel = path.relative_to(EXTENSION)
            if path.is_file() and rel.parts[0] not in EXTENSION_SKIP:
                z.write(path, "phishshield-extension/" + rel.as_posix())
    name = f"phishshield-extension-{_extension_version()}.zip"
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


def main() -> None:
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    if "--dev" in sys.argv:
        # Extension test pages (extension/dev/*.html) run the real content scripts against this API.
        app.mount("/dev/extension", StaticFiles(directory=ROOT / "extension"), name="extension-dev")
        logger.info("dev: Gmail test page at http://localhost:%d/dev/extension/dev/gmail.html", port)
    logger.info("PhishShield (%s mode) on http://localhost:%d", mode(), port)
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    sys.exit(main())
