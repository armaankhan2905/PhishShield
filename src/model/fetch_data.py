"""Download the public datasets used to train and evaluate the PhishShield models.

Owner: Govind. Every file lands in its own folder under data/raw/ (not in git)
and is recorded in data/raw/SOURCES.json with its URL, size, SHA-256 and
download date, so a run can be traced back to exact inputs. Downloads are data
files only; nothing downloaded is executed.

Run (from repo root):
    python -m src.model.fetch_data            # skips files already present
    python -m src.model.fetch_data --force
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"

HF = "https://huggingface.co/datasets"
SOURCES = {
    # Combined phishing / benign URLs and texts (emails + SMS) compiled from public corpora. Apache-2.0.
    "ealvaradob_urls": (f"{HF}/ealvaradob/phishing-dataset/resolve/main/urls.json", "urls.json"),
    "ealvaradob_texts": (f"{HF}/ealvaradob/phishing-dataset/resolve/main/texts.json", "texts.json"),
    "ealvaradob_readme": (f"{HF}/ealvaradob/phishing-dataset/resolve/main/README.md", "README.md"),
    # Phishing vs safe emails (Kaggle "Phishing Email Detection" mirror). LGPL-3.0.
    "phishing_emails": (f"{HF}/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv", "Phishing_Email.csv"),
    # UCI SMS Spam Collection (spam vs ham, not phishing specifically). CC BY 4.0.
    "uci_sms": ("https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip", "sms_spam_collection.zip"),
    # Tranco top sites (popular, mostly benign registered domains). Used only for benign URL samples.
    "tranco": ("https://tranco-list.eu/top-1m.csv.zip", "top-1m.csv.zip"),
    # OpenPhish community feed: recent live phishing URLs. Held out entirely as an unseen test slice.
    "openphish": ("https://openphish.com/feed.txt", "feed.txt"),
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(name: str, url: str, filename: str, force: bool) -> dict:
    folder = RAW / name
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / filename
    if force or not path.exists():
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            tmp = path.with_suffix(path.suffix + ".part")
            with tmp.open("wb") as f:
                for chunk in r.iter_content(1 << 20):
                    f.write(chunk)
            tmp.replace(path)
    return {"url": url, "file": str(path.relative_to(ROOT)).replace("\\", "/"), "bytes": path.stat().st_size,
            "sha256": sha256(path), "downloaded": dt.datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    record = {}
    for name, (url, filename) in SOURCES.items():
        print(f"{name:20s} {url}", flush=True)
        record[name] = fetch(name, url, filename, args.force)
    (RAW / "SOURCES.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"recorded {len(record)} sources in data/raw/SOURCES.json")


if __name__ == "__main__":
    sys.exit(main())
