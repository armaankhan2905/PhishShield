"""Turn the raw datasets into clean, de-duplicated, leak-free splits.

Owner: Govind. Reads data/raw/ (see fetch_data.py), writes data/processed/.

  urls.jsonl.gz     url, label, source, registered, split (train / val / test)
  texts.jsonl.gz    text, label, source, kind, split
  slices.jsonl.gz   evaluation-only sets the models never train on:
                    openphish (recent phishing), tranco (popular domains),
                    uci_sms_ham / uci_sms_spam, curated (hand-written, synthetic)
  MANIFEST.json     counts, seed, and SHA-256 of every output file

Leakage rules:
  - URLs are split by registered domain: one domain never appears in two splits.
  - Texts are de-duplicated after normalisation and split by a near-duplicate
    key (the first 30 normalised words), so template variants stay together.
  - Messages that appear with both labels are dropped.
  - The test split is defined by a fixed hash, so it never changes between runs.

Run:
    python -m src.model.prepare
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import random
import re
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

from src.detection import domains as D
from src.model import synth_sms

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "processed"
CURATED = ROOT / "data" / "curated" / "indian_messages.jsonl"

SEED = 2026
URL_SAMPLE = 160_000          # balanced sample of the 835k URL corpus, for CPU training time
TRANCO_TOP = 5_000            # ranks 1..5000: held-out evaluation slice
TRANCO_TRAIN = 30_000         # next ranks: benign bare-domain training examples
SPLIT_SALT = "phishshield-v1"


def split_of(key: str) -> str:
    """Deterministic 70 / 15 / 15 split from a stable hash of the group key."""
    h = int(hashlib.sha256((SPLIT_SALT + key).encode("utf-8")).hexdigest(), 16) % 100
    return "train" if h < 70 else "val" if h < 85 else "test"


def canonical_url(url: str) -> str:
    """Scheme and leading www. removed: the corpora differ in how often they include them,
    which would otherwise teach the model a shortcut. Prediction uses the same form."""
    u = url.strip()
    u = re.sub(r"^[a-z][a-z0-9+.-]*://", "", u, flags=re.I)
    u = re.sub(r"^www\d?\.", "", u, flags=re.I)
    host, sep, rest = u.partition("/")
    return host.lower() + sep + rest


_WORD = re.compile(r"[a-z0-9]+")


def normalise_text(text: str) -> str:
    t = text.lower()
    t = re.sub(r"(?:https?://|www\.)\S+", " zurlz ", t)
    t = re.sub(r"\S+@\S+\.\S+", " zemailz ", t)
    t = re.sub(r"\d+", "0", t)
    return " ".join(_WORD.findall(t))


def _write(path: Path, rows) -> str:
    # mtime=0: no timestamp in the gzip header, so identical data gives an identical file and hash.
    with open(path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz, \
            io.TextIOWrapper(gz, encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_urls(rng: random.Random):
    data = json.load(open(RAW / "ealvaradob_urls" / "urls.json", encoding="utf-8"))
    by_canon, conflict = {}, set()
    for row in data:
        c = canonical_url(row["text"])
        if c in by_canon and by_canon[c] != row["label"]:
            conflict.add(c)
        by_canon[c] = row["label"]
    items = [(c, lab) for c, lab in by_canon.items() if c not in conflict]
    rng.shuffle(items)
    per = URL_SAMPLE // 2
    picked = [x for x in items if x[1] == 0][:per] + [x for x in items if x[1] == 1][:per]
    rows = []
    for c, lab in picked:
        info = D.parse_url(c)
        if not info.valid or not info.registered:
            continue
        rows.append({"url": c, "label": lab, "source": "ealvaradob_urls", "registered": info.registered,
                     "split": split_of(info.registered)})
    # Benign bare domains: 90% of the corpus's benign URLs have a path, which teaches
    # "no path = phishing". Tranco ranks below TRANCO_TOP fix that; the top ones stay held out.
    known = {r["registered"] for r in rows} | {D.parse_url(c).registered for c, lab in picked if lab == 1}
    added = 0
    for rank, dom in enumerate(_tranco(), 1):
        if rank <= TRANCO_TOP:
            continue
        if added >= TRANCO_TRAIN:
            break
        info = D.parse_url(dom)
        if not info.valid or info.registered in known:
            continue
        known.add(info.registered)
        rows.append({"url": dom, "label": 0, "source": "tranco", "registered": info.registered,
                     "split": split_of(info.registered)})
        added += 1
    stats = {"raw": len(data), "unique": len(by_canon), "label_conflicts_dropped": len(conflict),
             "tranco_benign_added": added, "used": len(rows)}
    return rows, stats


def _tranco():
    with zipfile.ZipFile(RAW / "tranco" / "top-1m.csv.zip") as z:
        for line in io.TextIOWrapper(z.open(z.namelist()[0]), encoding="utf-8"):
            yield line.strip().split(",")[-1]


def infer_kind(text: str) -> str:
    """The combined corpus doesn't say which rows are SMS. Long texts, and short texts with the
    email corpus's markers (pre-tokenised " , " spacing, "re :" subjects, header lines), are email."""
    if len(text) > 300:
        return "email"
    if re.match(r"\s*(?:re|fw|fwd|subject)\s*:", text, re.I) or len(re.findall(r"\w [,.!?:;] ", text)) >= 2:
        return "email"
    if re.search(r"^(?:URL|Date|From|To):", text, re.M):
        return "email"
    return "sms"


def build_texts():
    rows = []
    for r in json.load(open(RAW / "ealvaradob_texts" / "texts.json", encoding="utf-8")):
        kind = infer_kind(r["text"])
        rows.append({"text": r["text"], "label": int(r["label"]), "source": "ealvaradob_texts", "kind": kind})
    e = pd.read_csv(RAW / "phishing_emails" / "Phishing_Email.csv").dropna(subset=["Email Text", "Email Type"])
    for text, typ in zip(e["Email Text"], e["Email Type"]):
        rows.append({"text": str(text), "label": int(typ == "Phishing Email"), "source": "phishing_emails", "kind": "email"})
    labels, keep = defaultdict(set), {}
    for r in rows:
        n = normalise_text(r["text"])
        if len(n.split()) < 3:
            continue
        labels[n].add(r["label"])
        keep.setdefault(n, r)
    out = []
    for n, r in keep.items():
        if len(labels[n]) > 1:
            continue
        r = dict(r, split=split_of(" ".join(n.split()[:30])))
        out.append(r)
    # Synthetic Indian SMS: train split only, never validation, calibration or test.
    seen = set(keep)
    synth = [dict(r, split="train", synthetic=True) for r in synth_sms.generate()
             if normalise_text(r["text"]) not in seen and not seen.add(normalise_text(r["text"]))]
    out += synth
    stats = {"raw": len(rows), "unique_normalised": len(keep),
             "label_conflicts_dropped": sum(len(v) > 1 for v in labels.values()),
             "synthetic_train_only": len(synth), "used": len(out)}
    return out, stats


def build_slices(url_rows, text_rows):
    train_domains = {r["registered"] for r in url_rows if r["split"] != "test"}
    train_texts = {normalise_text(r["text"]) for r in text_rows if r["split"] != "test"}
    rows, stats = [], Counter()

    for line in (RAW / "openphish" / "feed.txt").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        c = canonical_url(line)
        info = D.parse_url(c)
        if info.valid and info.registered not in train_domains:
            rows.append({"slice": "openphish", "url": c, "label": 1})
            stats["openphish"] += 1
        else:
            stats["openphish_skipped_seen_domain"] += 1

    for i, dom in enumerate(_tranco()):
        if i >= TRANCO_TOP:
            break
        if D.parse_url(dom).registered in train_domains:
            stats["tranco_skipped_seen_domain"] += 1
            continue
        rows.append({"slice": "tranco", "url": dom, "label": 0})
        stats["tranco"] += 1

    with zipfile.ZipFile(RAW / "uci_sms" / "sms_spam_collection.zip") as z:
        name = next(n for n in z.namelist() if n.lower().endswith("smsspamcollection"))
        for line in io.TextIOWrapper(z.open(name), encoding="utf-8", errors="replace"):
            lab, _, text = line.rstrip("\n").partition("\t")
            if normalise_text(text) in train_texts:
                stats["uci_skipped_seen_text"] += 1
                continue
            sl = "uci_sms_spam" if lab == "spam" else "uci_sms_ham"
            rows.append({"slice": sl, "text": text, "label": int(lab == "spam"), "kind": "sms"})
            stats[sl] += 1

    for line in CURATED.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            if normalise_text(r["text"]) in train_texts:  # e.g. matches a synthetic training template
                stats["curated_skipped_seen_text"] += 1
                continue
            rows.append({"slice": "curated", "text": r["text"], "label": r["label"], "kind": r["kind"],
                         "group": r["group"], "synthetic": True})
            stats["curated"] += 1
    return rows, dict(stats)


def main() -> None:
    rng = random.Random(SEED)
    OUT.mkdir(parents=True, exist_ok=True)
    url_rows, url_stats = build_urls(rng)
    text_rows, text_stats = build_texts()
    slice_rows, slice_stats = build_slices(url_rows, text_rows)

    overlap = ({r["registered"] for r in url_rows if r["split"] == "train"} &
               {r["registered"] for r in url_rows if r["split"] == "test"})
    assert not overlap, f"registered domains in both train and test: {list(overlap)[:5]}"

    manifest = {
        "seed": SEED, "split_salt": SPLIT_SALT,
        "sources": json.loads((RAW / "SOURCES.json").read_text(encoding="utf-8")),
        "urls": {**url_stats, "by_split": dict(Counter((r["split"], r["label"]) for r in url_rows).most_common())},
        "texts": {**text_stats, "by_split": dict(Counter((r["split"], r["kind"], r["label"]) for r in text_rows).most_common())},
        "slices": slice_stats,
        "files": {},
    }
    for name, rows in (("urls", url_rows), ("texts", text_rows), ("slices", slice_rows)):
        manifest["files"][f"{name}.jsonl.gz"] = _write(OUT / f"{name}.jsonl.gz", rows)
    manifest["urls"]["by_split"] = {f"{k[0]}/{k[1]}": v for k, v in manifest["urls"]["by_split"].items()}
    manifest["texts"]["by_split"] = {"/".join(map(str, k)): v for k, v in manifest["texts"]["by_split"].items()}
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in ("urls", "texts", "slices")}, indent=1))


if __name__ == "__main__":
    main()
