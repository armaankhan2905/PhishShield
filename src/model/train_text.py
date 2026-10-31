"""Train the text model: TF-IDF word n-grams + logistic regression, calibrated on validation.

Owner: Govind. Text is normalised first (lower case, links -> "zurlz",
email addresses -> "zemailz", digits -> 0) so the model reads wording, not
specific links or numbers, and so formatting differences between corpora
(e.g. pre-tokenised Enron mail) matter less. The regularisation strength is
chosen on the validation split; the test split is never touched here.

Run (after src.model.prepare):
    python -m src.model.train_text
Writes models/text_model.joblib and models/text_model.json.
"""
from __future__ import annotations

import gzip
import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from src.model.prepare import normalise_text
from src.model.train_url import metrics

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "processed" / "texts.jsonl.gz"
MODELS = ROOT / "models"
VERSION = "text-tfidf-lr-1"


def load(split: str):
    rows = [json.loads(l) for l in gzip.open(DATA, "rt", encoding="utf-8")]
    rows = [r for r in rows if r["split"] == split]
    return [r["text"] for r in rows], np.array([r["label"] for r in rows]), [r["kind"] for r in rows]


def build(c: float) -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(preprocessor=normalise_text, ngram_range=(1, 2), min_df=2, max_df=0.5,
                                  max_features=150_000, sublinear_tf=True, dtype=np.float32)),
        ("lr", LogisticRegression(C=c, class_weight="balanced", max_iter=3000, solver="liblinear")),
    ])


def main() -> None:
    t0 = time.time()
    Xtr, ytr, _ = load("train")
    Xva, yva, kva = load("val")
    search = {}
    for c in (0.5, 2.0, 8.0, 32.0):
        m = build(c).fit(Xtr, ytr)
        search[c] = metrics(yva, m.predict_proba(Xva)[:, 1])
        print(f"C={c}: {search[c]}", flush=True)
    best_c = max(search, key=lambda c: (search[c]["pr_auc"], search[c]["f1"]))
    base = build(best_c).fit(Xtr, ytr)
    model = CalibratedClassifierCV(FrozenEstimator(base), method="isotonic")
    model.fit(Xva, yva)
    cal = model.predict_proba(Xva)[:, 1]
    kva = np.array(kva)
    MODELS.mkdir(exist_ok=True)
    joblib.dump({"model": model, "version": VERSION}, MODELS / "text_model.joblib", compress=3)
    meta = {"version": VERSION, "C": best_c, "c_search_val": {str(k): v for k, v in search.items()},
            "train_n": len(ytr), "val_n": int(len(yva)), "vocabulary": len(base.named_steps["tfidf"].vocabulary_),
            "val_calibrated": metrics(yva, cal),
            "val_calibrated_by_kind": {k: metrics(yva[kva == k], cal[kva == k]) for k in ("sms", "email")},
            "note": "Validation metrics only (C and calibration chosen on validation). "
                    "Held-out numbers come from src/eval/phish_bench.py.",
            "train_seconds": round(time.time() - t0, 1)}
    (MODELS / "text_model.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=1))


if __name__ == "__main__":
    main()
