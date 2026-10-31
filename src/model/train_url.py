"""Train the URL model: gradient-boosted trees on lexical URL features, calibrated on validation.

Owner: Govind. Uses scikit-learn's HistGradientBoostingClassifier (same family
as LightGBM, no extra dependency). Probabilities are calibrated with isotonic
regression on the validation split; the test split is never touched here.

Run (after src.model.prepare):
    python -m src.model.train_url
Writes models/url_model.joblib and models/url_model.json (metadata + validation metrics).
"""
from __future__ import annotations

import gzip
import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import average_precision_score, brier_score_loss, f1_score, precision_score, recall_score

from src.model import url_features as F

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "processed" / "urls.jsonl.gz"
MODELS = ROOT / "models"
SEED = 2026
VERSION = "url-hgb-1"


def load(split: str):
    rows = [json.loads(l) for l in gzip.open(DATA, "rt", encoding="utf-8")]
    rows = [r for r in rows if r["split"] == split]
    return np.array(F.matrix([r["url"] for r in rows]), dtype=float), np.array([r["label"] for r in rows])


def metrics(y, p, threshold=0.5) -> dict:
    pred = (p >= threshold).astype(int)
    fp = int(((pred == 1) & (y == 0)).sum())
    return {"n": int(len(y)), "precision": round(float(precision_score(y, pred)), 4),
            "recall": round(float(recall_score(y, pred)), 4), "f1": round(float(f1_score(y, pred)), 4),
            "fpr": round(fp / max(1, int((y == 0).sum())), 4), "pr_auc": round(float(average_precision_score(y, p)), 4),
            "brier": round(float(brier_score_loss(y, p)), 4)}


def main() -> None:
    t0 = time.time()
    Xtr, ytr = load("train")
    Xva, yva = load("val")
    base = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.08, max_leaf_nodes=63, min_samples_leaf=40,
                                          l2_regularization=1.0, early_stopping=True, validation_fraction=0.1,
                                          random_state=SEED)
    base.fit(Xtr, ytr)
    raw = base.predict_proba(Xva)[:, 1]
    model = CalibratedClassifierCV(FrozenEstimator(base), method="isotonic")
    model.fit(Xva, yva)
    cal = model.predict_proba(Xva)[:, 1]
    MODELS.mkdir(exist_ok=True)
    joblib.dump({"model": model, "features": F.FEATURES, "version": VERSION}, MODELS / "url_model.joblib", compress=3)
    meta = {"version": VERSION, "features": F.FEATURES, "train_n": int(len(ytr)), "val_n": int(len(yva)),
            "iterations": int(base.n_iter_), "val_uncalibrated": metrics(yva, raw), "val_calibrated": metrics(yva, cal),
            "note": "Validation metrics only; calibration is fitted on validation, so these are optimistic. "
                    "Held-out numbers come from src/eval/phish_bench.py.",
            "train_seconds": round(time.time() - t0, 1)}
    (MODELS / "url_model.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta, indent=1))


if __name__ == "__main__":
    main()
