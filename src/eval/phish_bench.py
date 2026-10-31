"""PhishShield evaluation: every number shown to the judges comes from this script.

Owner: Govind.

  python -m src.eval.phish_bench --tune    grid-search the scoring constants on VALIDATION,
                                           write data/calibration.json
  python -m src.eval.phish_bench           measure on the frozen TEST split and the held-out
                                           slices, write data/eval.json

What is measured (each with n, precision, recall, F1, false-positive rate, confusion matrix):
  url_model / text_model   each model alone at p >= 0.5
  rules_only               the full engine with model findings removed
  system_flagged           full system, positive = suspicious or phishing (score >= SAFE_BELOW)
  system_phishing          full system, positive = phishing only (score >= PHISHING_FROM)
  baseline_35_30_35        the Phase 1 weighted average, for comparison

Slices: text test (sms / email), URL test, openphish (recent phishing, unseen
domains), tranco (popular domains, benign), uci_sms_ham / uci_sms_spam (unseen
source; spam is not phishing, so reported for information), curated (hand-written,
synthetic). Metrics are deterministic for fixed data and models; timings are
reported separately because they vary by machine.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import itertools
import json
import random
import subprocess
import time
from pathlib import Path
from statistics import median
from typing import Dict, List

import src.model  # noqa: F401
from src.detection import engine
from src.detection import fuse as FU
from src.model import predict
from src.model.url_features import matrix

ROOT = Path(__file__).resolve().parents[2]
PROC = ROOT / "data" / "processed"
EVAL_OUT = ROOT / "data" / "eval.json"
CAL_OUT = ROOT / "data" / "calibration.json"
SEED = 2026
URL_SYSTEM_SAMPLE = 6000     # URLs per split run through the full engine (model-only metrics use all)
FPR_LIMIT = 0.05             # tuning constraint on validation benign messages and URLs
TIE_TOLERANCE = 0.005        # objective differences below this are treated as ties

GRID = {
    "ML_MAX": [35, 45, 55],
    "URL_FLOOR": [0.7, 0.8, 0.9, 0.95],
    "TEXT_FLOOR": [0.5, 0.7, 0.85],
    "SAFE_BELOW": [30, 35, 40],
}


def _rows(name):
    return [json.loads(l) for l in gzip.open(PROC / f"{name}.jsonl.gz", "rt", encoding="utf-8")]


def confusion(y: List[int], pred: List[int]) -> dict:
    tp = sum(1 for a, b in zip(y, pred) if a == 1 and b == 1)
    fp = sum(1 for a, b in zip(y, pred) if a == 0 and b == 1)
    fn = sum(1 for a, b in zip(y, pred) if a == 1 and b == 0)
    tn = sum(1 for a, b in zip(y, pred) if a == 0 and b == 0)
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else (0.0 if prec is not None and rec is not None else None)
    r = lambda v: None if v is None else round(v, 4)  # noqa: E731
    return {"n": len(y), "positives": tp + fn, "negatives": fp + tn, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": r(prec), "recall": r(rec), "f1": r(f1), "fpr": r(fp / (fp + tn) if fp + tn else None)}


# --- collect engine output once, re-score many times ---------------------------------

def collect(items: List[dict]) -> List[dict]:
    """Run every detection layer once per item; keep findings so scoring can be re-run cheaply."""
    out = []
    for it in items:
        if "url" in it:
            det = engine.run(it["url"], "url", None, [])
        else:
            det = engine.run(it["text"], it.get("kind", "sms"), None, [])
        t0 = time.perf_counter()
        out.append({"label": it["label"], "det": det, "slice": it.get("slice") or it.get("kind") or "url",
                    "ms": (time.perf_counter() - t0) * 1000})
    return out


def system_scores(collected: List[dict], drop_ml: bool = False) -> List[int]:
    scores = []
    for c in collected:
        det = c["det"]
        findings, coverage = det.findings, dict(det.coverage)
        if drop_ml:
            findings = [f for f in findings if f.tier != "ml"]
            coverage.update(url_model=FU.UNAVAILABLE, text_model=FU.UNAVAILABLE)
        scores.append(FU.fuse(findings, coverage, det.context).score)
    return scores


def baseline_scores(collected: List[dict]) -> List[int]:
    """Phase 1 formula: 35% rules (capped sum of weights) + 30% worst URL + 35% text, missing layers skipped."""
    out = []
    for c in collected:
        fs = c["det"].findings
        parts = [(0.35, min(100, sum(f.weight for f in fs if f.tier != "ml")))]
        url = [f.confidence for f in fs if f.source == "url-model"]
        txt = [f.confidence for f in fs if f.source == "text-model"]
        if c["det"].coverage.get("url_model") == FU.RAN and c["det"].urls:
            scores = [u["score"] for u in c["det"].urls if u["score"] is not None]
            if scores:
                parts.append((0.30, 100 * max(scores)))
        elif url:
            parts.append((0.30, 100 * max(url)))
        if c["det"].coverage.get("text_model") == FU.RAN:
            parts.append((0.35, 100 * (max(txt) if txt else 0.0)))
        out.append(round(sum(w * s for w, s in parts) / sum(w for w, _ in parts)))
    return out


def set_constants(values: Dict[str, float]) -> None:
    for k, v in values.items():
        setattr(FU, k, v)


# --- data ---------------------------------------------------------------------------

def split_items(split: str, rng: random.Random):
    texts = [dict(r) for r in _rows("texts") if r["split"] == split]
    urls = [r for r in _rows("urls") if r["split"] == split]
    rng.shuffle(urls)
    return texts, urls


# --- tuning -------------------------------------------------------------------------

def tune() -> dict:
    rng = random.Random(SEED)
    texts, urls = split_items("val", rng)
    urls_sys = urls[:URL_SYSTEM_SAMPLE]
    defaults = {k: getattr(FU, k) for k in GRID}
    set_constants({"URL_FLOOR": 0.5, "TEXT_FLOOR": 0.5})  # collect every model finding; floors are re-applied per combo
    print(f"collecting validation: {len(texts)} texts, {len(urls_sys)} urls", flush=True)
    ct, cu = collect(texts), collect(urls_sys)
    results = []
    for combo in itertools.product(*GRID.values()):
        values = dict(zip(GRID, combo))
        set_constants(values)
        mt = confusion([c["label"] for c in ct], [int(s >= FU.SAFE_BELOW) for s in system_scores(ct)])
        mu = confusion([c["label"] for c in cu], [int(s >= FU.SAFE_BELOW) for s in system_scores(cu)])
        ok = (mt["fpr"] or 0) <= FPR_LIMIT and (mu["fpr"] or 0) <= FPR_LIMIT
        dist = sum(abs(values[k] - defaults[k]) / defaults[k] for k in GRID)
        results.append({"values": values, "text": mt, "url": mu, "meets_fpr_limit": ok,
                        "objective": round(((mt["f1"] or 0) + (mu["f1"] or 0)) / 2, 4), "distance_from_default": round(dist, 3)})
    set_constants(defaults)
    feasible = [r for r in results if r["meets_fpr_limit"]] or results
    top = max(r["objective"] for r in feasible)
    # Differences this small are noise; among them prefer the setting closest to the current defaults.
    near = [r for r in feasible if r["objective"] >= top - TIE_TOLERANCE]
    best = min(near, key=lambda r: (r["distance_from_default"], -r["objective"]))
    record = {"split": "val", "fpr_limit": FPR_LIMIT, "tie_tolerance": TIE_TOLERANCE, "grid": GRID, "defaults": defaults, "chosen": best["values"],
              "chosen_val": {"text": best["text"], "url": best["url"], "objective": best["objective"]},
              "all": sorted(results, key=lambda r: -r["objective"]), "n_text": len(ct), "n_url": len(cu)}
    CAL_OUT.write_text(json.dumps(record, indent=1), encoding="utf-8")
    print(json.dumps({"chosen": best["values"], "val": record["chosen_val"]}, indent=1))
    return record


# --- evaluation -----------------------------------------------------------------------

def evaluate() -> dict:
    rng = random.Random(SEED)
    t_start = time.time()
    texts, urls = split_items("test", rng)
    slices = _rows("slices")
    url_slices = [r for r in slices if "url" in r]
    text_slices = [r for r in slices if "text" in r]

    metrics: Dict[str, dict] = {}
    timing: Dict[str, float] = {}

    # Models alone, batch, on everything they apply to.
    if predict.available("url"):
        for name, items in (("url_test", urls), ("openphish", [r for r in url_slices if r["slice"] == "openphish"]),
                            ("tranco", [r for r in url_slices if r["slice"] == "tranco"])):
            p = predict._loaded["url"].predict_proba(matrix([r["url"] for r in items]))[:, 1]
            metrics.setdefault(name, {})["url_model"] = confusion([r["label"] for r in items], [int(x >= 0.5) for x in p])
    if predict.available("text"):
        groups = {"text_test_sms": [r for r in texts if r["kind"] == "sms"],
                  "text_test_email": [r for r in texts if r["kind"] == "email"]}
        for sl in ("uci_sms_ham", "uci_sms_spam", "curated"):
            groups[sl] = [r for r in text_slices if r["slice"] == sl]
        for name, items in groups.items():
            p = predict._loaded["text"].predict_proba([r["text"] for r in items])[:, 1]
            metrics.setdefault(name, {})["text_model"] = confusion([r["label"] for r in items], [int(x >= 0.5) for x in p])

    # Full engine.
    system_sets = {
        "text_test_sms": [r for r in texts if r["kind"] == "sms"],
        "text_test_email": [r for r in texts if r["kind"] == "email"],
        "url_test": urls[:URL_SYSTEM_SAMPLE],
        "openphish": [r for r in url_slices if r["slice"] == "openphish"],
        "tranco": [r for r in url_slices if r["slice"] == "tranco"],
        "uci_sms_ham": [r for r in text_slices if r["slice"] == "uci_sms_ham"],
        "uci_sms_spam": [r for r in text_slices if r["slice"] == "uci_sms_spam"],
        "curated": [r for r in text_slices if r["slice"] == "curated"],
    }
    curated_groups = {}
    for name, items in system_sets.items():
        t0 = time.perf_counter()
        col = collect(items)
        per_item_ms = (time.perf_counter() - t0) * 1000 / max(1, len(items))
        timing[name] = round(per_item_ms, 2)
        y = [c["label"] for c in col]
        sys_s, rules_s, base_s = system_scores(col), system_scores(col, drop_ml=True), baseline_scores(col)
        m = metrics.setdefault(name, {})
        m["rules_only"] = confusion(y, [int(s >= FU.SAFE_BELOW) for s in rules_s])
        m["system_flagged"] = confusion(y, [int(s >= FU.SAFE_BELOW) for s in sys_s])
        m["system_phishing"] = confusion(y, [int(s >= FU.PHISHING_FROM) for s in sys_s])
        m["baseline_35_30_35"] = confusion(y, [int(s >= 35) for s in base_s])
        if name == "curated":
            for it, s in zip(items, sys_s):
                g = curated_groups.setdefault(it["group"], {"n": 0, "label": it["label"], "verdicts": {}})
                g["n"] += 1
                v = FU.verdict_for(s)
                g["verdicts"][v] = g["verdicts"].get(v, 0) + 1
        print(f"{name:16s} n={len(items):5d}  flagged F1={m['system_flagged']['f1']}  FPR={m['system_flagged']['fpr']}", flush=True)

    manifest = json.loads((PROC / "MANIFEST.json").read_text(encoding="utf-8"))
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    except OSError:
        commit = None
    result = {
        "metrics": metrics,
        "curated_by_group": curated_groups,
        "scoring": {k: getattr(FU, k) for k in ("SAFE_BELOW", "PHISHING_FROM", "FAMILY_CAPS", "ML_MAX", "ML_CONFIDENT",
                                                 "HEURISTIC_ONLY_CAP", "CONSISTENT_DISCOUNT", "URL_FLOOR", "TEXT_FLOOR")},
        "models": {k: predict.status(k).get("version") for k in ("url", "text")},
        "data": {"manifest_sha256": hashlib.sha256((PROC / "MANIFEST.json").read_bytes()).hexdigest(),
                 "files": manifest["files"], "url_system_sample": URL_SYSTEM_SAMPLE, "seed": SEED},
        "notes": [
            "test split = 15% held out by hash of registered domain (URLs) or near-duplicate key (texts); never used for training, calibration or tuning",
            "openphish and tranco exclude every registered domain seen in train or validation",
            "uci_sms_spam is spam, not phishing: reported for information, not as a phishing score",
            "curated is 40 hand-written synthetic messages by the project team: not an accuracy claim",
            "url_test system metrics use a fixed sample of the URL test split; url_model metrics use all of it",
        ],
    }
    det_hash = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    result["run"] = {"commit": commit, "metrics_sha256": det_hash, "ms_per_item": timing,
                     "seconds": round(time.time() - t_start, 1), "generated": time.strftime("%Y-%m-%dT%H:%M:%S")}
    EVAL_OUT.write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"wrote {EVAL_OUT.relative_to(ROOT)}  metrics_sha256={det_hash[:16]}")
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tune", action="store_true", help="tune scoring constants on validation")
    args = ap.parse_args()
    for k in ("url", "text"):
        print(k, predict.status(k))
    if args.tune:
        tune()
    else:
        evaluate()


if __name__ == "__main__":
    main()
