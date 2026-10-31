"""Facts about the pipeline for the demo's "How it works" view.

Everything here is read from the repo or measured at runtime, never typed in:
  - training_info():  model/training config parsed from src/model/train.py and
                      src/model/corpus/build_corpus.py (AST, no torch import),
                      plus metrics from a real Trainer run if one exists locally.
  - evaluate_patterns(): precision/recall of the pattern layer on a seeded
                      synthetic benchmark generated here (positives + negatives).
  - canary_audit():   Athrav's canary values pushed through sanitize().

Run:
    python -m src.pipeline.insights
"""
from __future__ import annotations

import ast
import json
import random
import re
import string
import threading
import time
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

from src.detection import DETECTORS, detect
from src.detection import ner

ROOT = Path(__file__).resolve().parents[2]


def _newest(*paths: Path) -> Path:
    """First existing path: the v2 training scripts supersede v1 when present."""
    return next((p for p in paths if p.exists()), paths[-1])


TRAIN_PY = _newest(ROOT / "src" / "model" / "train_v2.py", ROOT / "src" / "model" / "train.py")
CORPUS_PY = _newest(ROOT / "src" / "model" / "corpus" / "build_corpus_v2.py",
                    ROOT / "src" / "model" / "corpus" / "build_corpus.py")
CORPUS_FILE = ROOT / "data" / "corpus" / "train.jsonl"
MODEL_DIR = ROOT / "models" / "pii_classifier"


# --- training pipeline (read from source) -----------------------------------

def _literal(node):
    try:
        return ast.literal_eval(node)
    except Exception:  # noqa: BLE001
        return None


def _parse_train() -> dict:
    src = TRAIN_PY.read_text(encoding="utf-8")
    tree = ast.parse(src)
    info: dict = {"base_model": None, "labels": [], "args": {}, "max_length": None}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name == "MODEL_NAME":
                info["base_model"] = _literal(node.value)
            elif name == "LABEL2ID":
                info["labels"] = list((_literal(node.value) or {}).keys())
        elif isinstance(node, ast.Call) and getattr(node.func, "id", None) == "TrainingArguments":
            info["args"] = {k.arg: _literal(k.value) for k in node.keywords if _literal(k.value) is not None}
        elif isinstance(node, ast.FunctionDef) and node.name == "tokenize_and_align_labels":
            for arg, default in zip(node.args.args[-len(node.args.defaults):], node.args.defaults):
                if arg.arg == "max_length":
                    info["max_length"] = _literal(default)
    m = re.search(r"int\(\s*([\d.]+)\s*\*\s*len", src)
    info["train_split"] = float(m.group(1)) if m else None
    m = re.search(r"random\.seed\((\d+)\)", src)
    info["seed"] = int(m.group(1)) if m else None
    m = re.search(r"subset_size\s*=\s*min\((\d+)", src)
    info["subset"] = int(m.group(1)) if m else None
    if not info["base_model"]:
        m = re.search(r"from_pretrained\(\s*[\"']models/([^\"']+)", src)
        info["base_model"] = m.group(1).replace("_", "/", 1) if m else None
    info["source"] = str(TRAIN_PY.relative_to(ROOT)).replace("\\", "/")
    return info


def _parse_corpus_builder() -> dict:
    tree = ast.parse(CORPUS_PY.read_text(encoding="utf-8"))
    templates, loops, generators, samples = [], None, [], None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("make_"):
            generators.append(node.name[5:].upper())
        if isinstance(node, ast.FunctionDef) and node.name == "build_corpus" and node.args.defaults:
            samples = _literal(node.args.defaults[0])
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "records":
            templates = [t[0] for t in (_literal(node.value) or [])]
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "TEMPLATES":
            groups = _literal(node.value) or {}
            templates = [t if isinstance(t, str) else t[0] for g in groups.values() for t in g]
        if (isinstance(node, ast.For) and isinstance(node.iter, ast.Call)
                and getattr(node.iter.func, "id", None) == "range" and loops is None):
            loops = _literal(node.iter.args[0])
    planned = samples if samples else (len(templates) * loops if isinstance(loops, int) else None)
    return {"templates": templates, "rounds": loops if not samples else None, "generators": generators,
            "planned_sentences": planned, "source": str(CORPUS_PY.relative_to(ROOT)).replace("\\", "/")}


def _num_labels(config: Path) -> int | None:
    try:
        return len(json.loads(config.read_text())["id2label"])
    except Exception:  # noqa: BLE001
        return None


def _trainer_runs() -> dict | None:
    """Metrics from the newest HF Trainer state that belongs to the served model.

    Checkpoints from other runs (different label set) are skipped, and logged
    ratios outside [0, 1] are dropped as invalid rather than displayed.
    """
    served = _num_labels(MODEL_DIR / "config.json")
    states = [p for p in MODEL_DIR.glob("**/trainer_state.json")
              if served is None or _num_labels(p.parent / "config.json") in (None, served)]
    states.sort(key=lambda p: json.loads(p.read_text()).get("global_step", 0))
    if not states:
        return None
    state = json.loads(states[-1].read_text())
    hist = state.get("log_history", [])
    train = [{"step": h["step"], "loss": h["loss"]} for h in hist if "loss" in h]
    ratio = ("accuracy", "precision", "recall", "f1")
    invalid = lambda k, v: any(r in k for r in ratio) and not 0 <= v <= 1  # noqa: E731
    evals = [{k: h[k] for k in h if k == "step" or (k.startswith("eval_") and not invalid(k, h[k]))}
             for h in hist if "eval_loss" in h]
    dropped = sorted({f"{k}={h[k]}" for h in hist for k in h if k.startswith("eval_") and invalid(k, h[k])})
    return {"global_step": state.get("global_step"), "epochs": state.get("epoch"),
            "train_loss": train, "eval": evals, "final_eval": evals[-1] if evals else None,
            "dropped_invalid": dropped,
            "source": str(states[-1].relative_to(ROOT)).replace("\\", "/")}


def training_info() -> dict:
    corpus_lines = None
    if CORPUS_FILE.exists():
        with CORPUS_FILE.open(encoding="utf-8") as f:
            corpus_lines = sum(1 for _ in f)
    return {
        "train": _parse_train(),
        "corpus": {**_parse_corpus_builder(), "generated_lines": corpus_lines},
        "model_dir_present": (MODEL_DIR / "config.json").exists(),
        "run": _trainer_runs(),
        "ner": ner.status(),
    }


# --- pattern-layer benchmark --------------------------------------------------

def _luhn_complete(prefix: str, length: int, rng: random.Random) -> str:
    body = prefix + "".join(rng.choices(string.digits, k=length - len(prefix) - 1))
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return body + str((10 - total % 10) % 10)


def _gen_value(label: str, rng: random.Random) -> str:
    if label == "CARD":
        prefix, length = rng.choice([("4", 16), ("51", 16), ("55", 16), ("6011", 16), ("34", 15), ("37", 15)])
        num = _luhn_complete(prefix, length, rng)
        sep = rng.choice(["", " ", "-"])
        if not sep:
            return num
        groups = [num[:4], num[4:10], num[10:]] if length == 15 else [num[i:i + 4] for i in range(0, 16, 4)]
        return sep.join(groups)
    if label == "PHONE":
        n = str(rng.randint(6, 9)) + "".join(rng.choices(string.digits, k=9))
        return rng.choice([n, f"+91 {n[:5]} {n[5:]}", f"+91-{n}", f"0{n}", f"{n[:5]} {n[5:]}",
                           f"+1 {rng.randint(200, 999)} 555 {rng.randint(1000, 9999)}",
                           f"+44 20 {rng.randint(1000, 9999)} {rng.randint(1000, 9999)}"])
    if label == "EMAIL":
        user = rng.choice(["priya.s", "rahul_92", "a.k.verma", "dev+alerts", "support", "neha.gupta"])
        dom = rng.choice(["example.com", "mail.co.in", "corp.example.org", "uni.ac.in"])
        return f"{user}{rng.randint(1, 99)}@{dom}"
    if label == "PAN":
        return ("".join(rng.choices(string.ascii_uppercase, k=5)) +
                "".join(rng.choices(string.digits, k=4)) + rng.choice(string.ascii_uppercase))
    if label == "IP":
        return ".".join(str(rng.randint(0, 255)) for _ in range(4))
    if label == "URL":
        return rng.choice([f"https://bank.example.com/login?id={rng.randint(100, 999)}",
                           f"http://portal.example.in/u/{rng.randint(1000, 9999)}",
                           f"www.example.org/reset/{rng.randint(10, 99)}"])
    if label == "OTP":
        return "".join(rng.choices(string.digits, k=rng.choice([4, 6, 6, 8])))
    raise ValueError(label)


TEMPLATES = {
    "CARD": ["Card number: {v}", "please charge {v} for the order", "My card is {v}, expiry 09/28"],
    "PHONE": ["Call me on {v}", "Phone: {v}", "whatsapp {v} after 6pm"],
    "EMAIL": ["Email: {v}", "send the invoice to {v} today", "contact {v}."],
    "PAN": ["PAN: {v}", "my pan card no. is {v}", "Tax ID {v} verified"],
    "IP": ["Login from IP {v}", "server {v} is down", "blocked {v}."],
    "URL": ["visit {v}", "reset link: {v}.", "Open ({v}) to continue"],
    # The last two phrasings are realistic but have no keyword before the code.
    "OTP": ["Your OTP is {v}", "verification code: {v}", "PIN {v} for ATM",
            "use code {v} to log in", "{v} is your one-time password"],
}

NEGATIVES = [
    "Order #{n13} shipped yesterday",
    "Invoice total Rs {amt} due on 12/05/2026",
    "Card ending 4242 was declined",
    "Rejected card {badcard}",
    "Running version 1.2.3.4.5 of the app",
    "Employee id {n6} joined team 42",
    "Meeting at 10:30 in room 204",
    "Address 999.300.1.1 is not an IP",
]


def _negative(rng: random.Random) -> str:
    good = _luhn_complete("4", 16, rng)
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    return rng.choice(NEGATIVES).format(
        n13="".join(rng.choices(string.digits, k=13)), amt=f"{rng.randint(1, 99)},{rng.randint(100, 999)}",
        badcard=bad, n6="".join(rng.choices(string.digits, k=6)))


# Names only the model can find: the pattern layer has no PERSON detector.
PERSON_TEMPLATES = ["Name: {v}", "Hello {v}, your order has shipped", "Please contact {v} for details",
                    "Account holder {v} requested a refund"]
PERSON_NAMES = ["Priya Sharma", "Rahul Verma", "Ananya Iyer", "Arjun Mehta", "Neha Gupta", "Vikram Singh",
                "Sara Khan", "John Miller", "Emily Carter", "Rohan Das", "Kavya Nair", "Aditya Rao"]


def _build_cases(per_label: int, negatives: int, seed: int, with_person: bool = False) -> list:
    """Seeded benchmark: (text, [(label, start, end)]) with one planted value per sentence."""
    rng = random.Random(seed)
    cases = []
    groups = dict(TEMPLATES, **({"PERSON": PERSON_TEMPLATES} if with_person else {}))
    for label, templates in groups.items():
        for _ in range(per_label):
            v = rng.choice(PERSON_NAMES) if label == "PERSON" else _gen_value(label, rng)
            text = rng.choice(templates).format(v=v)
            start = text.index(v)
            cases.append((text, [(label, start, start + len(v))]))
    for _ in range(negatives):
        cases.append((_negative(rng), []))
    return cases


def _prf(t, f_p, f_n):
    p = t / (t + f_p) if t + f_p else 1.0
    r = t / (t + f_n) if t + f_n else 1.0
    return {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0,
            "tp": t, "fp": f_p, "fn": f_n}


def _score(cases: list, run, labels: list[str]) -> dict:
    """Score a detector (text -> [DetectionResult]) on *cases*.

    exact:   label and character span both match.
    overlap: label matches and the predicted span overlaps the gold span,
             i.e. the value would still be redacted (what matters for leakage).
    """
    tp, fp, fn = defaultdict(int), defaultdict(int), defaultdict(int)
    ov_tp, ov_fn = defaultdict(int), defaultdict(int)
    misses, false_alarms = defaultdict(list), []
    neg_flagged = 0
    t0 = time.perf_counter()
    for text, gold in cases:
        dets = run(text)
        pred = {(d.label, d.start, d.end) for d in dets}
        gold_set = set(gold)
        for g in gold_set:
            if g in pred:
                tp[g[0]] += 1
            else:
                fn[g[0]] += 1
                if len(misses[g[0]]) < 2:
                    misses[g[0]].append(text)
            if any(p[0] == g[0] and p[1] < g[2] and g[1] < p[2] for p in pred):
                ov_tp[g[0]] += 1
            else:
                ov_fn[g[0]] += 1
        for p in pred - gold_set:
            fp[p[0]] += 1
            if not gold and len(false_alarms) < 3:
                false_alarms.append({"text": text, "label": p[0]})
        neg_flagged += bool(not gold and dets)
    elapsed = (time.perf_counter() - t0) * 1000
    per = {lab: {**_prf(tp[lab], fp[lab], fn[lab]), "misses": misses[lab],
                 "overlap_recall": ov_tp[lab] / max(1, ov_tp[lab] + ov_fn[lab])} for lab in labels}
    n_neg = sum(1 for _, g in cases if not g)
    return {
        "per_label": per,
        "overall": {**_prf(sum(tp.values()), sum(fp.values()), sum(fn.values())),
                    "overlap_recall": sum(ov_tp.values()) / max(1, sum(ov_tp.values()) + sum(ov_fn.values()))},
        "negatives": {"total": n_neg, "flagged": neg_flagged, "examples": false_alarms},
        "cases": len(cases), "ms_total": elapsed, "ms_per_case": elapsed / len(cases),
    }


@lru_cache(maxsize=1)
def evaluate_patterns(per_label: int = 60, negatives: int = 120, seed: int = 7) -> dict:
    """Exact-span precision / recall / F1 of the pattern layer on a synthetic benchmark."""
    res = _score(_build_cases(per_label, negatives, seed), detect, list(TEMPLATES))
    return {**res, "seed": seed}


@lru_cache(maxsize=1)
def evaluate_model(per_label: int = 25, negatives: int = 50, seed: int = 11) -> dict:
    """Pattern layer vs NER model vs both, on a benchmark that also contains names.

    Uses a different seed from evaluate_patterns so the two are independent
    samples. Returns {"available": False} when the model isn't loaded.
    """
    st = ner.status(wait=True)
    if st["state"] != "loaded":
        return {"available": False, "status": st}
    cases = _build_cases(per_label, negatives, seed, with_person=True)
    labels = list(TEMPLATES) + ["PERSON"]
    model_only = lambda t: ner.predict(t) or []  # noqa: E731
    configs = {
        "pattern": _score(cases, detect, labels),
        "model": _score(cases, model_only, labels),
        "ensemble": _score(cases, lambda t: detect(t, ner.predict(t)), labels),
    }
    return {"available": True, "status": ner.status(), "seed": seed, "cases": len(cases), "configs": configs}


# --- canary audit -------------------------------------------------------------

CANARY_SENTENCES = {
    "card": "Customer paid with {v} at checkout.",
    "phone": "Reach the customer on {v}.",
    "otp": "Your OTP is {v}.",
    "email": "Receipt sent to {v}.",
    "ip": "Request came from {v}.",
    "url": "Callback was {v}",
}


CANARY_MARKERS = [
    "fake_card_4111111111111111",
    "fake_phone_9876543210",
    "fake_otp_123456",
    "fake_email_x@y.z",
    "fake_ip_8.8.8.8",
    "fake_url_https://example.com/pass=secret",
]


@lru_cache(maxsize=1)
def canary_audit() -> dict:
    """Push the canary values through sanitize(); count leaks."""
    from src.pipeline.sanitize import SanitizationError, sanitize

    rows = []
    for marker in CANARY_MARKERS:
        _, kind, value = marker.split("_", 2)
        text = CANARY_SENTENCES.get(kind, "{v}").format(v=value)
        try:
            out = sanitize(text).sanitized
            leaked = value in out
        except SanitizationError:
            out, leaked = "(blocked: fail-closed)", False
        rows.append({"kind": kind.upper(), "input": text, "output": out, "leaked": leaked})
    return {"markers": len(rows), "leaked": sum(r["leaked"] for r in rows), "rows": rows}


_warm = threading.Event()


def warm_up() -> None:
    """Load the model and run every benchmark once, off the request path."""
    def run():
        try:
            evaluate_patterns()
            canary_audit()
            evaluate_model()
        finally:
            _warm.set()
    threading.Thread(target=run, name="insights-warmup", daemon=True).start()


def model_evaluation() -> dict:
    """evaluate_model() if it's ready, else a 'measuring' placeholder (never blocks)."""
    if not _warm.is_set():
        return {"available": None, "status": {"state": "measuring", "detail": "benchmark running"}}
    return evaluate_model()


def detectors_info() -> list[dict]:
    return [{"name": n, "label": lab, "method": m, "priority": i + 1}
            for i, (n, lab, m, _) in enumerate(DETECTORS)]


def main() -> None:
    ev = evaluate_patterns()
    print(f"Pattern benchmark: {ev['cases']} cases, {ev['ms_per_case']:.3f} ms/case")
    for lab, m in ev["per_label"].items():
        print(f"  {lab:6s} P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f}  misses={m['misses']}")
    o = ev["overall"]
    print(f"  ALL    P={o['precision']:.2f} R={o['recall']:.2f} F1={o['f1']:.2f}")
    print(f"  negatives flagged: {ev['negatives']['flagged']}/{ev['negatives']['total']} {ev['negatives']['examples']}")
    ca = canary_audit()
    print(f"Canary: {ca['leaked']}/{ca['markers']} leaked")
    for r in ca["rows"]:
        print(f"  {r['kind']:5s} {r['output']}")
    me = evaluate_model()
    if not me["available"]:
        print("Model:", me["status"])
    for name, res in me.get("configs", {}).items():
        o = res["overall"]
        print(f"[{name:8s}] P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f} "
              f"overlapR={o['overlap_recall']:.3f} neg={res['negatives']['flagged']}/{res['negatives']['total']} "
              f"{res['ms_per_case']:.1f} ms/case")
        for lab, m in res["per_label"].items():
            print(f"    {lab:6s} P={m['precision']:.2f} R={m['recall']:.2f} ovR={m['overlap_recall']:.2f} miss={m['misses'][:1]}")
    print(json.dumps(training_info(), indent=1)[:1500])


if __name__ == "__main__":
    main()
