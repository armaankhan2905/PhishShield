"""Sanitization pipeline: detect() -> replace spans with placeholders.

Pipeline:
  1. Load raw input (DOM / form / page)  -> detection (src.detection)
  2. Sanitize: replace each span with [REDACTED:{TYPE}]
  3. Leak check: no detected raw value may survive in the output
  4. (later) Local LLM reasoning + action validation over the sanitized view

Fail-closed: if detection or the leak check fails, SanitizationError is raised
and the caller must block the action instead of passing raw data on.

Run:
    python -m src.pipeline.sanitize "My card is 4532015112830366"
"""
from __future__ import annotations

import logging
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import List

from src.detection import DetectionResult, detect_trace
from src.detection import ner

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


class SanitizationError(RuntimeError):
    """Raised when input cannot be safely sanitized (fail-closed)."""


@dataclass
class SanitizeResult:
    original: str
    sanitized: str
    detections: List[DetectionResult] = field(default_factory=list)
    leaked: int = 0
    latency_ms: float = 0.0
    trace: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "sanitized": self.sanitized,
            "detections": [asdict(d) for d in self.detections],
            "leaked": self.leaked,
            "latency_ms": round(self.latency_ms, 2),
            "trace": self.trace,
        }


def placeholder(label: str, typed: bool = True) -> str:
    return f"[REDACTED:{label}]" if typed else "[REDACTED]"


def sanitize_text(text: str, detections: List[DetectionResult], typed: bool = True) -> str:
    """Replace detected spans with placeholders; preserve everything else."""
    out: list[str] = []
    cursor = 0
    for d in sorted(detections, key=lambda r: r.start):
        if d.start < cursor:  # overlapping span already covered
            continue
        out.append(text[cursor:d.start])
        out.append(placeholder(d.label, typed))
        cursor = d.end
    out.append(text[cursor:])
    return "".join(out)


def _occurrences(value: str, text: str):
    """Whole-token occurrences of *value* in *text* (not inside a longer word/number)."""
    for m in re.finditer(re.escape(value), text):
        s, e = m.span()
        if s > 0 and text[s - 1].isalnum() and value[0].isalnum():
            continue
        if e < len(text) and text[e].isalnum() and value[-1].isalnum():
            continue
        yield s, e


def propagate(text: str, detections: List[DetectionResult]) -> List[DetectionResult]:
    """Once a value is detected, redact every other occurrence of it too.

    e.g. a name caught on line 1 is also hidden where it repeats on line 9,
    instead of leaking there (or failing the whole document closed).
    """
    taken = [(d.start, d.end) for d in detections]
    extra = []
    for d in {d.text: d for d in detections}.values():
        if len(d.text.strip()) < 3:
            continue
        for s, e in _occurrences(d.text, text):
            if not any(s < b and a < e for a, b in taken):
                extra.append(DetectionResult(d.text, d.label, s, e, d.confidence, "propagated"))
                taken.append((s, e))
    return sorted(detections + extra, key=lambda r: r.start)


def count_leaks(sanitized: str, detections: List[DetectionResult]) -> int:
    """Number of detected raw values that still appear (as whole tokens) in the sanitized text."""
    return sum(1 for d in {d.text: d for d in detections}.values()
               if d.text and next(_occurrences(d.text, sanitized), None) is not None)


# The NER model reads ~128 tokens at a time, so long text is sanitized in
# segments cut at line / sentence boundaries and stitched back together.
SEGMENT_CHARS = 360
_BREAK = re.compile(r"\n|(?<=[.!?;])\s+")


def segments(text: str, limit: int = SEGMENT_CHARS) -> List[tuple]:
    """Split *text* into (start, end) spans of at most ~limit chars, cut at breaks."""
    spans, start = [], 0
    while len(text) - start > limit:
        window = text[start:start + limit]
        cuts = [m.end() for m in _BREAK.finditer(window) if m.end() > limit // 3]
        if cuts:
            end = start + cuts[-1]
        else:  # no break: cut at the last space so a value isn't split mid-word
            sp = window.rfind(" ")
            end = start + (sp + 1 if sp > limit // 3 else limit)
        spans.append((start, end))
        start = end
    if start < len(text) or not spans:
        spans.append((start, len(text)))
    return spans


def _merge_traces(traces: List[dict], text: str, sanitized: str, n_dets: int, leaked: int) -> dict:
    base = {"detectors": [dict(d) for d in traces[0]["detectors"]], "merge": dict(traces[0]["merge"]),
            "model": dict(traces[0]["model"]), "sanitize": dict(traces[0]["sanitize"]),
            "leak_check": dict(traces[0]["leak_check"])}
    for tr in traces[1:]:
        for agg, d in zip(base["detectors"], tr["detectors"]):
            for k in ("matches", "rejected", "ms"):
                agg[k] += d[k]
        for k in ("candidates", "pattern", "model", "dropped_overlap", "kept", "ms"):
            base["merge"][k] += tr["merge"][k]
        base["model"]["matches"] += tr["model"]["matches"]
        base["model"]["ms"] += tr["model"]["ms"]
        base["sanitize"]["ms"] += tr["sanitize"]["ms"]
        base["leak_check"]["ms"] += tr["leak_check"]["ms"]
    base["input"] = {"chars": len(text), "lines": text.count("\n") + 1 if text else 0, "segments": len(traces)}
    base["sanitize"].update(replaced=n_dets, chars_out=len(sanitized))
    base["leak_check"].update(checked=n_dets, leaked=leaked)
    return base


def sanitize(text: str, typed: bool = True) -> SanitizeResult:
    """Detect and redact sensitive spans in *text*. Fail-closed on any error.

    Long text is processed segment by segment (see segments()); offsets in the
    returned detections always refer to the full *text*.
    """
    spans = segments(text)
    if len(spans) == 1:
        return _sanitize_one(text, typed)
    t0 = time.perf_counter()
    parts, dets, traces = [], [], []
    for s, e in spans:
        r = _sanitize_one(text[s:e], typed)
        parts.append(r.sanitized)
        traces.append(r.trace)
        dets.extend(DetectionResult(d.text, d.label, d.start + s, d.end + s, d.confidence, d.source)
                    for d in r.detections)
    n_before = len(dets)
    dets = propagate(text, dets)  # a value found in one segment is hidden in every segment
    sanitized = sanitize_text(text, dets, typed)
    leaked = count_leaks(sanitized, dets)  # re-check the stitched document as a whole
    if leaked:
        raise SanitizationError(f"{leaked} detected value(s) survived sanitization")
    trace = _merge_traces(traces, text, sanitized, len(dets), leaked)
    trace["merge"]["propagated"] = sum(tr["merge"].get("propagated", 0) for tr in traces) + len(dets) - n_before
    return SanitizeResult(text, sanitized, dets, leaked, (time.perf_counter() - t0) * 1000, trace)


def _sanitize_one(text: str, typed: bool = True) -> SanitizeResult:
    t0 = time.perf_counter()
    try:
        t = time.perf_counter()
        model_results = ner.predict(text)
        model_stage = {**ner.status(), "matches": len(model_results or []),
                       "ms": (time.perf_counter() - t) * 1000}
        detections, trace = detect_trace(text, model_results)
        found = len(detections)
        detections = propagate(text, detections)
        trace["merge"]["propagated"] = len(detections) - found
    except Exception as exc:  # noqa: BLE001 - fail closed on anything
        raise SanitizationError(f"detection failed: {exc}") from exc
    t = time.perf_counter()
    sanitized = sanitize_text(text, detections, typed)
    sanitize_ms = (time.perf_counter() - t) * 1000
    t = time.perf_counter()
    leaked = count_leaks(sanitized, detections)
    leak_ms = (time.perf_counter() - t) * 1000
    if leaked:
        raise SanitizationError(f"{leaked} detected value(s) survived sanitization")
    trace.update(
        input={"chars": len(text), "lines": text.count("\n") + 1 if text else 0},
        model=model_stage,
        sanitize={"replaced": len(detections), "chars_out": len(sanitized), "ms": sanitize_ms},
        leak_check={"checked": len(detections), "leaked": leaked, "ms": leak_ms},
    )
    return SanitizeResult(text, sanitized, detections, leaked,
                          (time.perf_counter() - t0) * 1000, trace)


def validate_action(action: dict, sanitized: str) -> bool:
    """Reject invalid/unsafe actions before execution."""
    # TODO: action validation logic for the reasoning step
    return True


def main() -> None:
    text = " ".join(sys.argv[1:]) or (
        "Hi, I'm paying with 4532 0151 1283 0366. Call +91 98765 43210 or "
        "mail test@example.com. OTP is 126225."
    )
    result = sanitize(text)
    print("Input:    ", result.original)
    print("Sanitized:", result.sanitized)
    for d in result.detections:
        print(f"  [{d.label:6s}] {d.text!r} {d.start}-{d.end}")
    print(f"Leaked: {result.leaked}  ({result.latency_ms:.2f} ms)")


if __name__ == "__main__":
    sys.exit(main())
