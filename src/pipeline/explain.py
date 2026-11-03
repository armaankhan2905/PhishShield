"""Plain-English explanations: an LLM on Groq grounded in the findings, or a template.

Owner: Ryan. The model only ever sees:
  - the verdict, score and confidence,
  - the reasons from findings that added points (written by the rules and models),
  - the registered domains those findings name,
  - the SANITIZED message (personal data replaced by [REDACTED:TYPE]).
It is told to restate those reasons, not to add new ones, and its answer is
checked: an answer that names a domain not in the findings, contradicts the
verdict, is empty or too long, is thrown away and the template is used instead.

Disabled (template only) when GROQ_API_KEY isn't set, PHISHSHIELD_LLM=0, or
Groq isn't reachable. Config: GROQ_API_KEY (free at https://console.groq.com/keys),
PHISHSHIELD_LLM_MODEL (default openai/gpt-oss-120b), GROQ_URL.
"""
from __future__ import annotations

import logging
import os
import re
import time
from typing import List, Optional

import requests

from src.detection import domains as D

logger = logging.getLogger(__name__)

GROQ_URL = os.environ.get("GROQ_URL", "https://api.groq.com/openai/v1")
LLM_MODEL = os.environ.get("PHISHSHIELD_LLM_MODEL", "openai/gpt-oss-120b")
TIMEOUT_S = 20
MAX_CHARS = 700
STATUS_TTL_S = 300

SYSTEM = (
    "You explain the result of a phishing check to someone who is not technical. "
    "Use ONLY the findings you are given: restate them in plain words, most important first. "
    "Never add reasons, facts, domains, names or numbers that are not in the findings. "
    "Do not guess redacted values shown as [REDACTED:TYPE]. "
    "Write 2 or 3 short sentences, then one sentence starting with 'What to do:'. Plain text, no lists, no markdown."
)

_status_cache = {"at": 0.0, "value": None}


def template(verdict: str, score: int, reasons: List[str], confidence: str, gate: Optional[str] = None) -> str:
    """Deterministic explanation built only from the findings' reasons."""
    uniq = list(dict.fromkeys(reasons))
    if not uniq:
        text = "No phishing signals were found in this message."
    elif verdict == "safe":
        text = f"No strong phishing evidence ({score}/100). Worth noting: " + "; ".join(uniq[:2]) + "."
    else:
        text = f"Rated {verdict} ({score}/100). Main reasons: " + "; ".join(uniq[:3]) + "."
    if gate == "nothing_to_act_on":
        text += " The message has no link or number to act on, which keeps the risk low."
    if confidence == "low":
        text += " Some checks were not available, so treat this result with caution."
    return text


def _headers() -> dict:
    return {"Authorization": f"Bearer {os.environ.get('GROQ_API_KEY', '').strip()}"}


def status() -> dict:
    """Whether the LLM can be used. Cached so a missing key or outage doesn't slow every call."""
    if os.environ.get("PHISHSHIELD_LLM", "1") == "0":
        return {"available": False, "detail": "disabled (PHISHSHIELD_LLM=0)"}
    if not os.environ.get("GROQ_API_KEY", "").strip():
        return {"available": False, "detail": "GROQ_API_KEY isn't set"}
    now = time.monotonic()
    if _status_cache["value"] is not None and now - _status_cache["at"] < STATUS_TTL_S:
        return _status_cache["value"]
    try:
        r = requests.get(f"{GROQ_URL}/models", headers=_headers(), timeout=3)
        if r.status_code in (401, 403):
            value = {"available": False, "detail": "Groq rejected GROQ_API_KEY"}
        else:
            r.raise_for_status()
            names = [m.get("id") for m in r.json().get("data", [])]
            value = ({"available": True, "model": LLM_MODEL, "detail": "Groq"} if LLM_MODEL in names
                     else {"available": False, "detail": f"Groq doesn't offer {LLM_MODEL} (set PHISHSHIELD_LLM_MODEL)"})
    except Exception:  # noqa: BLE001
        value = {"available": False, "detail": "Groq isn't reachable"}
    _status_cache.update(at=now, value=value)
    return value


_DOMAIN_IN_TEXT = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
_SAFE_CONTRADICTION = re.compile(r"\b(?:is|looks like|appears to be|this is) (?:a )?(?:phishing|scam|fraud)", re.I)


def check_answer(answer: str, verdict: str, allowed_domains: List[str]) -> Optional[str]:
    """Why an LLM answer must be rejected, or None if it can be shown."""
    if not answer or len(answer) > MAX_CHARS:
        return "empty or too long"
    allowed = {d.lower() for d in allowed_domains}
    for m in _DOMAIN_IN_TEXT.finditer(answer):
        info = D.parse_url(m.group(0))
        if info.valid and info.registered.lower() not in allowed:
            return f"names a domain not in the findings ({m.group(0)})"
    if verdict == "safe" and _SAFE_CONTRADICTION.search(answer):
        return "contradicts the verdict"
    lower = answer.lower()
    if "what to do" not in lower:
        return "missing the 'What to do' advice"
    explanation = answer[:lower.index("what to do")]
    if len(re.sub(r"(?i)verdict:[^.]*\.", "", explanation).strip()) < 40:
        return "doesn't explain the reasons"
    return None


def llm(verdict: str, score: int, confidence: str, reasons: List[str], domains: List[str], sanitized: str) -> dict:
    """{"text", "source": "llm"|"template", "detail", "model"?}. Never raises."""
    if verdict == "safe" or not reasons:
        # Nothing to explain: a model would only add claims the checks didn't make.
        return {"source": "template", "detail": "nothing was flagged, so the plain summary is used"}
    st = status()
    if not st["available"]:
        return {"source": "template", "detail": st["detail"]}
    findings = "\n".join(f"- {r}" for r in dict.fromkeys(reasons)) or "- (no findings)"
    user = (f"Verdict: {verdict} (score {score}/100, confidence {confidence}).\n"
            f"Findings:\n{findings}\n"
            f"Domains named in the findings: {', '.join(domains) or 'none'}\n"
            f"Message (personal data redacted):\n\"\"\"\n{sanitized[:2000]}\n\"\"\"")
    t0 = time.perf_counter()
    try:
        body = {"model": LLM_MODEL, "temperature": 0.1, "max_tokens": 1024,
                "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]}
        if LLM_MODEL.startswith("openai/gpt-oss"):
            # Reasoning models: keep the hidden reasoning short so the answer fits in max_tokens.
            body.update(reasoning_effort="low", include_reasoning=False)
        r = requests.post(f"{GROQ_URL}/chat/completions", headers=_headers(), timeout=TIMEOUT_S, json=body)
        r.raise_for_status()
        answer = (r.json()["choices"][0]["message"]["content"] or "").strip()
    except Exception as exc:  # noqa: BLE001 - log the failure kind only, never the prompt
        logger.warning("LLM explanation failed: %s", type(exc).__name__)
        return {"source": "template", "detail": "the AI model didn't answer in time"}
    problem = check_answer(answer, verdict, domains)
    if problem:
        logger.info("LLM explanation rejected: %s", problem.split(" (")[0])
        return {"source": "template", "detail": f"the AI answer was rejected ({problem})"}
    return {"text": answer, "source": "llm", "model": LLM_MODEL,
            "detail": "written by an AI model from the findings", "ms": round((time.perf_counter() - t0) * 1000)}


def domains_in(findings: List[dict]) -> List[str]:
    out = []
    for f in findings:
        if f.get("family") in ("link", "sender", "ml") and f.get("text"):
            raw = f["text"].split("<")[-1].strip(" >") if f.get("field") in ("from", "reply_to") else f["text"]
            raw = raw.rsplit("@", 1)[-1]
            info = D.parse_url(raw)
            if info.valid and info.registered not in out:
                out.append(info.registered)
    return out
