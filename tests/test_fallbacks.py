"""Phase 5 fallback matrix and privacy checks (revised plan §10, P5 -> P6).

Every case must fail safely: a missing or broken part lowers confidence or
returns a clear error. It never turns into a confident "safe", and no message
text ends up in logs.
"""
import logging

import pytest
from fastapi.testclient import TestClient

from src.model import predict
from src.pipeline import explain, files
from src.pipeline.demo import app

client = TestClient(app)
PHISH = "URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz/login"
SECRET = "Call Ravi on 9876501234 about the parcel"


def analyze(**body):
    return client.post("/api/analyze", json=body)


# --- detection layers ---------------------------------------------------------------

def test_rules_only_still_flags_and_says_checks_were_limited():
    body = analyze(text=PHISH).json()  # conftest: models off
    assert body["verdict"] == "phishing" and body["confidence"] == "medium"
    assert body["coverage"]["url_model"] == body["coverage"]["text_model"] == "unavailable"


@pytest.mark.parametrize("missing", ["url", "text"])
def test_one_model_missing(monkeypatch, models_on, missing):
    monkeypatch.setattr(predict, "available", lambda kind: kind != missing)
    monkeypatch.setattr(predict, "url_proba", lambda urls: [0.9] * len(urls))
    monkeypatch.setattr(predict, "text_proba", lambda text: 0.9)
    body = analyze(text=PHISH).json()
    assert body["coverage"][f"{missing}_model"] == "unavailable"
    assert body["confidence"] != "high" and body["verdict"] != "safe"


def test_legit_message_with_missing_models_is_not_a_confident_safe():
    body = analyze(text="Meeting moved to 4pm").json()
    assert body["verdict"] == "safe" and body["confidence"] == "low" and "caution" in body["explanation"]


# --- explanation ------------------------------------------------------------------------

def test_groq_down_falls_back_to_template(monkeypatch):
    monkeypatch.setattr(explain, "status", lambda: {"available": False, "detail": "Groq isn't reachable"})
    out = client.post("/api/explain", json={"text": PHISH}).json()
    assert out["source"] == "template" and out["explanation"].startswith("Rated phishing")


def test_llm_error_falls_back_to_template(monkeypatch):
    monkeypatch.setattr(explain, "status", lambda: {"available": True, "model": "x"})

    def boom(*a, **k):
        raise TimeoutError("slow")
    monkeypatch.setattr(explain.requests, "post", boom)
    out = client.post("/api/explain", json={"text": PHISH}).json()
    assert out["source"] == "template" and "didn't answer" in out["detail"]


@pytest.mark.parametrize("answer,problem", [
    ("This message is from evil-other.com and asks for money. It is fake. What to do: delete it.", "domain"),
    ("", "empty"),
    ("Verdict: phishing (100/100). What to do: delete it.", "doesn't explain"),
    ("It pretends to be SBI using a fake domain and asks you to verify your details quickly.", "What to do"),
])
def test_llm_answers_that_add_or_skip_things_are_rejected(answer, problem):
    assert problem in (explain.check_answer(answer, "phishing", ["sbi-kyc.xyz"]) or "")


def test_grounded_llm_answer_is_accepted():
    ok = "The link goes to sbi-kyc.xyz, which isn't an SBI site, and it asks you to verify your KYC. What to do: don't click it."
    assert explain.check_answer(ok, "phishing", ["sbi-kyc.xyz"]) is None


def test_safe_results_never_use_the_llm(monkeypatch):
    called = []
    monkeypatch.setattr(explain, "status", lambda: called.append(1) or {"available": True, "model": "x"})
    out = client.post("/api/explain", json={"text": "Meeting moved to 4pm, see you"}).json()
    assert out["source"] == "template" and not called


def test_no_groq_key_means_template_only(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert explain.status() == {"available": False, "detail": "GROQ_API_KEY isn't set"}


def test_groq_status_checks_the_model_is_offered(monkeypatch):
    class R:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"data": [{"id": explain.LLM_MODEL}]}
    monkeypatch.setenv("GROQ_API_KEY", "test")
    monkeypatch.setitem(explain._status_cache, "value", None)
    monkeypatch.setattr(explain.requests, "get", lambda *a, **k: R())
    assert explain.status()["available"] is True


def test_groq_answer_is_read_from_the_chat_completion(monkeypatch):
    answer = ("It pretends to be SBI and the link goes to sbi-kyc.xyz, which SBI doesn't own, to collect your details. "
              "What to do: don't click it.")
    class R:
        def raise_for_status(self): pass
        def json(self): return {"choices": [{"message": {"content": answer}}]}
    monkeypatch.setattr(explain, "status", lambda: {"available": True, "model": "x"})
    monkeypatch.setattr(explain.requests, "post", lambda *a, **k: R())
    out = client.post("/api/explain", json={"text": PHISH}).json()
    assert out["source"] == "llm" and out["explanation"] == answer


def test_hosted_mode_is_reported(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_MODE", "hosted")
    assert client.get("/api/health").json()["mode"] == "hosted"


# --- inputs ------------------------------------------------------------------------------

@pytest.mark.parametrize("body,status", [
    ({"text": ""}, 422), ({"text": "   "}, 422), ({"text": "x" * 20_001}, 422), ({"text": "hi", "kind": "fax"}, 422),
])
def test_bad_requests_are_rejected_clearly(body, status):
    assert analyze(**body).status_code == status


@pytest.mark.parametrize("url", ["http://", "http://[::1", "javascript:alert(1)", "htp:/broken..com", "http://exa mple.com"])
def test_malformed_urls_do_not_crash(url):
    r = analyze(text=url)
    assert r.status_code == 200 and r.json()["coverage"]["rules"] == "ran"


def test_long_input_at_the_limit_is_handled():
    r = analyze(text=("Your account is blocked. " * 900)[:20_000])
    assert r.status_code == 200 and r.json()["verdict"] in {"safe", "suspicious", "phishing"}


def upload(name, data, ctype="application/octet-stream"):
    return client.post("/api/analyze/file", files={"file": (name, data, ctype)})


EML = b"""From: "HDFC Bank" <alerts@hdfc-netbanking-secure.com>
Reply-To: hdfc.support@gmail.com
Subject: NetBanking suspended
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Dear Customer,</p><p>Login at <a href="http://hdfc-netbanking-secure.com/login">https://www.hdfcbank.com/login</a> to unlock.</p>
<div style="display:none">hdfc official genuine</div><script>alert(1)</script>
"""


def test_html_email_upload_is_parsed_safely():
    body = upload("mail.eml", EML, "message/rfc822").json()
    labels = {f["label"] for f in body["findings"]}
    assert {"LINK_TEXT_MISMATCH", "SENDER_BRAND_MISMATCH", "REPLY_TO_MISMATCH"} <= labels
    assert "alert(1)" not in body["text"] and "genuine" not in body["text"]
    assert body["file"]["hidden_html_blocks"] == 1 and body["verdict"] == "phishing"


@pytest.mark.parametrize("name,data,status", [
    ("photo.png", b"\x89PNG\r\n", 415), ("empty.eml", b"", 400), ("big.txt", None, 413),
    ("fake.pdf", b"%PDF-1.4 not really", 400), ("random.eml", b"just some words", 400),
], ids=["png", "empty", "too-big", "broken-pdf", "not-an-email"])
def test_unsupported_or_broken_files_get_clear_errors(name, data, status):
    r = upload(name, data if data is not None else b"a" * (files.MAX_BYTES + 1))
    assert r.status_code == status and isinstance(r.json()["detail"], str)


def test_text_file_upload():
    body = upload("sms.txt", PHISH.encode(), "text/plain").json()
    assert body["verdict"] == "phishing" and body["text"] == PHISH


# --- privacy -------------------------------------------------------------------------------

def test_message_text_never_reaches_the_logs(caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    analyze(text=SECRET)
    upload("m.eml", EML.replace(b"Dear Customer", SECRET.encode()), "message/rfc822")
    monkeypatch.setattr(explain, "status", lambda: {"available": True, "model": "x"})
    monkeypatch.setattr(explain.requests, "post", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(SECRET)))
    client.post("/api/explain", json={"text": SECRET + " http://sbi-kyc.xyz"})
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "9876501234" not in logged and "Ravi" not in logged


def test_removed_privacylens_endpoints_are_gone():
    for path in ("/api/rag", "/api/pipeline", "/api/document"):
        assert client.get(path).status_code in (404, 405)
    assert client.get("/ask", follow_redirects=False).status_code == 301


def test_extension_ids_can_be_pinned(monkeypatch):
    from src.pipeline import demo
    monkeypatch.setenv("PHISHSHIELD_EXTENSION_IDS", "a" * 32)
    rx = demo._extension_origins()
    assert "aaaaaaaa" in rx and "[a-p]{32}" not in rx
