"""Phase 3 model-layer tests.

Fake-model tests always run. Real-model tests are skipped when models/ has
not been trained locally (python -m src.model.train_url / train_text).
"""
import json
from pathlib import Path

import pytest

from src.model import predict
from src.pipeline.analyze import analyze

ROOT = Path(__file__).resolve().parents[1]
HAVE_MODELS = all(p.exists() for p in predict.FILES.values())


@pytest.fixture
def fake_models(monkeypatch, models_on):
    def use(url_p=0.9, text_p=0.9):
        monkeypatch.setattr(predict, "available", lambda kind: True)
        monkeypatch.setattr(predict, "url_proba", lambda urls: [url_p] * len(urls))
        monkeypatch.setattr(predict, "text_proba", lambda text: text_p)
    return use


def test_models_off_are_unavailable_not_safe():
    r = analyze("Meeting moved to 4pm, see you there")
    assert r["coverage"]["url_model"] == r["coverage"]["text_model"] == "unavailable"
    assert r["confidence"] == "low"


def test_model_findings_shape(fake_models):
    fake_models(0.95, 0.95)
    r = analyze("Your account is suspended, verify at http://example-login.xyz/a now")
    assert r["coverage"] == {"rules": "ran", "anomaly": "ran", "url_model": "ran", "text_model": "ran"}
    assert r["urls"][0]["score"] == 0.95
    ml = {f["source"]: f for f in r["findings"] if f["tier"] == "ml"}
    assert set(ml) == {"url-model", "text-model"}
    assert ml["url-model"]["start"] is not None and ml["text-model"]["start"] is None
    assert all(f["contribution"] > 0 and f["confidence"] == 0.95 for f in ml.values())


def test_low_model_scores_are_not_listed_as_evidence(fake_models):
    fake_models(0.1, 0.1)
    r = analyze("See the notes at https://docs.python.org/3/")
    assert not [f for f in r["findings"] if f["tier"] == "ml"]
    assert r["coverage"]["text_model"] == "ran" and r["urls"][0]["score"] == 0.1


def test_model_alone_cannot_make_phishing(fake_models):
    fake_models(0.99, 0.99)
    r = analyze("Hello, here is the report https://example.org/report")
    assert r["verdict"] != "phishing"


def test_nothing_to_act_on_caps_even_confident_models(fake_models):
    fake_models(0.99, 0.99)
    r = analyze("Dear customer, update your KYC within 24 hours using our official website.")
    assert r["verdict"] == "safe" and "no link or number" in r["explanation"]


def test_failing_model_is_reported(monkeypatch, models_on):
    monkeypatch.setattr(predict, "available", lambda kind: True)
    monkeypatch.setattr(predict, "url_proba", lambda urls: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(predict, "text_proba", lambda text: 0.2)
    r = analyze("Check http://example.org/a please today")
    assert r["coverage"]["url_model"] == "failed" and r["partial"] is True and r["confidence"] != "high"
    assert r["urls"][0]["score"] is None


def test_text_model_skips_bare_urls(fake_models):
    fake_models(0.2, 0.99)
    r = analyze("https://example.org/a")
    assert r["kind"] == "url" and not [f for f in r["findings"] if f["source"] == "text-model"]


# --- real trained models ------------------------------------------------------------

needs_models = pytest.mark.skipif(not HAVE_MODELS, reason="models not trained locally")


@needs_models
def test_real_models_load(models_on):
    assert predict.status("url")["state"] == predict.status("text")["state"] == "loaded"


@needs_models
@pytest.mark.parametrize("text", [
    "123456 is your OTP for txn of Rs 500 at Amazon. Valid 5 mins. Do not share it with anyone -HDFC Bank",
    "Rs.500 debited from HDFC Bank A/c **1234 on 12-10-24 to VPA abc@okaxis. Not you? Call 18002586161 -HDFC Bank",
    "Dear customer, update your KYC within 24 hours using our official website.",
    "Your Amazon order has shipped. Track it at https://www.amazon.in/gp/your-orders",
    "Meeting moved to 4pm, see you there 🙂",
])
def test_real_models_keep_legit_messages_safe(models_on, text):
    r = analyze(text)
    assert r["verdict"] == "safe", [(f["label"], f["contribution"]) for f in r["findings"]]
    assert r["confidence"] == "high"


@needs_models
@pytest.mark.parametrize("text,at_least", [
    ("URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz/login", "phishing"),
    ("Your electricity connection will be disconnected tonight. Contact officer 9876543210 immediately.", "suspicious"),
    ("Congratulations! You have won Rs 25,00,000 in the KBC lottery. Pay Rs 5,000 processing fee to receive your prize.",
     "suspicious"),
])
def test_real_models_flag_scams(models_on, text, at_least):
    order = ["safe", "suspicious", "phishing"]
    assert order.index(analyze(text)["verdict"]) >= order.index(at_least)
