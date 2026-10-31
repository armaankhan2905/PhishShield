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


# --- first-party emails: the sender owns every link and the email asks for nothing ----------------

def _email(sender, text, links=(), subject=""):
    return analyze(text, kind="email", email={"from": sender, "subject": subject},
                   links=[{"text": t, "href": h} for t, h in links])


NEWSLETTER = ("Win cash prizes worth INR 5,00,000! Registrations close today. Click here to register now. "
              "Also trending: Flipkart GRiD and the Amazon ML Challenge.")


def test_first_party_newsletter_is_safe_even_when_models_are_sure(fake_models):
    fake_models(url_p=0.99, text_p=0.99)
    r = _email("Unstop <noreply@unstop.news>", NEWSLETTER,
               [("Register", "https://unstop.com/hackathons/x"), ("Tracked", "https://u1.ct.sendgrid.net/ls/click?upn=a"),
                ("Instagram", "https://instagram.com/unstop")])
    assert r["verdict"] == "safe", r["findings"]
    assert not any(f["label"] == "BRAND_LINK_UNVERIFIED" for f in r["findings"])  # Flipkart/Amazon are only mentioned


@pytest.mark.parametrize("sender,links,text", [
    # asks for a password: no discount, whoever sends it
    ("IT <it@mail-quota-center.com>", [("Upgrade", "https://mail-quota-center.com/up")],
     "Your mailbox is almost full. Enter your password to upgrade your storage."),
    # a link to someone else's site
    ("Unstop <noreply@unstop.news>", [("Register", "https://unstop-prizes.top/claim")], NEWSLETTER),
    # free mail sender
    ("Unstop Team <unstop.team@gmail.com>", [("Register", "https://unstop.com/x")], NEWSLETTER),
    # display name claims a brand the sender doesn't own
    ("ChatGPT <noreply@chatgpt-alerts.com>", [], "Your ChatGPT code is 482913. Enter this code to continue."),
])
def test_no_discount_when_anything_is_off(fake_models, sender, links, text):
    fake_models(url_p=0.99, text_p=0.99)
    assert _email(sender, text, links)["verdict"] != "safe"


@pytest.mark.skipif(not HAVE_MODELS, reason="models not trained locally")
@pytest.mark.parametrize("sender,subject,text,links", [
    ("ChatGPT <noreply@tm.openai.com>", "Your ChatGPT code is 482913",
     "Your ChatGPT code is 482913. Enter this temporary verification code to continue. If you didn't try to log in, "
     "you can safely ignore this email.", []),
    ("OpenAI <noreply@tm.openai.com>", "Verify your email address",
     "To continue setting up your OpenAI account, please verify that this is your email address. This link will expire in 5 days.",
     [("Verify email address", "https://auth.openai.com/u/email-verification?ticket=xyz")]),
    ("Unstop <noreply@unstop.news>", "Win prizes worth INR 5 Lakhs | Registrations close today!", NEWSLETTER,
     [("Register Now", "https://unstop.com/hackathons/x")]),
    ("GitHub <noreply@github.com>", "[GitHub] Please verify your device",
     "A sign in attempt requires further verification because we did not recognize your device. To complete the sign in, "
     "enter the verification code on the unrecognized device. Verification code: 123456",
     [("Security settings", "https://github.com/settings/security")]),
])
def test_real_models_leave_ordinary_email_safe(models_on, sender, subject, text, links):
    r = _email(sender, text, links, subject)
    assert r["verdict"] == "safe", [(f["label"], f["contribution"]) for f in r["findings"]]


@pytest.mark.skipif(not HAVE_MODELS, reason="models not trained locally")
@pytest.mark.parametrize("sender,text,links", [
    ("OpenAI Billing <billing@openai-support.help>",
     "Your ChatGPT account has been suspended due to a failed payment. Update your card details within 24 hours.",
     [("Update billing", "https://openai-billing-verify.com/login")]),
    ("Account Security <alerts@secure-account-center.com>",
     "Unusual sign-in on your PayPal account. Verify your account within 24 hours or it will be suspended. Log in here to confirm.",
     [("Verify now", "https://secure-account-center.com/paypal/verify")]),
])
def test_real_models_still_catch_lookalike_and_own_domain_phishing(models_on, sender, text, links):
    assert _email(sender, text, links)["verdict"] == "phishing"
