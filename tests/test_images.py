"""Screenshots, QR codes and UPI checks (src/pipeline/images.py, src/detection/upi.py).

The sample images are synthetic (demo/samples/make_images.py). QR tests need OpenCV; OCR tests
need RapidOCR and are skipped without it.
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.detection import upi
from src.pipeline import images
from src.pipeline.analyze import analyze
from src.pipeline.demo import app

client = TestClient(app)
SAMPLES = Path(__file__).resolve().parents[1] / "demo" / "static" / "samples"
cv2 = pytest.importorskip("cv2")
HAVE_OCR = images.ocr_available()


def upload(name):
    return client.post("/api/analyze/file", files={"file": (name, (SAMPLES / name).read_bytes(), "image/png")})


def labels(result):
    return {f["label"] for f in result["findings"] if f["contribution"] > 0}


# --- UPI rules on text ------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "Scan the QR code to receive Rs 2000 cashback in your account",
    "Enter your UPI PIN to receive the refund",
    "Approve the collect request to get your prize money",
])
def test_scan_or_pin_to_receive_is_flagged(text):
    r = analyze(text)
    assert "SCAN_TO_RECEIVE" in labels(r) and r["verdict"] != "safe"


@pytest.mark.parametrize("text", [
    "Never enter your UPI PIN to receive money. Stay safe -SBI",
    "You don't need to scan a QR code to receive money. Beware of fraud.",
    "Scan the QR at the counter to pay for your order",
    "Pay to rajesh.kumar@ybl for the books",
])
def test_warnings_and_ordinary_payments_are_not_flagged(text):
    assert not labels(analyze(text)) & {"SCAN_TO_RECEIVE", "UPI_ID_IMPERSONATION"}


def test_brand_upi_id_is_impersonation_and_not_a_website():
    r = analyze("Pay Rs 10 verification fee to sbi.kyc.support@okaxis to avoid blocking of your account.")
    assert "UPI_ID_IMPERSONATION" in labels(r)
    assert not r["urls"]  # the part before @ is not a link to kyc.support


def test_parse_upi():
    p = upi.parse_upi("upi://pay?pa=amazon.refund@ybl&pn=Amazon%20Refund&am=4999&cu=INR")
    assert p == {"pa": "amazon.refund@ybl", "pn": "Amazon Refund", "am": "4999", "tn": ""}
    assert upi.parse_upi("https://example.com") is None


def test_upi_qr_that_promises_money_is_confirmed():
    qr = ["upi://pay?pa=amazon.refund@ybl&pn=Amazon%20Refund%20Desk&am=4999"]
    r = analyze("Your refund has been approved. Scan this code.", qr=qr)
    assert {"QR_PAY_TO_RECEIVE", "UPI_PAYEE_CLAIMS_BRAND"} <= labels(r)
    assert r["verdict"] == "phishing"


def test_shop_qr_is_not_flagged():
    r = analyze("Thanks for shopping! Scan to pay your bill of Rs 340.",
                qr=["upi://pay?pa=sharmastore@okhdfcbank&pn=Sharma%20General%20Store&am=340"])
    assert r["verdict"] == "safe"


def test_link_qr_is_checked_as_a_link():
    r = analyze("Scan to pay the delivery charge", qr=["http://dhl-parcel-release.top/pay"])
    assert any(u["url"] == "http://dhl-parcel-release.top/pay" for u in r["urls"])
    assert "BRAND_IN_DOMAIN" in labels(r)


# --- images ------------------------------------------------------------------------------

def test_qr_codes_are_read_from_images():
    img = images._decode((SAMPLES / "qr-refund-scam.png").read_bytes())
    assert images.read_qr(img) == ["upi://pay?pa=amazon.refund@ybl&pn=Amazon%20Refund%20Desk&am=4999&cu=INR&tn=Refund"]


def test_unreadable_image_gets_a_clear_error():
    r = client.post("/api/analyze/file", files={"file": ("x.png", b"\x89PNG\r\n\x1a\nnot really", "image/png")})
    assert r.status_code == 415 and "image" in r.json()["detail"].lower()


def test_image_upload_reports_what_the_qr_does():
    body = upload("qr-shop-legit.png").json()
    assert body["file"]["type"] == "image"
    assert body["file"]["qr"] == [{"kind": "upi", "payee": "sharmastore@okhdfcbank", "name": "Sharma General Store",
                                   "amount": "340", "note": ""}]
    assert body["verdict"] == "safe"


@pytest.mark.skipif(not HAVE_OCR, reason="RapidOCR not installed")
@pytest.mark.parametrize("name,verdicts,label", [
    ("qr-refund-scam.png", {"phishing"}, "QR_PAY_TO_RECEIVE"),
    ("upi-id-scam.png", {"suspicious", "phishing"}, "UPI_ID_IMPERSONATION"),  # rules only here; 100 with the models
    ("qr-link-scam.png", {"phishing"}, "BRAND_IN_DOMAIN"),
])
def test_scam_screenshots_end_to_end(name, verdicts, label):
    body = upload(name).json()
    assert body["file"]["ocr"] == "ran" and body["text"].strip()
    assert body["verdict"] in verdicts and label in labels(body)
