"""Filter-dodging tricks (src/detection/normalize.py) and Indian scam types (src/detection/rules.py).

Run rules-only (the default in tests), so these don't depend on the trained models.
"""
import pytest

from src.detection.normalize import fold
from src.pipeline.analyze import analyze

SBI = "URGENT: Dear customer, your SBI KYC is pending and your account will be blocked today. Verify at http://sbi-kyc.xyz/login"


def labels(r):
    return {f["label"] for f in r["findings"] if f["contribution"] > 0}


# --- tricks ---------------------------------------------------------------------------------

@pytest.mark.parametrize("trick,text", [
    ("invisible", "URG​ENT: Dear cus​tomer, your SBI KYC is pen​ding and your acc​ount will be blo​cked today. "
                  "Verify at http://sbi-kyc.xyz/login"),
    ("lookalike_letters", "URGЕNT: Dеar customеr, your SBI KYC is pеnding and your аccount will be blоcked today. "
                          "Verify at http://sbi-kyc.xyz/login"),
    ("styled", "𝐔𝐑𝐆𝐄𝐍𝐓: Dear customer, your 𝐒𝐁𝐈 𝐊𝐘𝐂 is pending and your account will be blocked today. "
               "Verify at http://sbi-kyc.xyz/login"),
    ("digit_swap", "URGENT: Dear customer, your SBI KYC is pending and your acc0unt will be bl0cked today. "
                   "V3rify at http://sbi-kyc.xyz/login"),
    ("disguised_link", "URGENT: Dear customer, your SBI KYC is pending and your account will be blocked today. "
                       "Verify at hxxp://sbi-kyc[.]xyz/login"),
])
def test_disguised_scams_are_still_caught(trick, text):
    plain = analyze(SBI)
    r = analyze(text)
    assert r["verdict"] == plain["verdict"] == "phishing"
    assert "OBFUSCATION" in labels(r)
    assert trick in next(f["text"] for f in r["findings"] if f["label"] == "OBFUSCATION")


def test_highlights_point_at_what_the_user_received():
    text = "Your acc​ount will be blo​cked today, verify at hxxp://sbi-kyc[.]xyz/login"
    r = analyze(text)
    threat = next(f for f in r["findings"] if f["label"] == "THREAT")
    assert text[threat["start"]:threat["end"]] == "acc​ount will be blo​cked"
    link = next(f for f in r["findings"] if f["label"] == "BRAND_IN_DOMAIN")
    assert link["text"] == "http://sbi-kyc.xyz/login"
    assert text[link["start"]:link["end"]].startswith("hxxp://sbi-kyc[.]xyz")


def test_lookalike_letters_in_a_link_still_count_as_impersonation():
    r = analyze("Login at http://раypal.com/secure to restore your account")  # Cyrillic "р" and "а"
    assert labels(r) & {"HOMOGRAPH_DOMAIN", "MIXED_SCRIPT_DOMAIN"}


@pytest.mark.parametrize("text", [
    "H1N1 vaccine update from the w3c team on the 2nd floor",
    "Family dinner tonight 👨‍👩‍👧 see you ❤️",
    "Привет, как дела? Увидимся завтра.",
    "The ﬁnal report is attached, see section x² for details.",
])
def test_ordinary_text_has_no_tricks(text):
    assert fold(text).tricks == {}
    assert "OBFUSCATION" not in labels(analyze(text))


# --- Indian scam types -------------------------------------------------------------------------

@pytest.mark.parametrize("label,text", [
    ("DIGITAL_ARREST", "This is CBI Mumbai. A case is registered against your Aadhaar for money laundering. You are under "
                       "digital arrest. Join the video call now. Call 9876543210"),
    ("DIGITAL_ARREST", "Your Aadhaar number is linked to an illegal parcel containing drugs. Press 1 to talk to the officer."),
    ("TASK_JOB_SCAM", "Part time job! Like YouTube videos and earn Rs 3000 daily. Join t.me/earn_daily_job"),
    ("PARCEL_HOLD", "FedEx: Your parcel is on hold at customs due to illegal items. Contact 9988776655 immediately."),
    ("ELECTRICITY_CUT", "Your electricity connection will be disconnected tonight. Call officer 9876501234"),
    ("LOAN_FEE", "Your instant loan of Rs 5,00,000 is approved without CIBIL check. Pay Rs 999 processing fee now."),
    ("CREDENTIAL_REQUEST_HINGLISH", "Aapka SBI account band ho jayega. Turant OTP bhejo is number par 9876543210"),
    ("PAYMENT_REQUEST_HINGLISH", "Badhai ho! Aapne KBC lottery mein 25 lakh jeete hai. Inaam ke liye Rs 5000 bhejo"),
    ("THREAT_HINDI", "प्रिय ग्राहक, आपका खाता आज बंद हो जाएगा। तुरंत अपना केवाईसी अपडेट करें: http://sbi-kyc.xyz/login"),
    ("CREDENTIAL_REQUEST_HINDI", "आपका लकी ड्रॉ इनाम तैयार है। अपना OTP तुरंत भेजें 9876543210 पर"),
])
def test_indian_scam_types_are_flagged(label, text):
    r = analyze(text)
    assert label in labels(r) and r["verdict"] != "safe"


@pytest.mark.parametrize("text", [
    "SBI kabhi bhi aapse OTP nahi maangta. OTP kisi ko mat bhejo. -SBI",
    "अपना OTP किसी को न बताएं। बैंक कभी OTP नहीं मांगता। -SBI",
    "Delhi Police arrested two men for a cyber fraud racket, the report said.",
    "Your Amazon parcel has been delivered today. Rate your delivery experience in the app.",
    "Your personal loan EMI of Rs 12,400 is due on 5 Nov. Pay via the HDFC Bank app. Ignore if already paid.",
    "दिवाली की हार्दिक शुभकामनाएं! आपका परिवार सुखी रहे।",
])
def test_lookalike_ordinary_messages_stay_safe(text):
    assert analyze(text)["verdict"] == "safe"


# --- shop QR codes with cashback offers ---------------------------------------------------------

SHOP = "upi://pay?pa=sharmastore@okhdfcbank&pn=Sharma%20General%20Store"


def test_shop_cashback_qr_is_not_a_scam():
    r = analyze("Scan and pay with any UPI app. Get 5% cashback on your first payment!", qr=[SHOP])
    assert "QR_PAY_TO_RECEIVE" not in labels(r) and r["verdict"] == "safe"


@pytest.mark.parametrize("text", ["Congratulations! Get your cashback now, scan the QR.",
                                  "Your refund of Rs 5000 is approved. Scan this code."])
def test_money_promising_qr_is_still_a_scam(text):
    assert "QR_PAY_TO_RECEIVE" in labels(analyze(text, qr=["upi://pay?pa=amazon.refund@ybl&pn=Amazon%20Refund"]))
