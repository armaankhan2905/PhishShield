"""Phase 2 detection tests: domains, brands, rules, anomaly checks and scoring.

Messages here are hand-written test fixtures, not an accuracy benchmark.
Accuracy numbers come only from src/eval on held-out data (Phase 3).
Run: python -m pytest tests
"""
import pytest

from src.detection import brands as B
from src.detection import domains as D
from src.detection.fuse import FAILED, RAN, UNAVAILABLE, Context, fuse
from src.detection.rules import Finding, content_findings, url_findings
from src.pipeline.analyze import analyze

# --- domains ------------------------------------------------------------------


@pytest.mark.parametrize("url,registered", [
    ("https://www.onlinesbi.sbi/login", "onlinesbi.sbi"),
    ("sbi.co.in", "sbi.co.in"),
    ("https://sbi.bank.in", "sbi.bank.in"),
    ("https://paypal.com.login.ru/a", "login.ru"),
    ("https://evil.github.io/x", "evil.github.io"),
    ("http://3232235777/", "192.168.1.1"),
])
def test_registered_domain(url, registered):
    assert D.parse_url(url).registered == registered


def test_find_urls_includes_bare_domains_and_skips_emails_and_numbers():
    text = "Visit sbi-kyc.xyz/login or https://amazon.in/a. Mail alert@sbi.co.in, Rs.500.00 at 9 a.m. readme.md"
    assert [u for u, _, _ in D.find_urls(text)] == ["sbi-kyc.xyz/login", "https://amazon.in/a"]


def test_gmail_redirect_is_unwrapped():
    assert D.unwrap_redirect("https://www.google.com/url?q=http://evil.xyz/a&sa=D") == "http://evil.xyz/a"
    assert D.unwrap_redirect("https://example.com/url?q=http://x") == "https://example.com/url?q=http://x"


# --- brands -------------------------------------------------------------------

@pytest.mark.parametrize("url,label", [
    ("https://paypa1.com", "TYPOSQUAT_DOMAIN"),
    ("https://rnicrosoft.com", "TYPOSQUAT_DOMAIN"),
    ("https://amazom.com", "TYPOSQUAT_DOMAIN"),
    ("http://xn--pypal-4ve.com", "HOMOGRAPH_DOMAIN"),
    ("http://sbi-kyc.xyz", "BRAND_IN_DOMAIN"),
    ("https://paypalsecure.com", "BRAND_IN_DOMAIN"),
    ("https://sbi-verify.web.app", "BRAND_IN_DOMAIN"),
    ("https://paypal.com.login.ru", "BRAND_IN_SUBDOMAIN"),
    ("https://amazon.ca", "BRAND_OTHER_TLD"),
])
def test_impersonation_detected(url, label):
    assert B.impersonation(D.parse_url(url))[0] == label


@pytest.mark.parametrize("url", [
    "https://www.onlinesbi.sbi", "https://sbi.bank.in", "https://hdfcbank.com", "https://mail.google.com",
    "https://pineapple.com", "https://appleton.com", "https://window.com", "https://outlookindia.com",
    "https://hdfc.payu.in/pay", "https://sbi.billdesk.com", "https://swiggyinstamart.in", "https://s3.amazonaws.com/x",
])
def test_no_impersonation_for_official_or_unrelated(url):
    assert B.impersonation(D.parse_url(url)) is None


def test_user_content_hosts_are_never_official():
    assert B.official_for(D.parse_url("https://sites.google.com/view/sbi")) == set()
    assert B.official_for(D.parse_url("https://www.google.com")) == {"Google"}


# --- rules ----------------------------------------------------------------------

def labels(findings):
    return {f.label for f in findings}


@pytest.mark.parametrize("text", [
    "Please share the OTP you received to complete verification",
    "Enter your card number and CVV here",
    "Update PAN now",
    "Send me the 6 digit code",
])
def test_credential_requests(text):
    assert "CREDENTIAL_REQUEST" in labels(content_findings(text))


@pytest.mark.parametrize("text", [
    "123456 is your OTP. Do not share it with anyone.",
    "Never share your OTP or PIN with anyone. SBI never asks for it",
    "We will never ask you to share your password",
    "Use code SAVE10 to get 10% off. Enter the code at checkout",
    "Your PAN has been linked successfully.",
])
def test_warnings_and_promos_are_not_requests(text):
    assert "CREDENTIAL_REQUEST" not in labels(content_findings(text))


def test_url_findings_tiers():
    assert {f.tier for f in url_findings("http://192.168.1.5/login")} >= {"confirmed"}
    assert labels(url_findings("javascript:alert(1)")) == {"SCRIPT_URL"}
    assert labels(url_findings("https://bit.ly/x")) == {"SHORTENER"}
    https_only = url_findings("https://example.com/a")
    assert https_only == []  # HTTPS alone adds nothing, and an ordinary domain raises nothing


# --- scoring ----------------------------------------------------------------------

def H(label, w, fam="content"):
    return Finding(label, label.lower(), None, None, "r", "rule", w, None, "heuristic", fam, "body", "low")


def C(label, w, fam="link"):
    return Finding(label, label.lower(), None, None, "r", "rule", w, "impersonation", "confirmed", fam, "body", "high")


COV = {"rules": RAN, "anomaly": RAN, "url_model": UNAVAILABLE, "text_model": UNAVAILABLE}


def test_repeated_heuristic_counts_once():
    once = fuse([H("URGENCY", 10)], COV).score
    many = fuse([H("URGENCY", 10)] * 5, COV).score
    assert once == many == 10


def test_heuristics_alone_never_reach_phishing():
    r = fuse([H(f"H{i}", 20) for i in range(6)] + [H("L1", 20, "link"), H("L2", 20, "link")], COV)
    assert r.verdict != "phishing"
    assert fuse([H(f"H{i}", 20) for i in range(6)], COV, Context(actionable=False)).score <= 30


def test_confirmed_evidence_can_reach_phishing():
    assert fuse([C("BRAND_IN_DOMAIN", 45), C("LINK_TEXT_MISMATCH", 45), H("URGENCY", 10)], COV).verdict == "phishing"


def test_consistent_identity_discounts_heuristics_only():
    base = fuse([H("URGENCY", 10), C("IP_HOST", 35)], COV).score
    disc = fuse([H("URGENCY", 10), C("IP_HOST", 35)], COV, Context(identity_consistent=True)).score
    assert disc == base - 5


def test_ml_alone_cannot_reach_phishing():
    ml = Finding("TEXT_MODEL", "msg", None, None, "r", "text-model", 0, None, "ml", "ml", "body", "high", 0.99)
    assert fuse([ml], COV).verdict != "phishing"
    assert fuse([ml, H("URGENCY", 10)], COV).score > fuse([ml], COV).score


def test_confidence_reflects_coverage():
    assert fuse([], COV).confidence == "low"
    assert fuse([C("IP_HOST", 35)], COV).confidence == "medium"
    full = {k: RAN for k in COV}
    assert fuse([], full).confidence == "high"
    assert fuse([], {**COV, "rules": FAILED}).confidence == "low"


# --- end to end: fixtures --------------------------------------------------------

PHISHING = [
    ("URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz/login", None, []),
    ("Dear user, your PayPal account is restricted. Verify your account at https://paypa1.com/secure", None, []),
    ("Your parcel is held. Pay Rs 25 delivery fee: https://indiapost-delivery.top/pay", None, []),
    ("Please review the document", "Microsoft 365 <alerts@m365-secure-login.xyz>",
     [{"text": "https://office.com/review", "href": "http://m365-review.top/a"}]),
    ("Your HDFC NetBanking is blocked. Login at https://hdfcbank.com.secure-login.info to unlock", None, []),
    ("Amazon: your refund is approved. Claim at http://amaz0n-refund.in/claim", None, []),
]
SUSPICIOUS = [
    "Your account will be blocked. Update PAN at bit.ly/sbi-pan-upd today",
    "Install AnyDesk and share the code so our bank team can help with your refund",
    "Congratulations! You have won Rs 25 lakh in KBC lottery. Pay Rs 5000 processing fee to claim. Call 9876543210",
    "Your electricity connection will be disconnected tonight. Contact our officer 9876543210 immediately",
]
LEGIT = [
    ("123456 is your OTP for txn of Rs 500 at Amazon. Valid 5 mins. Do not share it with anyone -HDFC Bank", None, []),
    ("Rs.500 debited from HDFC Bank A/c **1234 on 12-10-24 to VPA abc@okaxis. Not you? Call 18002586161 -HDFC Bank",
     None, []),
    ("Your Amazon order has shipped. Track it at https://www.amazon.in/gp/your-orders", None, []),
    ("Dear customer, update your KYC within 24 hours using our official website.", None, []),
    ("Your statement is ready", "HDFC Bank <alerts@hdfcbank.net>",
     [{"text": "View statement", "href": "https://www.hdfcbank.com/statement"}]),
    ("Do not share this code with anyone. 482910 is your Swiggy login code", None, []),
    ("Meeting moved to 4pm, see you there 🙂", None, []),
    ("Pay your bill at https://hdfc.payu.in/pay/123 before the due date", None, []),
    ("Your SBI card statement: https://www.sbicard.com/en/personal/statement", None, []),
]


def run(text, sender=None, links=()):
    return analyze(text, email={"from": sender} if sender else None, links=list(links))


@pytest.mark.parametrize("text,sender,links", PHISHING)
def test_phishing_fixtures(text, sender, links):
    r = run(text, sender, links)
    assert r["verdict"] == "phishing", r["findings"]
    assert any(f["tier"] == "confirmed" for f in r["findings"])


@pytest.mark.parametrize("text", SUSPICIOUS)
def test_heuristic_only_scams_are_suspicious(text):
    assert run(text)["verdict"] == "suspicious"


@pytest.mark.parametrize("text,sender,links", LEGIT)
def test_legit_fixtures_are_safe(text, sender, links):
    r = run(text, sender, links)
    assert r["verdict"] == "safe", r["findings"]


def test_missing_models_keep_confidence_down():
    r = run("Meeting moved to 4pm")
    assert r["coverage"]["url_model"] == "unavailable" and r["confidence"] == "low"


def test_every_point_has_a_reason():
    r = run(*PHISHING[0])
    assert all(f["reason"] for f in r["findings"] if f["contribution"] > 0)
    assert abs(sum(f["contribution"] for f in r["findings"]) - r["score"]) <= 1


def test_broken_layer_is_reported_not_hidden(monkeypatch):
    from src.detection import anomaly

    def boom(*a):
        raise RuntimeError("boom")
    monkeypatch.setattr(anomaly, "check_email", boom)
    r = run("hello", "a@b.com")
    assert r["coverage"]["anomaly"] == "failed" and r["partial"] is True and r["confidence"] == "low"
