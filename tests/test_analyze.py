"""Contract tests for POST /api/analyze (doc/API.md). Run: python -m pytest tests"""
from fastapi.testclient import TestClient

from src.pipeline.demo import app

client = TestClient(app)

FIELDS = {"score", "verdict", "category", "kind", "findings", "urls", "explanation",
          "sanitized", "partial", "stub", "latency_ms"}
FINDING_FIELDS = {"label", "text", "start", "end", "reason", "source", "weight", "category"}


def post(**body):
    return client.post("/api/analyze", json=body)


def test_response_matches_contract():
    r = post(text="URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz/login")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == FIELDS
    assert 0 <= body["score"] <= 100
    assert body["verdict"] in {"safe", "suspicious", "phishing"}
    for f in body["findings"]:
        assert set(f) == FINDING_FIELDS
        if f["start"] is not None:
            assert body_text_slice(f) == f["text"]
    assert body["urls"][0]["url"] == "http://sbi-kyc.xyz/login"


def body_text_slice(f):
    text = "URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz/login"
    return text[f["start"]:f["end"]]


def test_phishing_sms_is_flagged_and_legit_is_safe():
    assert post(text="URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz/login").json()["verdict"] != "safe"
    assert post(text="Hi, reaching home by 7. Dinner?").json()["verdict"] == "safe"


def test_kind_detection():
    assert post(text="http://192.168.1.5/login").json()["kind"] == "url"
    assert post(text="hello there").json()["kind"] == "sms"
    assert post(text="hi", email={"from": "a@b.com"}).json()["kind"] == "email"


def test_links_only_and_dedupe():
    body = post(links=[{"text": "SBI", "href": "http://x.xyz/a"}, {"text": "again", "href": "http://x.xyz/a"}]).json()
    assert [u["url"] for u in body["urls"]] == ["http://x.xyz/a"]


def test_empty_request_rejected():
    assert post(text="   ").status_code == 422
    assert post(text="x", kind="fax").status_code == 422


def test_sanitized_hides_personal_data():
    assert "9876543210" not in post(text="Call 9876543210 now to claim your prize").json()["sanitized"]


def test_cors_allows_extension_only():
    origin = "chrome-extension://" + "a" * 32
    r = client.options("/api/analyze", headers={"Origin": origin, "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") == origin
    r = client.options("/api/analyze", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in r.headers
