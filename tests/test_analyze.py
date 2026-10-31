"""Contract tests for POST /api/analyze (doc/API.md v1.1). Run: python -m pytest tests"""
from fastapi.testclient import TestClient

from src.pipeline.demo import app

client = TestClient(app)

SBI = "URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz/login"
FIELDS = {"analysis_id", "score", "verdict", "confidence", "category", "kind", "findings", "urls", "coverage",
          "explanation", "explanation_source", "sanitized", "partial", "stub", "mode", "latency_ms"}
FINDING_FIELDS = {"id", "label", "text", "start", "end", "start_u16", "end_u16", "reason", "source", "tier",
                  "family", "field", "severity", "weight", "contribution", "confidence", "category"}
LAYERS = {"rules", "anomaly", "url_model", "text_model"}


def post(**body):
    return client.post("/api/analyze", json=body)


def test_response_matches_contract():
    r = post(text=SBI)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == FIELDS
    assert 0 <= body["score"] <= 100
    assert body["verdict"] in {"safe", "suspicious", "phishing"}
    assert body["confidence"] in {"high", "medium", "low"}
    assert body["mode"] in {"local", "hosted"}
    assert set(body["coverage"]) == LAYERS
    assert set(body["coverage"].values()) <= {"ran", "unavailable", "failed", "stub"}
    assert body["urls"][0]["url"] == "http://sbi-kyc.xyz/login"
    for f in body["findings"]:
        assert set(f) == FINDING_FIELDS
        assert f["tier"] in {"confirmed", "heuristic", "ml"}
        assert f["family"] in {"sender", "link", "content", "ml"}
        assert f["field"] in {"body", "subject", "from", "reply_to", "link"}
        assert f["severity"] in {"low", "medium", "high"}


def test_findings_point_into_the_original_text():
    body = post(text=SBI).json()
    ids = [f["id"] for f in body["findings"]]
    assert len(ids) == len(set(ids))
    for f in body["findings"]:
        if f["start"] is not None:
            assert f["field"] == "body" and SBI[f["start"]:f["end"]] == f["text"]
        else:  # header / link findings, and message-level model findings
            assert f["end"] is None and (f["field"] != "body" or f["tier"] == "ml")


def test_utf16_offsets_survive_emoji():
    text = "🎁🎁 You won a prize! claim at http://win.xyz/claim"
    body = post(text=text).json()
    utf16 = text.encode("utf-16-le")
    assert body["findings"]
    for f in body["findings"]:
        if f["start"] is not None:
            assert f["start_u16"] == f["start"] + 2  # each emoji is 2 UTF-16 units
            assert utf16[2 * f["start_u16"]:2 * f["end_u16"]].decode("utf-16-le") == f["text"]


def test_score_is_sum_of_contributions():
    for text in (SBI, "Claim your refund now at http://192.168.1.5/login", "hello"):
        body = post(text=text).json()
        assert abs(sum(f["contribution"] for f in body["findings"]) - body["score"]) <= 1


def test_missing_layers_never_give_confident_results():
    body = post(text="Hi, reaching home by 7. Dinner?").json()
    assert body["verdict"] == "safe"
    assert "unavailable" in body["coverage"].values() or "stub" in body["coverage"].values()
    assert body["confidence"] == "low"
    assert "caution" in body["explanation"]


def test_phishing_sms_is_flagged_and_legit_is_safe():
    assert post(text=SBI).json()["verdict"] != "safe"
    assert post(text="Hi, reaching home by 7. Dinner?").json()["verdict"] == "safe"


def test_kind_detection():
    assert post(text="http://192.168.1.5/login").json()["kind"] == "url"
    assert post(text="hello there").json()["kind"] == "sms"
    assert post(text="hi", email={"from": "a@b.com"}).json()["kind"] == "email"


def test_links_only_and_dedupe():
    body = post(links=[{"text": "SBI", "href": "http://x.xyz/a"}, {"text": "again", "href": "http://x.xyz/a"}]).json()
    assert [u["url"] for u in body["urls"]] == ["http://x.xyz/a"]
    assert all(f["field"] == "link" for f in body["findings"])


def test_empty_request_rejected():
    assert post(text="   ").status_code == 422
    assert post(text="x", kind="fax").status_code == 422


def test_sanitized_is_a_copy_and_hides_personal_data():
    text = "Call 9876543210 now to claim your prize"
    body = post(text=text).json()
    assert "9876543210" not in body["sanitized"]
    money = [f for f in body["findings"] if f["label"] == "MONEY_BAIT"]
    assert money and all(text[f["start"]:f["end"]] == f["text"] for f in money)


def test_mode_follows_env(monkeypatch):
    monkeypatch.setenv("PHISHSHIELD_MODE", "hosted")
    assert post(text="hello").json()["mode"] == "hosted"
    monkeypatch.setenv("PHISHSHIELD_MODE", "nonsense")
    assert post(text="hello").json()["mode"] == "local"


def test_analysis_ids_are_unique():
    assert post(text="hello").json()["analysis_id"] != post(text="hello").json()["analysis_id"]


def test_cors_allows_extension_only():
    origin = "chrome-extension://" + "a" * 32
    r = client.options("/api/analyze", headers={"Origin": origin, "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") == origin
    r = client.options("/api/analyze", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in r.headers
