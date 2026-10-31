# PhishShield API contract

Agreed in Phase 1. The web app (Ryan), the extension (Atharvva), the detection
layer (Armaan) and the models (Govind) all build against this. Change it only
by telling the whole team and updating this file in the same commit.

Base URL: `http://localhost:8000` locally (`python -m src.pipeline.demo`).

## `POST /api/analyze`

### Request

```json
{
  "text": "Dear customer, your SBI KYC is pending. Verify within 24 hours at http://sbi-kyc.xyz/login",
  "kind": "auto",
  "email": {
    "from": "SBI Alerts <alert@sbi-kyc.xyz>",
    "reply_to": "help@gmail.com",
    "subject": "Account blocked"
  },
  "links": [
    {"text": "onlinesbi.sbi", "href": "http://sbi-kyc.xyz/login"}
  ]
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `text` | string, ≤ 20,000 chars | yes, unless `links` is non-empty | Message body, SMS text, or a single URL |
| `kind` | `auto` \| `email` \| `sms` \| `url` | no, default `auto` | `auto`: `email` if `email` is sent, `url` if `text` is one URL, else `sms` |
| `email` | object | no | Headers from Gmail or an `.eml` file: `from`, `reply_to`, `subject` |
| `links` | array of `{text, href}`, ≤ 500 | no | Links as shown on the page: visible text and real target |

`422` when both `text` and `links` are empty, or a field breaks a limit.

### Response

```json
{
  "score": 87,
  "verdict": "phishing",
  "category": "credential_harvesting",
  "kind": "email",
  "findings": [
    {
      "label": "CREDENTIAL_REQUEST",
      "text": "Verify",
      "start": 40,
      "end": 46,
      "reason": "Asks for login details or account verification",
      "source": "rule",
      "weight": 25,
      "category": "credential_harvesting"
    },
    {
      "label": "SENDER_MISMATCH",
      "text": "SBI Alerts <alert@sbi-kyc.xyz>",
      "start": null,
      "end": null,
      "reason": "Claims to be SBI but sends from sbi-kyc.xyz",
      "source": "anomaly",
      "weight": 30,
      "category": "impersonation"
    }
  ],
  "urls": [
    {"url": "http://sbi-kyc.xyz/login", "score": 0.94, "flags": ["no_https", "risky_tld"]}
  ],
  "explanation": "Rated phishing (87/100). Main reasons: ...",
  "sanitized": "Dear customer, your SBI KYC is pending. Verify within 24 hours at [REDACTED:URL]",
  "partial": false,
  "stub": false,
  "latency_ms": 42.1
}
```

| Field | Meaning |
|---|---|
| `score` | 0–100, higher = more likely phishing |
| `verdict` | `safe` (< 35), `suspicious` (35–69), `phishing` (≥ 70). Thresholds live in `src/detection/fuse.py` |
| `category` | `impersonation`, `urgency`, `credential_harvesting`, `suspicious_link`, `financial_scam`, or `null` when nothing was found |
| `kind` | The kind actually used (resolved from `auto`) |
| `findings[]` | Sorted by position. `start`/`end` index into `text`; both are `null` for header or link findings |
| `findings[].source` | `rule`, `url-model`, `text-model` or `anomaly` |
| `urls[]` | Every URL from `text` and `links`, de-duplicated, at most 50. `score` is the URL model's probability (0–1), `null` until the model is loaded |
| `explanation` | Plain-English summary. Template text now; local LLM from Phase 3 |
| `sanitized` | `text` with personal data replaced by `[REDACTED:TYPE]`. `null` if sanitization failed |
| `partial` | `true` when a layer failed and the result is incomplete |
| `stub` | `true` while the rules engine isn't ready. Reasons then start with `[stub]` and must not be shown in the final demo |
| `latency_ms` | Server-side time for this request |

## Calling it from the extension

Make the request from the **background service worker**, not the content
script: content scripts on `mail.google.com` are subject to Gmail's origin and
will be blocked by CORS. Add `"host_permissions": ["http://localhost:8000/*"]`
(and the deployed URL later) to `manifest.json`. The server allows
`chrome-extension://<id>` origins.

## Other endpoints kept from PrivacyLens

| Endpoint | Use |
|---|---|
| `GET /api/health` | `{"ok": true}`, for the extension's "server offline" check |
| `POST /api/sanitize` | Redact personal data from text |
| `POST /api/document` | PDF upload → sanitized pages (Phase 3 reuses this for uploads) |
| `GET /api/pipeline` | Data for the pipeline / training / evaluation pages (reworked in Phase 4) |
