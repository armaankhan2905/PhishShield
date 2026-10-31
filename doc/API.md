# PhishShield API contract · v1.1

Agreed in Phase 1. The web app (Ryan), the extension (Atharvva), the detection
layer (Armaan) and the models (Govind) all build against this. Change it only
by telling the whole team and updating this file in the same commit.

v1.1 adds evidence tiers, coverage, confidence, mode and JavaScript offsets.
Every v1.0 field is still present.

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
| `text` | string, ≤ 20,000 chars | yes, unless `links` is non-empty | Message body as plain text, SMS text, or a single URL. Send the original text; never pre-redact it |
| `kind` | `auto` \| `email` \| `sms` \| `url` | no, default `auto` | `auto`: `email` if `email` is sent, `url` if `text` is one URL, else `sms` |
| `email` | object | no | Headers from Gmail or an `.eml` file: `from`, `reply_to`, `subject` |
| `links` | array of `{text, href}`, ≤ 500 | no | Links as shown on the page: visible text and real target. Unwrap Gmail's `google.com/url?q=` wrapper first |

`422` when both `text` and `links` are empty, or a field breaks a limit.

### Response

```json
{
  "analysis_id": "3f9c0e5b0a6d4c2e9a51f0c7d2b8e114",
  "score": 87,
  "verdict": "phishing",
  "confidence": "high",
  "category": "impersonation",
  "kind": "email",
  "findings": [
    {
      "id": "f1",
      "label": "CREDENTIAL_REQUEST",
      "text": "Verify",
      "start": 40, "end": 46,
      "start_u16": 40, "end_u16": 46,
      "reason": "Asks you to verify your account",
      "source": "rule",
      "tier": "heuristic",
      "family": "content",
      "field": "body",
      "severity": "medium",
      "weight": 15,
      "contribution": 9.0,
      "confidence": null,
      "category": "credential_harvesting"
    },
    {
      "id": "f2",
      "label": "BRAND_DOMAIN_MISMATCH",
      "text": "SBI Alerts <alert@sbi-kyc.xyz>",
      "start": null, "end": null,
      "start_u16": null, "end_u16": null,
      "reason": "Claims to be SBI but sends from sbi-kyc.xyz, which is not an SBI domain",
      "source": "anomaly",
      "tier": "confirmed",
      "family": "sender",
      "field": "from",
      "severity": "high",
      "weight": 45,
      "contribution": 41.5,
      "confidence": null,
      "category": "impersonation"
    }
  ],
  "urls": [
    {"url": "http://sbi-kyc.xyz/login", "score": 0.94, "flags": ["no_https", "risky_tld"]}
  ],
  "coverage": {"rules": "ran", "anomaly": "ran", "url_model": "ran", "text_model": "ran"},
  "explanation": "Rated phishing (87/100). Main reasons: ...",
  "explanation_source": "template",
  "sanitized": "Dear customer, your SBI KYC is pending. Verify within 24 hours at [REDACTED:URL]",
  "partial": false,
  "stub": false,
  "mode": "local",
  "latency_ms": 42.1
}
```

(Example values are illustrative, not measured.)

### Top-level fields

| Field | Meaning |
|---|---|
| `analysis_id` | Random id for this result. Feedback refers to it; it is not derived from the message |
| `score` | 0–100, higher = more likely phishing. Equals the sum of finding `contribution`s (±1 for rounding) |
| `verdict` | `safe` (< 35), `suspicious` (35–69), `phishing` (≥ 70). **Provisional thresholds**, calibrated in Phase 3 (`src/detection/fuse.py`) |
| `confidence` | `high`: every detection layer ran. `medium`: a layer is missing but a confirmed finding stands on its own. `low`: anything else |
| `category` | `impersonation`, `urgency`, `credential_harvesting`, `suspicious_link`, `financial_scam`, or `null` when nothing was found |
| `kind` | The kind actually used (resolved from `auto`) |
| `findings[]` | All evidence, sorted by position (header and link findings last). **The only source of highlights and reasons** |
| `urls[]` | Every URL from `text` and `links`, de-duplicated, at most 50. `score` is the URL model's probability (0–1), `null` when the model didn't run |
| `coverage` | State of each detection layer: `ran`, `unavailable` (not built or not loaded), `failed` (crashed this request), `stub` (Phase 1 stand-in) |
| `explanation` | Plain-English summary written only from the findings |
| `explanation_source` | `template` or `llm` |
| `sanitized` | A *copy* of `text` with personal data replaced by `[REDACTED:TYPE]`. `null` if sanitization failed |
| `partial` | `true` when a layer failed or sanitization failed |
| `stub` | `true` while the rules engine isn't ready. Reasons then start with `[stub]`; never show them in the final demo |
| `mode` | `local` (server on the user's machine) or `hosted` (message was sent to a remote server; the UI must say so). Set by `PHISHSHIELD_MODE` |
| `latency_ms` | Server-side time for this request |

### Evidence: finding fields

| Field | Meaning |
|---|---|
| `id` | `f1`, `f2`, … unique within one response |
| `label` | Machine name, e.g. `LOOKALIKE_DOMAIN`, `URGENCY`, `URL_MODEL` |
| `text` | The exact evidence: a substring of `text` when `field` is `body`, otherwise the header value or URL |
| `start`, `end` | Positions in `text` in Python characters (code points). `null` unless `field` is `body` |
| `start_u16`, `end_u16` | The same positions in UTF-16 units. **JavaScript must use these** (`text.slice(start_u16, end_u16)`); they differ when the text has emoji |
| `reason` | One sentence stating what was detected. No guesses beyond the evidence |
| `source` | `rule`, `anomaly`, `url-model`, `text-model` |
| `tier` | `confirmed`: a verifiable technical fact (lookalike domain, link text ≠ real link, brand claimed from a non-brand domain). `heuristic`: often but not always phishing (urgency, shortener, risky TLD). `ml`: a model prediction |
| `family` | `sender`, `link`, `content`, `ml`: independent sources of evidence. Phishing should be backed by more than one family or by a confirmed finding |
| `field` | Where the evidence is: `body`, `subject`, `from`, `reply_to`, `link` |
| `severity` | `low`, `medium`, `high` |
| `weight` | Points this finding asked for before caps |
| `contribution` | Points this finding actually added to `score` |
| `confidence` | Model probability for `ml` findings; `null` for rules |
| `category` | As above, or `null` |

### Finding labels (Phase 2)

| Family | Confirmed | Heuristic |
|---|---|---|
| `link` | `HOMOGRAPH_DOMAIN`, `TYPOSQUAT_DOMAIN`, `BRAND_IN_DOMAIN`, `BRAND_IN_SUBDOMAIN`, `MIXED_SCRIPT_DOMAIN`, `USERINFO_IN_URL`, `IP_HOST`, `SCRIPT_URL`, `LINK_TEXT_MISMATCH`, `REQUEST_TO_UNOFFICIAL_LINK` (`BRAND_OTHER_TLD` on a risky ending) | `BRAND_OTHER_TLD`, `IDN_DOMAIN`, `SHORTENER`, `FREE_HOSTING`, `RISKY_TLD`, `DEEP_SUBDOMAINS`, `NONSTANDARD_PORT`, `NO_HTTPS`, `MALFORMED_URL`, `REQUEST_WITH_LINK`, `BRAND_LINK_UNVERIFIED`, `BRAND_SHORT_LINK` |
| `sender` | `SENDER_BRAND_MISMATCH`, `SENDER_LOOKALIKE`, `DISPLAY_NAME_SPOOF` | `REPLY_TO_MISMATCH` |
| `content` | none (wording alone is never proof) | `CREDENTIAL_REQUEST`, `ACCOUNT_VERIFICATION`, `LOGIN_PROMPT`, `KYC_PENDING`, `PAYMENT_REQUEST`, `REMOTE_ACCESS`, `THREAT`, `MONEY_BAIT`, `URGENCY`, `CALLBACK_REQUEST`, `CLICK_PROMPT`, `GENERIC_GREETING` |

### Rules for every client

1. Highlight only what `findings` returns, at `start_u16`/`end_u16` (or by matching `text` for header and link findings). Never add highlights or reasons of your own.
2. Insert all response strings as text (`textContent`), never as HTML.
3. Show `confidence: low` with a low score as **"Low risk: limited checks"** in grey, not green "Safe".
4. If the request fails or times out, show **"Couldn't check this message"**. Never default to safe.
5. When `mode` is `hosted`, show that the message was sent to the PhishShield server.

## Calling it from the extension

Make the request from the **background service worker**, not the content
script: content scripts on `mail.google.com` are subject to Gmail's origin and
will be blocked by CORS. Add `"host_permissions": ["http://localhost:8000/*"]`
(and the hosted URL only if the user opts in) to `manifest.json`. The server
allows `chrome-extension://<id>` origins.

## Other endpoints kept from PrivacyLens

| Endpoint | Use |
|---|---|
| `GET /api/health` | `{"ok": true}`, for the extension's "server offline" check |
| `POST /api/sanitize` | Redact personal data from text |
| `POST /api/document` | PDF upload → sanitized pages (may be reused for uploads) |
| `GET /api/pipeline` | Data for the pipeline / training / evaluation pages (reworked later) |

The PrivacyLens document Q&A endpoints (`/api/rag*`, `/ask`) are out of scope
for PhishShield and are planned to be hidden before the hosted demo.
