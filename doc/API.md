# PhishShield API contract · v1.1

Agreed in Phase 1. The web app (Ryan), the extension (Atharva), the detection
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
| `verdict` | `safe` (< 30), `suspicious` (30–69), `phishing` (≥ 70). The safe line was tuned on validation data in Phase 3 (`src/detection/fuse.py`, record in `data/calibration.json`) |
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
| `start`, `end` | Positions in `text` in Python characters (code points). `null` for header and link findings, and for message-level model findings (`TEXT_MODEL`, `field: "body"`) |
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

### Finding labels

| Family | Confirmed | Heuristic |
|---|---|---|
| `link` | `HOMOGRAPH_DOMAIN`, `TYPOSQUAT_DOMAIN`, `BRAND_IN_DOMAIN`, `BRAND_IN_SUBDOMAIN`, `MIXED_SCRIPT_DOMAIN`, `USERINFO_IN_URL`, `IP_HOST`, `SCRIPT_URL`, `LINK_TEXT_MISMATCH`, `REQUEST_TO_UNOFFICIAL_LINK` (`BRAND_OTHER_TLD` on a risky ending) | `BRAND_OTHER_TLD`, `IDN_DOMAIN`, `SHORTENER`, `FREE_HOSTING`, `RISKY_TLD`, `DEEP_SUBDOMAINS`, `NONSTANDARD_PORT`, `NO_HTTPS`, `MALFORMED_URL`, `REQUEST_WITH_LINK`, `BRAND_LINK_UNVERIFIED`, `BRAND_SHORT_LINK` |
| `sender` | `SENDER_BRAND_MISMATCH`, `SENDER_LOOKALIKE`, `DISPLAY_NAME_SPOOF` | `REPLY_TO_MISMATCH` |
| `content` | none (wording alone is never proof) | `CREDENTIAL_REQUEST`, `ACCOUNT_VERIFICATION`, `LOGIN_PROMPT`, `KYC_PENDING`, `PAYMENT_REQUEST`, `REMOTE_ACCESS`, `THREAT`, `MONEY_BAIT`, `URGENCY`, `CALLBACK_REQUEST`, `CLICK_PROMPT`, `GENERIC_GREETING` |
| `ml` | none (a model score is never proof on its own) | tier `ml`, not heuristic: `URL_MODEL` (one per link, `confidence` = probability, listed only above the URL model's floor), `TEXT_MODEL` (whole message, `text` = "(whole message)", listed only above the text model's floor) |

### Rules for every client

1. Highlight only what `findings` returns, at `start_u16`/`end_u16` (or by matching `text` for header and link findings). Never add highlights or reasons of your own.
2. Insert all response strings as text (`textContent`), never as HTML.
3. Show `confidence: low` with a low score as **"Low risk: limited checks"** in grey, not green "Safe".
4. If the request fails or times out, show **"Couldn't check this message"**. Never default to safe.
5. When `mode` is `hosted`, show that the message was sent to the PhishShield server.

## Calling it from the extension

Make the request from the **background service worker**, not the content
script: content scripts on `mail.google.com` are subject to Gmail's origin and
will be blocked by CORS. `extension/manifest.json` has `host_permissions` for
`http://localhost:8000/*` only; another server needs the user's permission
(the options page asks). The server allows `chrome-extension://<id>` origins;
set `PHISHSHIELD_EXTENSION_IDS=<id>[,<id>]` to allow only your published extension.

## `POST /api/analyze/file`

Multipart upload, field `file`. Accepts a saved email (`.eml`), a PDF or a text
file (`.txt`), up to 10 MB. Files are processed in memory and not stored.

- `.eml`: From, Reply-To and Subject are read. An HTML body is reduced to text
  with `<script>`, `<style>` and hidden elements dropped, and every `<a href>`
  becomes a `{text, href}` link. Attachments are listed by name, never opened.
- PDF: text of the first 30 pages (no OCR).

Response: everything `/api/analyze` returns, plus:

| Field | Meaning |
|---|---|
| `file` | `{name, type: "eml"\|"pdf"\|"txt", attachments?, hidden_html_blocks?, pages?, truncated}` |
| `text` | The text that was analysed. Highlight offsets point into this |
| `email` | Headers read from an `.eml`, else `null` |
| `links` | Links extracted from the HTML body |

Errors: `415` wrong type, `413` too large, `400` empty / unreadable, all with a
`detail` message that is safe to show.

## `POST /api/explain`

Same body as `/api/analyze`. Returns a plain-English explanation:

```json
{"explanation": "...", "source": "llm", "model": "llama-3.3-70b-versatile", "detail": "written by an AI model from the findings",
 "ms": 3120, "verdict": "phishing", "score": 100}
```

- **`source: "llm"`:** written by an LLM on Groq from the findings only.
  The model sees the reasons, the domains they name and the **sanitized** message.
  An answer that names another domain, contradicts the verdict, skips the reasons
  or the "What to do" advice, or is too long is rejected.
- **`source: "template"`:** the same text as `/api/analyze`'s `explanation`.
  Used when `GROQ_API_KEY` isn't set or Groq can't be reached, for safe results, or when an answer was rejected. `detail` says why.

The model takes a second or two, which is why it's a separate call: `/api/analyze`
stays fast for the extension.

## Other endpoints

| Endpoint | Use |
|---|---|
| `GET /api/health` | `{"ok": true, "mode": "local"\|"hosted", "models": {"url": state, "text": state}, "explainer": {"available", "model"?, "detail"}}`. Model states: `unloaded` (not loaded yet), `loaded`, `missing`, `disabled`, `error` |
| `GET /api/extension` | `{"version", "download", "store_url"}` for the **Get the extension** page. `store_url` is set from `PHISHSHIELD_EXTENSION_STORE_URL` (Chrome Web Store links only) |
| `GET /download/phishshield-extension.zip` | The extension as a zip with one `phishshield-extension/` folder, ready for *Load unpacked* (test pages excluded) |
| `GET /api/eval` | `data/eval.json` plus the scoring calibration and model metadata, for the Results page |
| `POST /api/sanitize` | Redact personal data from text (PrivacyLens) |

Removed in Phase 5 (PrivacyLens features outside PhishShield's scope):
`/api/document`, `/api/rag*`, `/api/pipeline`, and the `/ask` and `/training` pages
(old page URLs redirect to the new pages).
