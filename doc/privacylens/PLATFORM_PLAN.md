# PrivacyLens — Platform Plan (doc/PLATFORM_PLAN.md)

## 1. Goal
A local-first, privacy-preserving AI agent that intercepts a webpage / form / interface,
detects and sanitizes sensitive PII/PCI before it leaves the device, and lets an AI reason
over the sanitized view. Buildable by 4 people in ~9 hours with a strong measurable demo.

## 2. Data sources (fixed)
| Source | Role | Notes |
|---|---|---|
| DLPEP sample-data (dlptest.com) | Training + eval corpus | Name+SSN+CCN, SSN+DOB, etc. Synthetic PII/PCI |
| Faker | Generate phone / OTP / generic PII | Fill gaps in dlptest |
| bigcode/starpii | Optional NER fallback (code-domain PII) | Gated access; optional |
| amazon-science/fraud-dataset-benchmark | Context only | Card-fraud context, NOT raw-card training data |

## 3. Architecture
```
Client/Agent input
   ├─ DOM + form fields  (+ screenshot)
   ├─ Detection Layer
   │    ├─ Pattern Layer (regex): cards(Luhn), phones, PAN, emails, IPs, URLs
   │    ├─ DOM Structural Layer (type/name field labels)
   │    └─ Local Classifier (NER / sequence labeler) over content text
   ├─ Sanitizer → mask / placeholder [REDACTED:{TYPE}]
   ├─ Local LLM/VLM reasoning over sanitized data
   │    └─ Action validation; reject invalid/unsafe targets; user approval for sensitive ops
   ├─ Canary audit (leakage == 0)
   └─ eval (recall / precision / leakage rate / task-success / latency)
```

## 4. Build order (with gates)
1. **Detection API + eval corpus** (A, with B) → by 12:00
2. **Local classifier** fine-tuned + quantized (B) → by 16:00
3. **Sanitization + reasoning pipeline + UI** (C) → by 21:00
4. **Canary + eval + demo video + README** (D) → by 01:00

## 5. Model sizing (12GB VRAM hard cap)
- **Recommended**: ≤ 600M params, or a quantized 1–4B model.
- **Fallback**: token-classification NER prototype; or a small encoder (e.g., DeBERTa-v3-base) on top of a frozen LLM for content tagging.
- **Training**: 3–6 epochs, small LR, gradient accumulation; keep labels IOB2; eval on held-out.

## 6. Test corpus format
```jsonl
{"text": "My card is 4111111111111111, phone 9876543210, otp 123456.", "labels": [O, O, ..., B-CARD, ..., B-PHONE, ..., B-OTP, ...]}
```
Use IOB2 tagging with types: `CARD`, `PHONE`, `PAN`, `EMAIL`, `IP`, `URL`, `OTP`, `PERSON`, `ENTITY`.

## 7. Canary + security
- Canary: low-drama fake values (`fake_card_XXXX`, `fake_phone_XXXX`) injected into test pages.
- `leakage == 0` on every dev build. Fail-closed on any detection/sanitization failure.
- Input validation: cap batch size, reject private/local IPs, salted-hash any IP, short expiry.
- Readme threat model: what you defend against, what you accept.

## 8. Demo
- Live UI: capture a URL / paste a page → detect → redact → sanitized reasoning.
- 2–3 min video: same pipeline, well-produced.
- Sprint demo: end-to-end, numbers on screen.
