# Handoff log

Each lead adds a section when passing the baton. The next lead runs the
acceptance test themselves, then posts "baton taken" in the team chat.

---

## P1 Foundation → P2 Detection engine

**From:** Ryan · **To:** Armaan

### What works
- The project is cleaned and renamed to PhishShield, with fresh git history. PrivacyLens's PII model, canary test, KYC sample PDFs and old Flask server are removed.
- `python -m src.pipeline.demo` serves the web app at http://localhost:8000; every page and `/api/health` return 200.
- `POST /api/analyze` follows [API.md](API.md) exactly. Extension origins (`chrome-extension://<id>`) are allowed by CORS.
- Until `rules.READY` is `True`, findings come from `src/pipeline/stub.py`, a few keywords and URL checks marked `[stub]`, so the web app and the extension get realistic data now.
- `sanitized` is real: PrivacyLens's `sanitize()` redacts phone numbers, cards, emails and similar.
- `python -m pytest tests` runs 7 contract tests. All pass.

### Your files to fill (signatures are fixed, the API already calls them)
| File | Function | Returns |
|---|---|---|
| `src/detection/rules.py` | `analyze_rules(text)` | `List[Finding]` with spans into `text` |
| `src/detection/rules.py` | `analyze_url(url)` | list of flag names, e.g. `["ip_host", "risky_tld"]` |
| `src/detection/anomaly.py` | `check_email(email, links)` | `List[Finding]`, `source="anomaly"`, `start`/`end` = `None` |
| `src/detection/fuse.py` | `fuse(findings, url_scores, text_score)` | already works: rules score = sum of weights, capped at 100, missing layers skipped. Tune it |

Reuse `URL_RX`, `EMAIL_RX`, `PHONE_RX`, `OTP_RX` from `src/detection/main.py`.

### When you're done
1. Set `READY = True` in `rules.py`. The API stops using the stub and `"stub"` becomes `false`.
2. While `READY` is `True`, `urls[].score` stays `null` until Govind's URL model goes in.
3. Delete `src/pipeline/stub.py` and its import in `src/pipeline/analyze.py` (or ask Ryan to).

### Acceptance test for your handover to Govind
- The fake "SBI KYC update" SMS turns red in the web app with correct reasons.
- All 10 legitimate demo samples score under 35.
- `python -m pytest tests` still passes.

### Known gaps / notes
- `sanitize()` also redacts URLs. That's fine for privacy, but the Phase 3 LLM explanation will need the domain names. Ryan will pass the domains separately.
- `src/detection/ensemble.py` is old PrivacyLens code with hard-coded model paths. Nothing imports it. Delete it if it gets in the way.
- The web pages are still PrivacyLens's PII demo, rebranded. Ryan redoes `index.html` as a side task in P2.
- Old PrivacyLens git history was moved to `../PrivacyLens-git-backup` (outside this repo) because it contains 2.3 GB of model files.
