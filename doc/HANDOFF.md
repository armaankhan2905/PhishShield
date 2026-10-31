# Handoff log

Each lead adds a section when passing the baton. The next lead runs the
acceptance test themselves, then posts "baton taken" in the team chat.

---

## P1 Foundation → P2 Core detection

**From:** Ryan · **To:** Armaan

### What works
- The project is cleaned and renamed to PhishShield, with fresh git history. PrivacyLens's PII model, canary test, KYC sample PDFs and old Flask server are removed.
- `python -m src.pipeline.demo` serves the web app at http://localhost:8000; every page and `/api/health` return 200.
- `POST /api/analyze` follows [API.md](API.md) **v1.1**:
  - evidence `tier` / `family` / `field` on every finding;
  - `contribution` per finding (they add up to `score`);
  - `coverage` per layer and overall `confidence`;
  - `mode` (`local` / `hosted` from `PHISHSHIELD_MODE`);
  - JavaScript-safe offsets `start_u16` / `end_u16`;
  - `analysis_id`.
- A layer that didn't run shows up in `coverage` and gives `confidence: low`. The explanation then says to treat the result with caution. Missing checks never produce a confident "safe".
- Extension origins (`chrome-extension://<id>`) are allowed by CORS.
- Until `rules.READY` is `True`, findings come from `src/pipeline/stub.py`. These are keyword and URL stand-ins marked `[stub]`, with coverage `stub`.
- `sanitized` is a real, separate copy: PrivacyLens's `sanitize()` redacts phone numbers, cards, emails and similar. The original text is never modified, and findings point into it.
- `python -m pytest tests` runs 13 contract tests. All pass.

### Acceptance check run at handover (live server)
- SBI KYC email with headers and links → `phishing` 70, `confidence: low`, coverage shows the stub and unavailable layers, 4 findings with contributions adding up to 70.
- `/`, `/pipeline`, `/training`, `/evaluation`, `/ask`, `/api/health`, `/api/pipeline` → 200. Empty input → 422.

### Your files to fill (signatures are fixed; the API already calls them)
| File | Function | Returns |
|---|---|---|
| `src/detection/rules.py` | `analyze_rules(text)` | `List[Finding]`, `field="body"`, spans into `text` |
| `src/detection/rules.py` | `analyze_url(url)` | list of flag names, e.g. `["ip_host", "risky_tld"]` |
| `src/detection/anomaly.py` | `check_email(email, links)` | `List[Finding]`, `source="anomaly"`, `field` = `from` / `reply_to` / `link`, `start`/`end` = `None` |
| `src/detection/fuse.py` | `fuse(findings, coverage)` | **Provisional** 35/30/35 baseline. Replace it with evidence-gated scoring (revised plan §5). The return shape stays the same |

For every `Finding`, set:
- `tier`: `confirmed` only for verifiable technical facts, otherwise `heuristic`;
- `family`: `sender` / `link` / `content`;
- `severity`;
- a `reason` that states only what was detected.

Reuse `URL_RX`, `EMAIL_RX`, `PHONE_RX`, `OTP_RX` from `src/detection/main.py`.

### When you're done
1. Set `READY = True` in `rules.py`. Coverage becomes `ran` for `rules` and `anomaly`, and `"stub"` becomes `false`.
2. While `READY` is `True`, `url_model` / `text_model` stay `unavailable` until Govind's models go in, so confidence stays `low` unless a confirmed finding exists.
3. Delete `src/pipeline/stub.py` and the stub branch in `src/pipeline/analyze.py` (or ask Ryan to).

### Acceptance test for your handover to Govind (revised plan §10)
- `python -m pytest tests` passes, plus your new unit tests (legitimate and malicious examples, including hard negatives).
- Every phishing demo sample has at least one finding with a correct reason.
- Legitimate banking and OTP alerts (e.g. "… is your OTP. Do not share it with anyone.") are not rated phishing.
- Messages with only generic urgency stay below phishing.
- With the model layers unavailable, `confidence` is `low`, never a confident "safe".
- An emoji message gives correct `start_u16` / `end_u16`.

### Not done in P1 (side tasks, owners unchanged)
- Armaan: rule list and brand list (official registered domains per brand).
- Govind: dataset downloads and environment setup.
- Atharvva: 20 demo samples (`data/demo_samples.json`), extension skeleton, test Gmail inbox.
- Everyone: start collecting redacted legitimate banking or service messages for the false-positive test set.

### Known gaps / notes
- `sanitize()` also redacts URLs. When the LLM explanation is added, pass registered domains from the findings separately (no paths or query strings).
- `src/detection/ensemble.py` is old PrivacyLens code with hard-coded model paths. Nothing imports it. Delete it if it gets in the way.
- The web pages are still PrivacyLens's PII demo, rebranded. The PhishShield result screen is Ryan's side task in P2. It must follow the client rules in API.md: highlights only from findings, text inserted as text, grey "limited checks" state.
- `render.yaml` sets `PHISHSHIELD_MODE=hosted`. `requirements-demo.txt` still needs the model libraries before a hosted deploy (P5).
- The old PrivacyLens git history is in `../PrivacyLens-git-backup`, outside this repo, because it contains 2.3 GB of model files.
