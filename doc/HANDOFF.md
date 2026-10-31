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

---

## P2 Core detection → P3 Machine learning

**From:** Armaan · **To:** Govind

### What works
- The stub is gone: `rules.READY = True`, and responses say `"stub": false` with coverage `rules: ran`, `anomaly: ran`.
- **Domains** (`src/detection/domains.py`):
  - registered domains from tldextract's bundled Public Suffix List, offline only;
  - `bank.in` treated as a suffix; private suffixes such as `github.io` and `web.app` count as separate sites;
  - IDN/punycode decoding and IP hosts, including the `3232235777` and `0xC0A80001` forms;
  - bare domains in SMS text (`sbi-kyc.xyz/login`);
  - Gmail `google.com/url?q=` unwrapping;
  - URLs are only parsed, never fetched.
- **Brand registry** (`src/detection/brands.py`): 36 brands with their aliases, name tokens and official domains, plus the `.sbi` brand TLD and `<bank>.bank.in`. Impersonation checks:
  - homograph and typosquat domains, aimed only at labels that carry a brand name;
  - brand name plus a phishing word (`paypalsecure`, `sbi-kyc`, `amaz0n-refund`);
  - brand in a subdomain (payment gateways such as `payu.in` and `billdesk.com` are exempt);
  - brand name on another ending (`amazon.ca`) is only a heuristic unless the ending is risky.
- **Rules** (`src/detection/rules.py`):
  - content rules detect *requests* and skip warnings ("never share your OTP");
  - URL rules (see the label table in API.md);
  - `correlate()` turns "asks for details + names a brand + link to a domain that brand doesn't own" into a confirmed finding.
- **Anomaly checks** (`src/detection/anomaly.py`): display name vs sender domain (including free mail), sender look-alike, an email address shown in the display name, Reply-To mismatch, link text vs real link.
- **Engine** (`src/detection/engine.py`): runs each layer in isolation. A crash shows up as `failed` in coverage plus `partial: true`.
- **Evidence-gated scoring** (`src/detection/fuse.py`):
  - confirmed findings count in full;
  - heuristics count once per label and are capped per family;
  - "phishing" needs a confirmed finding, or a confident model backed by another family;
  - heuristics alone stop at 60, or at 30 when there's nothing to act on;
  - heuristics are halved when every link and the sender belong to the brand named;
  - every value is a named, **provisional** constant.
- 81 tests pass (`python -m pytest tests`).

### Acceptance check run at handover (live server)
- SBI KYC email with headers and links → phishing 100, `confidence: medium`, 5 confirmed findings (brand in domain, request to unofficial link, sender mismatch, sender look-alike, link text mismatch).
- "Dear customer, update your KYC within 24 hours using our official website." → safe 30 ("nothing to act on").
- HDFC OTP alert with emoji → safe 0.
- `/` and `/api/health` → 200.

### Results on the hand-written fixtures in `tests/test_detection.py`
These are unit-test fixtures, **not an accuracy measurement**.
- 6 of 6 phishing fixtures → phishing, each with a confirmed finding.
- 4 of 4 heuristic-only scams (lottery fee, electricity cut, AnyDesk, PAN short link) → suspicious.
- 9 of 9 legitimate fixtures (OTP alerts, debit alert, Amazon shipping, KYC reminder, HDFC statement email, Swiggy code, PayU bank payment, SBI Card link) → safe.

### Your plug-in point (Phase 3)
- Add the models as layers in `src/detection/engine.py` `run()`.
  - Return `Finding(..., source="url-model" | "text-model", tier="ml", family="ml", confidence=p, weight=0)`.
  - Use one finding per URL (located with the URL's span or `field="link"`) and one per message (`field="body"`, `start`/`end` `None`).
  - Set `coverage["url_model"]` / `coverage["text_model"]` to `"ran"` (or `"failed"`).
  - Put `urls[].score` from the URL model.
- `fuse.py` already scores `ml` findings: 0 points below p = 0.5, up to `ML_MAX = 25` at p = 1. A confident model (p ≥ `ML_CONFIDENT = 0.8`) can lift a message to phishing only together with a heuristic from another family.
- Calibrate on validation data (revised plan §5): `SAFE_BELOW`, `PHISHING_FROM`, `FAMILY_CAPS`, `ML_MAX`, `ML_CONFIDENT`, `HEURISTIC_ONLY_CAP`, `NO_ACTION_CAP`. Compare against the 35/30/35 baseline from P1 (git `85652ce`).

### Acceptance test for your handover to Atharvva (revised plan §10)
- The eval script reproduces `eval.json` exactly (fixed seeds).
- A script check shows no registered domain appears in both train and test.
- Each model can be disabled in turn without a crash; coverage shows it as unavailable or failed.
- Calibrated thresholds are written down with the validation numbers behind them.
- `python -m pytest tests` still passes.

### Known gaps / risks
- **Brand registry accuracy.** Official domains were written from general knowledge; `bank.in` names in particular need checking. A missing official domain causes false alarms; a wrong one hides impersonation. Check them against the team's real legitimate messages.
- **Heuristic-only scams** (lottery fee, electricity, AnyDesk) stop at suspicious by design. The text model is what can push them higher.
- **English only.** Hindi and Hinglish wording isn't covered by the content rules.
- **Legitimate links on unknown domains.** A brand mention plus a link to a domain not in the registry gives `BRAND_LINK_UNVERIFIED` (heuristic, 15). That turns into a confirmed finding when the message also asks for details or payment, so a real bank SMS using an unlisted shortener can be flagged. Add the shortener to the brand's domains.
- **No redirect following and no domain-age or reputation lookups** (Could Have, off by design).
- `src/detection/ensemble.py` is still old PrivacyLens code that nothing imports.
