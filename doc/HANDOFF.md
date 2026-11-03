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
- Atharva: 20 demo samples (`data/demo_samples.json`), extension skeleton, test Gmail inbox.
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
- **Brand registry** (`src/detection/brands.py`): 37 brands with their aliases, name tokens and official domains, plus the `.sbi` brand TLD and `<bank>.bank.in`. Impersonation checks:
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

### Acceptance test for your handover to Atharva (revised plan §10)
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

---

## P3 Machine learning → P4 Browser extension

**From:** Govind · **To:** Atharva

### What works
- **Two calibrated models** are plugged into the detection engine (details and limits in [MODEL_CARD.md](MODEL_CARD.md)):
  - URL model: gradient-boosted trees on the URL's spelling only, never fetched;
  - text model: TF-IDF + logistic regression.

  They're committed in `models/` (~4 MB, scikit-learn 1.6.1), so `python -m src.pipeline.demo` works without training.
- **Model findings** appear as `URL_MODEL` (per link) and `TEXT_MODEL` (whole message, `start: null`), tier `ml`. They're listed only when the model is confident enough to add points.
- **`urls[].score`** now carries the URL model's probability.
- **Coverage:** `url_model` / `text_model` are `ran` when the models are loaded, so `confidence` can now be `high`. If a model is missing it's `unavailable`; if it crashes it's `failed` with `partial: true`.
- **Startup:** the server loads both models in the background. `GET /api/health` reports `{"models": {"url": "loaded", "text": "loaded"}}`.
- **Scoring tuned on validation:**
  - **safe is now < 30** (was < 35);
  - a confident model adds up to 45 points;
  - a model alone can reach suspicious but never phishing;
  - messages with nothing to act on stay safe whatever the models say.
- **Reproducible evaluation:** `python -m src.eval.phish_bench` gave identical metrics on two runs (`ffabd7431ec8dd8b`). No domain or text overlaps between splits.
- **Tests:** 100 pass. They run rules-only by default (`tests/conftest.py`); model tests use fake models plus the real ones when present.

### Headline held-out results (system, flagged = suspicious or phishing)

| Set | F1 | False alarms |
|---|---|---|
| Emails | 0.941 | 4.5% |
| SMS | 0.767 | 0% |
| URLs | 0.749 | 0.8% |
| OpenPhish (recent) | n/a | recall 0.685 |
| Tranco top sites | n/a | 0.8% |
| UCI SMS ham | n/a | 0.03% (1 of 3,630) |

The full table, the comparison with the old 35/30/35 formula and the caveats are in the model card. The Indian set results there are synthetic and not an accuracy claim.

### For the extension (what you need from the API)
- Call `/api/analyze` from the background service worker (see API.md). Send `email.from` / `reply_to` / `subject` and every link as `{text, href}`; sender and link checks need them.
- The first call after server start can take ~1–3 s if the models are still loading. Use `/api/health` to show "starting…".
- Show `TEXT_MODEL` as a message-level reason (no highlight). Highlight everything else with `start_u16` / `end_u16`, or by matching `text` for `field: "link"` findings.
- Grey "Low risk: limited checks" when `confidence` is `low`. Grey "Couldn't check this message" when the request fails. Never green in either case.

### Acceptance test for your handover to Ryan (revised plan §10)
- 20 Gmail samples are correct.
- Stopping the server → grey banner.
- HTML/script inside an email is shown as text.
- `google.com/url?q=` links are unwrapped. The server also does this, but the extension should send the real target.
- No hard-coded results anywhere in the extension.

### Known gaps / notes
- **English only.** Indian SMS are represented by synthetic training templates only. Collect real, redacted messages to replace them and to measure false alarms properly.
- **Spam vs phishing.** The text model partly learned "spam". Marketing SMS may score high, but scoring keeps them safe unless they contain a link, number or payment request.
- **Rebuilding the models** (`fetch_data → prepare → train_url → train_text → phish_bench --tune → phish_bench`) needs ~180 MB of downloads and ~8 minutes. Re-run `--tune` after retraining and copy the chosen values into `fuse.py`.
- `src/model/train.py`, `train_v2.py`, `accuracy_loop.py` and `corpus/` are the old PrivacyLens PII model. The pipeline/training pages still read them; they're reworked in P5.

---

## P4 Browser extension → P5 Integration and deployment

**From:** Atharva · **To:** Ryan

### What works
- **Chrome extension (Manifest V3)** in `extension/`; install steps in [extension/README.md](../extension/README.md).
  - **Gmail:** a banner above each opened email.
    - red / amber / green / grey, up to 3 reasons, and **Details** with the explanation and the checks that ran;
    - on non-safe emails, flagged phrases are highlighted and risky links outlined;
    - a MutationObserver picks up emails Gmail swaps in without reloading.
  - **Other sites:** risky outgoing links are outlined, with the reason on hover and a badge count. *Automatic* mode only scans when the server is local.
  - **Popup:** server status, plus paste-and-check with highlighted phrases.
  - **Settings:** server address (a non-local address asks Chrome for permission), Gmail on/off, link checking auto/on/off.
- **Safety rules from API.md:**
  - the extension only shows what the API returns;
  - all text is inserted with `textContent` inside a closed Shadow DOM;
  - low confidence → grey "Low risk: limited checks";
  - request failed → grey "Couldn't check this message" (never green);
  - hosted mode shows a disclosure;
  - safe emails get no highlights; minor notes are labelled "Noted, but not enough to flag".
- **Only the background worker calls the API** (Gmail's origin would be blocked by CORS). It has a 15 s timeout and an in-memory cache of 50 results.
- **Dev test pages:** `python -m src.pipeline.demo --dev` serves `extension/dev/gmail.html` (Gmail look-alike with 5 samples and an offline switch), `extension/dev/links.html` and the popup. They run the real content scripts against the API.
- **Tests:** 5 Node unit tests for `shared/verdict.js` (`node --test extension/test/*.test.js`); 100 Python tests still pass.

### Checked on the dev pages (real scripts, real API, both models loaded)

| Sample | Result |
|---|---|
| SBI KYC phishing | **phishing 100**, 3 reasons, fake `onlinesbi.sbi` link outlined, phrases highlighted |
| HDFC statement (legit) | **green 2/100**, "Noted, but not enough to flag: generic greeting", no highlights |
| Lottery, no link, with emoji | **phishing 85**; payment, OTP/details request and "reply with your bank details" highlighted and aligned despite the emoji |
| Meeting note (legit) | **green 0/100** |
| `<script>` / `<img onerror>` as email text | shown as plain text, nothing executed; `paypa1.com` link caught (**phishing 100**) |
| Server offline | grey **"Couldn't check this message"**, email not marked safe |
| Link page (10 links) | the 4 risky ones outlined (amaz0n-refund.in, sbi-kyc.xyz, paypal.com.login-verify.ru, raw IP); Amazon, Flipkart, SBI, HDFC, Python docs, Wikipedia untouched |
| Popup | Paytm KYC scam → **phishing 100**, 5 reasons, phrases highlighted with emoji |

### Not verified
- **The extension hasn't been loaded into real Chrome or run against real Gmail yet.** The Claude app's browser can't load extensions, so the checks above used the Gmail look-alike page, which copies Gmail's class names (`div.a3s`, `div.adn`, `span.gD[email]`, `h2.hP`). Before the demo, someone must:
  1. load it unpacked (`chrome://extensions` → Developer mode → Load unpacked → `extension/`);
  2. send the 20 demo samples to the test inbox;
  3. confirm each banner.

  If Gmail's markup differs, fix the selectors in `SEL` at the top of `content/gmail.js`.
- **Real Chrome-only paths:** the badge, options-page permission requests and the service worker's message passing only run inside real Chrome.

### Acceptance test for your handover to Atharva (P5 → P6, revised plan §10)
- **Fallback matrix passes:** rules-only, no URL model, no text model, Groq down, API down, unsupported file, malformed URL, empty / oversized input, HTML email.
- Hosted disclosure visible; logs contain no message text.
- Metrics shown in the UI match `data/eval.json`.

### Known gaps / notes
- **Reply-To:** Gmail doesn't show it in the page, so the extension can't send it. That check only works for `.eml` uploads (P5).
- **Feedback buttons:** not built (Could Have).
- **Hosted use:** the API's CORS allows any `chrome-extension://` origin. For a hosted deploy, consider pinning the published extension ID.
- **Web app:** the main web page is still the PrivacyLens demo. The PhishShield result screen is part of P5. The popup's result card (`popup/`) and `shared/verdict.js` can be reused for it.

---

## P5 Integration and deployment → P6 Demo and submission

**From:** Ryan · **To:** Atharva

### What works (tag `v1.0`)
- **Web app** at http://localhost:8000:
  - **Check a message:** tabs for message / email (From, Reply-To, Subject) / link / file upload, and 7 one-click samples.
  - **The result shows:**
    - verdict colour, score bar (30 / 70 marks) and confidence;
    - which checks ran;
    - reasons labelled Proven / Pattern / Model with their points (top 5, then "Show all");
    - highlighted phrases, and a links table with risk and URL-model score;
    - the explanation.
  - **Results:** every number read from `data/eval.json` via `/api/eval`.
  - **How it works:** the checks, the privacy facts for the current mode, and what the labels mean.
  - It reuses the extension's result logic (`/shared/verdict.js`), so the web app and the Gmail banner always agree.
- **AI explanations** (`src/pipeline/explain.py`, `POST /api/explain`):
  - `openai/gpt-oss-120b` on Groq (`GROQ_API_KEY`), called separately so `/api/analyze` stays fast.
  - It sees only the reasons, their domains and the **sanitized** message.
  - Answers are rejected (template used instead) if they name another domain, contradict the verdict, skip the reasons or the "What to do" advice, or run long.
  - Never used for safe results or without a key.
- **Uploads** (`src/pipeline/files.py`, `POST /api/analyze/file`):
  - `.eml`: From / Reply-To / Subject are read, so the Reply-To check now works. HTML becomes text with scripts and hidden text dropped; link text vs real link is kept; attachments are listed, never opened.
  - PDF and `.txt` are supported too.
  - Clear 415 / 413 / 400 errors.
- **Local vs hosted** (`PHISHSHIELD_MODE`):
  - hosted shows a disclosure on every page and uses template explanations;
  - nothing is stored or logged in either mode (tested);
  - `render.yaml` + `requirements-demo.txt` were checked in a **clean venv**: no torch, about 238 MB RAM, identical model scores;
  - `PHISHSHIELD_EXTENSION_IDS` can lock the API to the published extension.
- **Removed:** the PrivacyLens features outside scope (document Q&A, `/api/rag*`, `/api/document`, `/api/pipeline`, the ask/training pages, old PII training and benchmark code). Old page URLs redirect.
- **Tests:**
  - **133 Python tests**, including the full fallback matrix: rules only, each model missing, Groq down or erroring, bad AI answers, empty / oversized / malformed input, HTML email, unsupported and broken files, no message text in logs, removed endpoints;
  - **5 extension tests**.
- **Final measurement:**
  - two runs give identical `metrics_sha256 = ca1d8651eeb44b87`;
  - the system's numbers are unchanged from P3;
  - the old-formula comparison was fixed: it had treated "no wording to read" on bare links as a 0 score. The fair numbers are in the model card.

### Checked in the browser
- **All 7 samples:**
  - the 4 scams are phishing 83–100 with a local-AI explanation;
  - the bank OTP and Amazon shipping messages are green 0;
  - the KYC reminder is green 29, with its notes labelled "not enough to flag".
- **Uploaded HDFC `.eml`:** phishing 100, from 5 proven findings including link text vs real link and sender mismatch. The attachment was not opened and the hidden text was ignored.
- **Errors:** PNG upload → clear "wrong type" message. Server offline → grey "Couldn't check this message".
- **Hosted mode:** disclosure banner and the "Hosted demo" / "Template explanations" chips.
- **Layout:** works in a desktop window and at 375 px phone width.

### For the demo (P6)
- **Start:** `python -m src.pipeline.demo`, with `GROQ_API_KEY` set for AI explanations. The header chips should read "Running on this computer · Models ready · AI explanations".
- **Suggested order:**
  1. SBI KYC SMS: phishing, proven reasons and the AI explanation.
  2. Bank OTP alert: green.
  3. KYC reminder: green 29, "not enough to flag".
  4. Upload the HDFC `.eml`, or the Fake PayPal email sample.
  5. Lookalike link.
  6. Gmail with the extension.
  7. Results page.
  8. How it works → Privacy.
- The AI explanation takes about 1–2 s and appears after the result. Without a key or if Groq is down, the template is used and the header says so.

### Still not done (before the demo)
- **The extension in real Chrome on real Gmail** (see the P4 notes).
- **Deploying to Render** needs a Render account connected to the GitHub repo (New → Blueprint → pick the repo). Not done here.
- **Real, redacted Indian messages** to measure false alarms on real data (model card limitation).

### Acceptance test for your submission (revised plan §10)
- Every number on screen or in the slides traces to `data/eval.json` / the model card.
- Privacy statements match the mode shown.
- Two rehearsals done.

---

## P6 Demo and submission: materials ready

**From:** Atharva · **To:** the whole team

- **Demo:**
  - [DEMO_SCRIPT.md](DEMO_SCRIPT.md): a 3-minute and a 5-minute run, a pre-flight checklist, recovery steps, and what not to say.
  - Every sample opens directly with `/?sample=<name>`.
  - [demo/samples](../demo/samples) has 5 sample emails (3 scams, 2 legitimate), each checked: 100 / 100 / 100 phishing; 2 and 9 safe.
- **Judge prep:** [QA.md](QA.md), with an owner for each answer.
- **Video:** [VIDEO_SCRIPT.md](VIDEO_SCRIPT.md), 8 shots in 2:45, with voice-over and captions.
- **Slides:** 12 slides at https://claude.ai/artifact/3nDzxi9nBKtScsJJX6M8uj (private until shared). Every number is taken from `data/eval.json`.
- **README:** rewritten as the submission front page, with screenshots in `doc/screenshots/`.
- **Consistency check:** every quoted number was checked against `data/eval.json`, and 2 rounding mismatches were fixed.
- **Checklist:** [SUBMISSION.md](SUBMISSION.md), which maps every requirement in the problem statement to where it lives.
- **Removed leftovers:** the `video/` stub and `requirements-gguf.txt`.

**Left for people:** the real Chrome + Gmail check, recording, an optional Render deploy, sharing the deck, rehearsals, and submitting.
