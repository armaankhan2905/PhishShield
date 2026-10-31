# PhishShield

**PECathon 2026 · Problem 02 · Phishing and scam detection**

A web app and a Chrome extension that analyse emails, SMS messages and URLs and
flag phishing, suspicious links, impersonation and social-engineering patterns.
Every result has a 0–100 risk score, a verdict, the exact phrases and links that
raised it with a reason for each, and a plain-English explanation. Analysis runs
locally, and personal data is redacted before any LLM sees a message.

Built on our earlier PrivacyLens project: its detection layer, FastAPI server,
web pages, sanitizer and local LLM client are reused.

## Team

| Member | Owns | Leads |
|---|---|---|
| Ryan | Backend (`src/pipeline/`), web app (`demo/`), deploy, merges | P1, P5 |
| Armaan | Rules, anomaly checks, score fusion (`src/detection/`) | P2 |
| Govind | Datasets, URL + message classifiers, evaluation (`src/model/`, `src/eval/`, `data/`) | P3 |
| Atharvva | Chrome extension (`extension/`), demo samples, README, video | P4, P6 |

The build runs as a relay: one lead per phase hands over to the next.
Handovers are logged in [doc/HANDOFF.md](doc/HANDOFF.md).

## Run it

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements-demo.txt
python -m src.pipeline.demo     # http://localhost:8000
```

Open http://localhost:8000 to check a message, email, link or uploaded `.eml` / PDF.
**Results** shows the measured accuracy and **How it works** explains the checks.

Optional, for plain-English explanations written by a local AI model
([Ollama](https://ollama.com) on the same computer; without it a template is used):

```bash
ollama pull qwen2.5:3b
```

Chrome extension (Gmail banner, risky-link outlines): see [extension/README.md](extension/README.md).

Try the API:

```bash
curl -X POST localhost:8000/api/analyze -H "Content-Type: application/json" -d "{\"text\": \"URGENT: your SBI KYC is pending, verify at http://sbi-kyc.xyz/login\"}"
```

Rebuild the models and measurements (optional: the trained models are committed):

```bash
python -m src.model.fetch_data        # download public datasets to data/raw/
python -m src.model.prepare           # clean, de-duplicate, split by domain -> data/processed/
python -m src.model.train_url         # ~35 s
python -m src.model.train_text        # ~90 s
python -m src.eval.phish_bench --tune # tune scoring on validation -> data/calibration.json
python -m src.eval.phish_bench        # held-out results -> data/eval.json
```

Run the tests:

```bash
pip install pytest httpx
python -m pytest tests                    # Python: API, detection, models, fallbacks, privacy
node --test extension/test/*.test.js      # extension result logic
```

## Hosted demo (Render)

`render.yaml` deploys the web app with `PHISHSHIELD_MODE=hosted`:
- every page shows that messages are sent to the server;
- explanations use the template (no Ollama on the server);
- nothing is stored or logged.

The build uses only `requirements-demo.txt` (no torch) and runs in about 240 MB.
To deploy: in Render, choose **New → Blueprint**, pick this repository, and confirm.
Optionally set `PHISHSHIELD_EXTENSION_IDS` to your published extension's ID.

## How it works

```text
message / URL / email ─► extract URLs ─► rules engine ────┐
                                     ├─► URL classifier ──┼─► fuse ─► score + verdict + reasons
                                     ├─► text classifier ─┤               │
                                     └─► email anomalies ─┘               ▼
                                                              sanitize ─► local LLM explanation
```

The request and response format is in [doc/API.md](doc/API.md).

## Layout

```text
src/detection/   engine.py · rules.py · anomaly.py · domains.py · brands.py · fuse.py · main.py (reused regexes)
src/model/       URL + text models: fetch_data · prepare · train_url · train_text · predict
src/eval/        phish_bench.py (every reported number comes from here)
src/pipeline/    demo.py (server) · analyze.py · explain.py (local AI) · files.py (.eml/PDF) · sanitize.py · documents.py
demo/            web app: index.html (check) · results.html · how.html · static/
extension/       Chrome extension (Manifest V3): Gmail banner, risky-link outlines, popup; see extension/README.md
data/            eval.json · calibration.json · curated/ (raw/ and processed/ are rebuilt, not in git)
models/          url_model.joblib · text_model.joblib (~4 MB, committed)
doc/             API.md · HANDOFF.md · MODEL_CARD.md · privacylens/ (old project docs)
tests/           API contract tests
```

## Status

| Phase | Lead | Status |
|---|---|---|
| P1 Foundation | Ryan | Done: API contract v1.1, stub detection live, 13 contract tests passing |
| P2 Detection engine | Armaan | Done: rules, domain and sender checks, evidence-gated scoring, 81 tests passing |
| P3 ML models | Govind | Done: URL + text models, calibrated scoring, held-out evaluation ([MODEL_CARD](doc/MODEL_CARD.md)) |
| P4 Extension live | Atharvva | Done: Gmail banner, link outlines, popup, settings (checked on dev pages; real-Gmail check pending) |
| P5 Integrate + deploy | Ryan | Done: web app, local-AI explanations, .eml/PDF upload, hosted mode, fallback tests, v1.0 |
| P6 Demo + submit | Atharvva | Next |
