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
python -m pytest tests
```

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
src/pipeline/    demo.py (server) · analyze.py · sanitize.py · rag.py · documents.py
demo/            web app pages
extension/       Chrome extension (Phase 1 side task)
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
| P4 Extension live | Atharvva | Next |
| P5 Integrate + deploy | Ryan | Pending |
| P6 Demo + submit | Atharvva | Pending |
