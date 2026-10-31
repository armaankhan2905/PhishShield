# Submission checklist

**Problem 02:** PhishShield AI, Phishing and Scam Detection.
**Repository:** https://github.com/armaankhan2905/PhishShield (code freeze: tag `v1.0`).

## What the problem statement asks, and where it is

| Asked for | Where |
|---|---|
| Browser extension **or** web application | **Both**: web app (`demo/`, `src/pipeline/demo.py`) and Chrome extension (`extension/`) |
| Analyse emails, SMS, URLs, message content | Web app tabs: message / email / link / file upload (`.eml`, PDF, `.txt`); extension reads opened Gmail emails and page links |
| Flag phishing attempts | Verdict safe / suspicious / phishing with score and confidence |
| Suspicious links | Public Suffix List domain checks, look-alikes, shorteners, IP links, link-text vs real-link; URL model |
| Impersonation | 37-brand registry: sender and link domain vs brand, display-name spoofing, look-alike characters |
| Social-engineering patterns | Requests for OTP / PIN / payment / remote access, threats, prizes, urgency (warnings like "never share" are not flagged) |
| AI: NLP | Text model (TF-IDF + logistic regression); local LLM explanations (Ollama) grounded in findings |
| AI: URL classification | URL model (gradient-boosted trees, 54 lexical features), calibrated |
| AI: anomaly detection | Sender / reply-to / link-text mismatch checks, hidden HTML text, evidence-gated scoring |

## Deliverables

| Item | Status | Owner |
|---|---|---|
| Source code, tagged `v1.0` | ✅ pushed | Ryan |
| README with setup, screenshots, results | ✅ `README.md` | Atharvva |
| Model card (data, results, limits, disclosures) | ✅ `doc/MODEL_CARD.md` | Govind |
| API reference | ✅ `doc/API.md` | Ryan |
| Demo script (3 and 5 min) | ✅ `doc/DEMO_SCRIPT.md` | Atharvva |
| Judge Q&A | ✅ `doc/QA.md` | everyone |
| Slides (12) | ✅ https://claude.ai/artifact/3nDzxi9nBKtScsJJX6M8uj (private until shared from its Share menu; download as PDF / PPTX there) | Atharvva |
| Video (≤ 3 min) | ⏳ **record**: script in `doc/VIDEO_SCRIPT.md` | Atharvva |
| Extension checked in real Chrome + Gmail | ⏳ **do before recording**: `extension/README.md` | Atharvva |
| Hosted demo URL (optional) | ⏳ Render → New → Blueprint → this repo | Ryan |
| Two rehearsals | ⏳ | everyone |

## Before you press submit
- [ ] `python -m pytest tests -q` → 133 passed; `node --test extension/test/*.test.js` → 5 passed
- [ ] Fresh clone works: `pip install -r requirements-demo.txt`, `python -m src.pipeline.demo`, and the header shows **Models ready**
- [ ] Every number in slides, video and README matches `/results` (`metrics_sha256 e3cf332d…`)
- [ ] Hosted URL (if any) shows the "hosted demo" notice
- [ ] Video uploaded, link set to "anyone with the link"
- [ ] Repository is public (or judges were given access)
- [ ] Portal form: team members, problem 02, repo link, video link, slides link, hosted URL
