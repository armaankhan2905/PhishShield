# PhishShield project progress

**Updated:** 2026-10-31, after Phase 5 was completed (tag `v1.0`).

| Phase | Lead | Status |
|---|---|---|
| P1 Foundation | Ryan | ✅ Done |
| P2 Core detection | Armaan | ✅ Done |
| P3 Machine learning | Govind | ✅ Done: see [doc/MODEL_CARD.md](doc/MODEL_CARD.md) and the P3 section of [doc/HANDOFF.md](doc/HANDOFF.md) |
| P4 Browser extension | Atharvva | ✅ Done: see [extension/README.md](extension/README.md). Real-Gmail check still to do |
| P5 Integration + deployment | Ryan | ✅ Done: web app, local-AI explanations, .eml/PDF upload, hosted mode, fallback tests. Render deploy not done (needs an account) |
| P6 Demo + submission | Atharvva | ⏳ Next |

## Phase 3 summary
- **Models:** URL model (`url-hgb-1`) and text model (`text-tfidf-lr-1`), calibrated, committed in `models/`.
- **Scoring:** constants tuned on validation (`data/calibration.json`): `SAFE_BELOW = 30`, `ML_MAX = 45`, `URL_FLOOR = 0.7`, `TEXT_FLOOR = 0.5`.
- **Held-out evaluation** (`data/eval.json`, reproducible: two runs give `metrics_sha256 = ffabd7431ec8dd8b`):

  | Set | F1 | False alarms |
  |---|---|---|
  | Emails | 0.941 | 4.5% |
  | SMS | 0.767 | 0% |
  | URLs | 0.749 | 0.8% |
  | OpenPhish recent phishing | n/a | recall 0.685 |
  | Tranco top sites | n/a | 0.8% |
  | UCI SMS ham | n/a | 0.03% |

- **Leakage check:** 0 domains / 0 texts in more than one split. 4 hand-written test messages that matched training templates were removed.
- **Tests:** 100 pass.

## Phase 3 interruptions (resolved)
- The first evaluation pair was interrupted by the user. It was restarted once, then stopped again by me after the hand-written test set was found to overlap synthetic training templates. It was re-run after the fix and the reproducibility check passed.

## Next
P6 (demo + submission): see the P5 → P6 section of doc/HANDOFF.md.
Before the demo:
- load the extension in real Chrome and check it against real Gmail;
- optionally deploy to Render (New → Blueprint).

Latest evaluation: `metrics_sha256 = 9b5ff4ec33237882` (two identical runs).

## Commands

```bash
python -m src.pipeline.demo                    # server on http://localhost:8000
python -m pytest tests -q                      # 133 tests
python -m src.eval.phish_bench                 # re-measure (about 2.5 min), writes data/eval.json
python -m src.pipeline.demo --dev              # + extension test pages at /dev/extension/dev/gmail.html
node --test extension/test/*.test.js           # extension unit tests
```
