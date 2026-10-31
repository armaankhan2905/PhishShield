"""Local PII classifier — corpus build + training.

Split into two scripts for the 4-hour build:
- `src/model/corpus/build_corpus.py`   → compile training corpus (dlptest + Faker)
- `src/model/train.py`                → fine-tune a local model, quantize, evaluate
"""
