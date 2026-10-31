"""PhishShield models: URL model and text model, plus data preparation.

  fetch_data.py   download public datasets into data/raw/
  prepare.py      clean, de-duplicate and group-split into data/processed/
  train_url.py    URL model (gradient-boosted trees on lexical features)
  train_text.py   text model (TF-IDF + logistic regression)
  predict.py      lazy-loaded models used by the detection engine
"""
import os

# joblib probes physical cores through a subprocess (wmic) that is missing on
# newer Windows and prints a traceback. A limit below the logical count skips the probe.
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(max(1, (os.cpu_count() or 2) // 2)))
