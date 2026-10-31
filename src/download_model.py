"""
Download google-bert/bert-base-uncased (or any HF model) to your local repo.
Run from the repo root (F:/Hackthon) in the activated venv.
"""

import os
import sys
from pathlib import Path

# Use the venv's transformers + torch
from transformers import AutoTokenizer, AutoModelForTokenClassification
from huggingface_hub import snapshot_download

MODEL_NAME = "google-bert/bert-base-uncased"
REPO = "google-bert/bert-base-uncased"
LOCAL_DIR = Path(os.path.abspath("models")) / MODEL_NAME.replace("/", "_")

os.makedirs(LOCAL_DIR, exist_ok=True)

print(f"Downloading {MODEL_NAME} -> {LOCAL_DIR}")
print("This will take 30-60s (440MB model).")

snapshot_download(
    repo_id=REPO,
    local_dir=LOCAL_DIR,
    allow_patterns=["*.json", "*.txt", "*.safetensors", "*.bin", "*.onnx", "*.md", "*.gitattributes", "*.gitignore", "*.coreml"],
    ignore_patterns=["*.msgpack", "*.h5", "*.ot", "*.flax.*", "*.tf.*"],  # skip large non-safetensors files
)

print("Done. Files in", LOCAL_DIR)

# Verify the download
print("\nVerifying...")
try:
    from transformers import AutoTokenizer, AutoModelForTokenClassification
    tokenizer = AutoTokenizer.from_pretrained(str(LOCAL_DIR))
    model = AutoModelForTokenClassification.from_pretrained(str(LOCAL_DIR))
    print(f"Tokenizer loaded: {tokenizer}")
    print(f"Model params: {sum(p.numel() for p in model.parameters()):,}")
    print("OK: model downloaded and verified")
except Exception as e:
    print("ERROR loading model:", e)
    sys.exit(1)
