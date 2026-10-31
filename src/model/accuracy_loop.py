"""
Recursive accuracy improvement loop.
Target: 92% token accuracy

Loop:
1. Generate/expand corpus
2. Train model
3. Evaluate
4. If accuracy < 92%, go to step 1 with more data
5. If accuracy >= 92%, stop and save
"""
import json
import random
import time
import shutil
from pathlib import Path

# Configuration
TARGET_ACCURACY = 0.92
MAX_ITERATIONS = 5
BASE_CORPUS_SIZE = 20000
CORPUS_GROWTH_FACTOR = 1.5  # Each iteration adds 50% more data


def run_training(corpus_path, model_output_dir):
    """Run training with current corpus."""
    import subprocess
    result = subprocess.run(
        ["python", "-m", "src.model.train_v2", corpus_path],
        capture_output=True,
        text=True,
        cwd="F:/Hackthon",
        timeout=7200  # 2 hour timeout for training
    )
    if result.returncode != 0:
        print(f"  Training stderr: {result.stderr[-500:]}")
    return result.returncode == 0


def evaluate_model(model_path, corpus_path, sample_size=500):
    """Quick evaluation of model accuracy."""
    import sys
    sys.path.insert(0, "F:/Hackthon")
    
    from transformers import AutoTokenizer, AutoModelForTokenClassification
    
    LABEL2ID = {
        'O': 0, 'B-CARD': 1, 'I-CARD': 2, 'B-PHONE': 3, 'I-PHONE': 4,
        'B-PAN': 5, 'I-PAN': 6, 'B-EMAIL': 7, 'I-EMAIL': 8,
        'B-IP': 9, 'I-IP': 10, 'B-URL': 11, 'I-URL': 12,
        'B-OTP': 13, 'I-OTP': 14, 'B-PERSON': 15, 'I-PERSON': 16,
    }
    
    tokenizer = AutoTokenizer.from_pretrained('models/google-bert_bert-base-uncased')
    model = AutoModelForTokenClassification.from_pretrained(model_path)
    
    # Load corpus
    texts, labels = [], []
    with open(corpus_path) as f:
        for i, line in enumerate(f):
            if i >= sample_size:
                break
            rec = json.loads(line)
            texts.append(rec['text'])
            labels.append([LABEL2ID.get(l, 0) for l in rec['labels']])
    
    # Evaluate
    correct = 0
    total = 0
    
    for text, true_labels in zip(texts, labels):
        inputs = tokenizer(text, return_tensors='pt', truncation=True, max_length=128)
        outputs = model(**inputs)
        preds = outputs.logits.argmax(-1)[0].tolist()
        
        # Align predictions with true labels
        enc = tokenizer(text, truncation=True, max_length=128, return_offsets_mapping=True)
        offsets = enc.offset_mapping
        
        pred_idx = 0
        for start, end in offsets:
            if start == 0 and end == 0:
                continue
            
            while pred_idx < len(preds) and preds[pred_idx] == -100:
                pred_idx += 1
            if pred_idx >= len(preds):
                break
            
            pred_label = preds[pred_idx]
            true_label = true_labels[start]
            pred_idx += 1
            
            total += 1
            if pred_label == true_label:
                correct += 1
    
    accuracy = correct / max(1, total)
    return accuracy


def improve_accuracy():
    """Recursive improvement loop."""
    print("=" * 60)
    print("ACCURACY IMPROVEMENT LOOP")
    print(f"Target: {TARGET_ACCURACY*100:.1f}% token accuracy")
    print(f"Max iterations: {MAX_ITERATIONS}")
    print("=" * 60)
    
    corpus_size = BASE_CORPUS_SIZE
    best_accuracy = 0.0
    best_model = None
    
    for iteration in range(1, MAX_ITERATIONS + 1):
        print(f"\n{'='*60}")
        print(f"ITERATION {iteration}/{MAX_ITERATIONS}")
        print(f"Corpus size: {corpus_size}")
        print(f"{'='*60}")
        
        # Step 1: Generate/expand corpus
        print("\n[1/3] Generating corpus...")
        corpus_path = f"data/corpus/train_v2_{corpus_size}.jsonl"
        
        # Use the improved corpus builder
        import sys
        sys.path.insert(0, "F:/Hackthon")
        from src.model.corpus.build_corpus_v2 import build_corpus
        
        print(f"  Generating {corpus_size} examples...")
        corpus = build_corpus(corpus_size)
        
        with open(corpus_path, "w") as f:
            for rec in corpus:
                f.write(json.dumps(rec) + "\n")
        print(f"  Saved to {corpus_path}")
        
        # Step 2: Train model
        print("\n[2/3] Training model...")
        model_output = f"models/pii_classifier_v2_{iteration}"
        success = run_training(corpus_path, model_output)
        if not success:
            print("  Training failed, skipping...")
            continue
        
        model_path = model_output
        print(f"  Model saved to {model_path}")
        
        # Step 3: Evaluate
        print("\n[3/3] Evaluating...")
        accuracy = evaluate_model(model_path, corpus_path)
        print(f"  Token accuracy: {accuracy*100:.2f}%")
        
        # Track best
        if accuracy > best_accuracy:
            best_accuracy = accuracy
            best_model = model_path
            print(f"  ✓ New best accuracy!")
        
        # Check if target reached
        if accuracy >= TARGET_ACCURACY:
            print(f"\n{'='*60}")
            print(f"✓ TARGET REACHED: {accuracy*100:.2f}% >= {TARGET_ACCURACY*100:.1f}%")
            print(f"Best model: {best_model}")
            print(f"{'='*60}")
            return True, accuracy, model_path
        
        # Increase corpus size for next iteration
        corpus_size = int(corpus_size * CORPUS_GROWTH_FACTOR)
        print(f"\n  Accuracy {accuracy*100:.2f}% < {TARGET_ACCURACY*100:.1f}%")
        print(f"  Increasing corpus to {corpus_size} for next iteration...")
    
    print(f"\n{'='*60}")
    print(f"✗ Target not reached after {MAX_ITERATIONS} iterations")
    print(f"Best accuracy: {best_accuracy*100:.2f}%")
    print(f"Best model: {best_model}")
    print(f"{'='*60}")
    return False, best_accuracy, best_model


if __name__ == "__main__":
    success, accuracy, model_path = improve_accuracy()
    exit(0 if success else 1)
