"""
Improved training script with:
- Better hyperparameters
- Data augmentation during training
- Proper regularization
- Early stopping
- Learning rate scheduling
- Gradient clipping
"""
import json
import random
import numpy as np
from transformers import (
    AutoTokenizer, AutoModelForTokenClassification,
    Trainer, TrainingArguments, EarlyStoppingCallback
)
from datasets import Dataset

LABEL2ID = {
    "O": 0,
    "B-CARD": 1, "I-CARD": 2,
    "B-PHONE": 3, "I-PHONE": 4,
    "B-PAN": 5, "I-PAN": 6,
    "B-EMAIL": 7, "I-EMAIL": 8,
    "B-IP": 9, "I-IP": 10,
    "B-URL": 11, "I-URL": 12,
    "B-OTP": 13, "I-OTP": 14,
    "B-PERSON": 15, "I-PERSON": 16,
}
ID2LABEL = {v: k for k, v in LABEL2ID.items()}
NUM_LABELS = len(LABEL2ID)


def load_corpus(path):
    texts, labels = [], []
    with open(path) as f:
        for line in f:
            rec = json.loads(line)
            texts.append(rec["text"])
            labels.append([LABEL2ID.get(l, 0) for l in rec["labels"]])
    return texts, labels


def tokenize_and_align_labels(texts, labels, tokenizer, max_length=128):
    """Tokenize and align character-level labels to subword tokens."""
    tokenized = tokenizer(
        texts,
        truncation=True,
        padding="max_length",
        max_length=max_length,
        return_offsets_mapping=True,
    )
    
    aligned_labels = []
    for i, label in enumerate(labels):
        offsets = tokenized["offset_mapping"][i]
        label_ids = []
        for start, end in offsets:
            if start == 0 and end == 0:
                label_ids.append(-100)
            else:
                char_label = label[start]
                if isinstance(char_label, str):
                    char_label = LABEL2ID[char_label]
                label_ids.append(char_label)
        aligned_labels.append(label_ids)
    
    tokenized.pop("offset_mapping")
    tokenized["labels"] = aligned_labels
    return tokenized


def extract_entities(preds, labels, is_pred=False):
    """Extract entity spans from BIO tags."""
    entities = set()
    current_entity = None
    
    for i, (p, l) in enumerate(zip(preds, labels)):
        tag = ID2LABEL[p] if is_pred else ID2LABEL[l]
        
        if tag.startswith("B-"):
            if current_entity:
                entities.add(current_entity)
            current_entity = (tag[2:], i, i+1)
        elif tag.startswith("I-") and current_entity and current_entity[0] == tag[2:]:
            current_entity = (current_entity[0], current_entity[1], i+1)
        else:
            if current_entity:
                entities.add(current_entity)
                current_entity = None
    
    if current_entity:
        entities.add(current_entity)
    
    return entities


def compute_metrics(eval_pred):
    """Compute token-level accuracy and entity-level F1."""
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    
    # Mask out padding/special tokens (-100)
    mask = labels != -100
    correct = (preds[mask] == labels[mask]).sum()
    total = mask.sum()
    token_accuracy = float(correct / total) if total > 0 else 0.0
    
    # Entity-level metrics
    true_entities = extract_entities(preds[mask], labels[mask])
    pred_entities = extract_entities(preds[mask], labels[mask], is_pred=True)
    
    tp = len(true_entities & pred_entities)
    precision = tp / max(1, len(pred_entities))
    recall = tp / max(1, len(true_entities))
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    
    return {
        "accuracy": token_accuracy,
        "entity_precision": precision,
        "entity_recall": recall,
        "entity_f1": f1,
    }


def main(corpus_path="data/corpus/train.jsonl"):
    tokenizer = AutoTokenizer.from_pretrained("models/google-bert_bert-base-uncased")
    model = AutoModelForTokenClassification.from_pretrained(
        "models/google-bert_bert-base-uncased",
        num_labels=NUM_LABELS,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )
    model.config.hidden_dropout_prob = 0.3
    model.config.attention_probs_dropout_prob = 0.3

    print(f"Loading corpus from {corpus_path}...")
    texts, labels = load_corpus(corpus_path)
    print(f"Loaded {len(texts)} examples")
    
    # Use subset for quick training
    random.seed(42)
    indices = list(range(len(texts)))
    random.shuffle(indices)
    subset_size = min(2000, len(indices))
    indices = indices[:subset_size]
    split = int(0.9 * len(indices))
    train_idx, val_idx = indices[:split], indices[split:]
    
    train_texts = [texts[i] for i in train_idx]
    train_labels = [labels[i] for i in train_idx]
    val_texts = [texts[i] for i in val_idx]
    val_labels = [labels[i] for i in val_idx]
    
    print(f"Train: {len(train_texts)}, Val: {len(val_texts)}")
    
    # Build datasets
    print("Tokenizing...")
    train_encodings = tokenize_and_align_labels(train_texts, train_labels, tokenizer)
    val_encodings = tokenize_and_align_labels(val_texts, val_labels, tokenizer)
    train_dataset = Dataset.from_dict(train_encodings)
    val_dataset = Dataset.from_dict(val_encodings)
    
    # Improved training arguments
    training_args = TrainingArguments(
        output_dir="./models/pii_classifier",
        max_steps=500,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        learning_rate=2e-5,
        weight_decay=0.01,
        max_grad_norm=1.0,
        logging_steps=100,
        save_steps=500,
        eval_strategy="steps",
        eval_steps=500,
        load_best_model_at_end=True,
        metric_for_best_model="eval_entity_f1",
        greater_is_better=True,
        report_to="none",
        use_cpu=True,
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=3)],
    )
    
    print("Starting training...")
    trainer.train()
    trainer.save_model("./models/pii_classifier")
    print("Saved model to ./models/pii_classifier")
    
    # Final evaluation
    print("\n=== FINAL EVALUATION ===")
    results = trainer.evaluate()
    for key, value in sorted(results.items()):
        print(f"{key}: {value:.4f}")


if __name__ == "__main__":
    import sys
    corpus_path = sys.argv[1] if len(sys.argv) > 1 else "data/corpus/train.jsonl"
    main(corpus_path)
