# src/model/train.py
import json
import random
import numpy as np
from transformers import AutoTokenizer, AutoModelForTokenClassification, Trainer, TrainingArguments
from datasets import Dataset

MODEL_NAME = "google-bert/bert-base-uncased"
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
            labels.append([LABEL2ID[l] for l in rec["labels"]])
    return texts, labels

def tokenize_and_align_labels(texts, labels, tokenizer, max_length=128):
    """Tokenize text and align character-level B-/I- labels to subword tokens."""
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
    """Compute token-level accuracy and entity-level F1, ignoring masked positions."""
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    
    # Mask out padding/special tokens (-100)
    mask = labels != -100
    correct = (preds[mask] == labels[mask]).sum()
    total = mask.sum()
    token_accuracy = float(correct / total) if total > 0 else 0.0
    
    # Entity-level precision/recall/F1
    true_entities = extract_entities(preds[mask], labels[mask])
    pred_entities = extract_entities(preds[mask], labels[mask], is_pred=True)
    
    precision = len(true_entities & pred_entities) / max(1, len(pred_entities))
    recall = len(true_entities & pred_entities) / max(1, len(true_entities))
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    
    return {
        "accuracy": token_accuracy,
        "entity_precision": precision,
        "entity_recall": recall,
        "entity_f1": f1,
    }

def main():
    tokenizer = AutoTokenizer.from_pretrained("models/google-bert_bert-base-uncased")
    model = AutoModelForTokenClassification.from_pretrained(
        "models/google-bert_bert-base-uncased",
        num_labels=NUM_LABELS,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )

    texts, labels = load_corpus("data/corpus/train.jsonl")
    
    # Random split with fixed seed
    random.seed(42)
    indices = list(range(len(texts)))
    random.shuffle(indices)
    split = int(0.9 * len(indices))
    train_idx, val_idx = indices[:split], indices[split:]
    
    train_texts = [texts[i] for i in train_idx]
    train_labels = [labels[i] for i in train_idx]
    val_texts = [texts[i] for i in val_idx]
    val_labels = [labels[i] for i in val_idx]
    
    # Build datasets
    train_encodings = tokenize_and_align_labels(train_texts, train_labels, tokenizer)
    val_encodings = tokenize_and_align_labels(val_texts, val_labels, tokenizer)
    train_dataset = Dataset.from_dict(train_encodings)
    val_dataset = Dataset.from_dict(val_encodings)

    training_args = TrainingArguments(
        output_dir="./models/pii_classifier",
        num_train_epochs=3,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        learning_rate=2e-5,
        logging_steps=50,
        save_steps=500,
        eval_strategy="steps",
        eval_steps=250,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
    )

    trainer.train()
    trainer.save_model("./models/pii_classifier")
    print("Saved model to ./models/pii_classifier")

if __name__ == "__main__":
    main()
