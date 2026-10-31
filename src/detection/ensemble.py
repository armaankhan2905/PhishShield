"""
PrivacyLens Detection Pipeline
Ensemble approach: Regex + ML Model for maximum recall
"""
import re
import json
from typing import List, Dict, Tuple

# Regex patterns for different entity types
CARD_PATTERN = re.compile(
    r'\b(?:\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}|\d{16})\b'
)
PHONE_PATTERN = re.compile(
    r'\b(?:\+91[\-\s]?|0)?[6-9]\d{9}\b|\b\d{10}\b|\b\d{9}\b'
)
OTP_PATTERN = re.compile(
    r'\b(?:otp|code|pin)[\s:]+(\d{4,8})\b',
    re.IGNORECASE
)
EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)
PAN_PATTERN = re.compile(
    r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'
)
IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)
URL_PATTERN = re.compile(
    r'https?://[^\s]+'
)

def luhn_check(card_number: str) -> bool:
    """Validate card number using Luhn algorithm."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0

def regex_detect(text: str) -> List[Dict]:
    """Detect PII using regex patterns."""
    entities = []
    
    # Card detection with Luhn validation
    for match in CARD_PATTERN.finditer(text):
        card_num = match.group()
        if luhn_check(card_num):
            entities.append({
                'text': card_num,
                'type': 'CARD',
                'start': match.start(),
                'end': match.end(),
                'method': 'regex+luhn'
            })
    
    # Phone detection
    for match in PHONE_PATTERN.finditer(text):
        phone = match.group()
        digits = ''.join(filter(str.isdigit, phone))
        if 9 <= len(digits) <= 10:
            entities.append({
                'text': phone,
                'type': 'PHONE',
                'start': match.start(),
                'end': match.end(),
                'method': 'regex'
            })
    
    # OTP detection (context-aware)
    for match in OTP_PATTERN.finditer(text):
        otp = match.group(1)
        entities.append({
            'text': otp,
            'type': 'OTP',
            'start': match.start(),
            'end': match.end() - len(otp) + len(match.group()),
            'method': 'regex+context'
        })
    
    # Email detection
    for match in EMAIL_PATTERN.finditer(text):
        entities.append({
            'text': match.group(),
            'type': 'EMAIL',
            'start': match.start(),
            'end': match.end(),
            'method': 'regex'
        })
    
    # PAN detection
    for match in PAN_PATTERN.finditer(text):
        entities.append({
            'text': match.group(),
            'type': 'PAN',
            'start': match.start(),
            'end': match.end(),
            'method': 'regex'
        })
    
    # IP detection
    for match in IP_PATTERN.finditer(text):
        ip = match.group()
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            entities.append({
                'text': ip,
                'type': 'IP',
                'start': match.start(),
                'end': match.end(),
                'method': 'regex'
            })
    
    # URL detection
    for match in URL_PATTERN.finditer(text):
        entities.append({
            'text': match.group(),
            'type': 'URL',
            'start': match.start(),
            'end': match.end(),
            'method': 'regex'
        })
    
    return entities

def ml_detect(text: str) -> List[Dict]:
    """Detect PII using the trained BERT model."""
    try:
        from transformers import AutoTokenizer, AutoModelForTokenClassification
        import torch
        
        tokenizer = AutoTokenizer.from_pretrained(
            'models/google-bert_bert-base-uncased'
        )
        model = AutoModelForTokenClassification.from_pretrained(
            'models/pii_classifier'
        )
        
        inputs = tokenizer(text, return_tensors='pt', truncation=True, max_length=128)
        outputs = model(**inputs)
        preds = outputs.logits.argmax(-1)[0].tolist()
        
        entities = []
        current_entity = None
        
        for i, (token, pred) in enumerate(
            zip(tokenizer.convert_ids_to_tokens(inputs['input_ids'][0]), preds)
        ):
            label = model.config.id2label[pred]
            
            if label.startswith('B-'):
                if current_entity:
                    entities.append(current_entity)
                entity_type = label[2:]
                current_entity = {
                    'type': entity_type,
                    'start': None,
                    'end': None,
                    'tokens': [token],
                    'method': 'ml'
                }
            elif label.startswith('I-') and current_entity:
                current_entity['tokens'].append(token)
            else:
                if current_entity:
                    entities.append(current_entity)
                    current_entity = None
        
        if current_entity:
            entities.append(current_entity)
        
        # Convert token positions to character positions
        enc = tokenizer(text, return_offsets_mapping=True, truncation=True, max_length=128)
        token_idx = 0
        for entity in entities:
            start_offset = None
            end_offset = None
            for i, (start, end) in enumerate(enc.offset_mapping):
                if start == 0 and end == 0:
                    continue
                if i < token_idx + len(entity['tokens']):
                    if start_offset is None:
                        start_offset = start
                    end_offset = end
            entity['start'] = start_offset
            entity['end'] = end_offset
            entity['text'] = text[start_offset:end_offset] if start_offset and end_offset else ''
            token_idx += len(entity['tokens'])
        
        return [e for e in entities if e.get('text')]
    
    except Exception as e:
        print(f"ML detection error: {e}")
        return []

def ensemble_detect(text: str) -> List[Dict]:
    """Combine regex and ML detection for maximum recall."""
    # Get regex results
    regex_entities = regex_detect(text)
    
    # Get ML results
    ml_entities = ml_detect(text)
    
    # Merge: prefer regex for structured data, ML for names
    seen_spans = set()
    combined = []
    
    # Add regex entities first (higher precision for cards, phones, etc.)
    for entity in regex_entities:
        span = (entity['start'], entity['end'])
        if span not in seen_spans:
            seen_spans.add(span)
            combined.append(entity)
    
    # Add ML entities that don't overlap
    for entity in ml_entities:
        span = (entity.get('start'), entity.get('end'))
        if span and span not in seen_spans:
            seen_spans.add(span)
            combined.append(entity)
    
    # Sort by position
    combined.sort(key=lambda x: x.get('start', 0))
    
    return combined

def redact_text(text: str, entities: List[Dict]) -> str:
    """Redact detected entities from text."""
    redacted = text
    for entity in reversed(entities):
        start = entity.get('start')
        end = entity.get('end')
        if start is not None and end is not None:
            redacted = redacted[:start] + f"[REDACTED:{entity['type']}]" + redacted[end:]
    return redacted

# Demo
if __name__ == '__main__':
    test_texts = [
        "My card number is 4532015112830366 and phone is 9876543210",
        "OTP for login is 126225 sent to 9876543210",
        "Contact John at john@example.com or visit https://example.com",
        "IP: 192.168.1.1, PAN: ABCDE1234F",
    ]
    
    print("=== PrivacyLens Detection Pipeline ===\n")
    for text in test_texts:
        print(f"Text: {text}")
        entities = ensemble_detect(text)
        print(f"Detected: {[e['type'] for e in entities]}")
        print(f"Redacted: {redact_text(text, entities)}\n")
