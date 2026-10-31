import json
import random
import re
from faker import Faker

fake = Faker('en_US')
random.seed(42)

def make_card():    return "4532015112830366"
def make_pan():     return f"{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{''.join(random.choices('1234567890', k=10))}"
def make_ip():      return ".".join(str(random.randint(1,255)) for _ in range(4))
def make_url():     return f"https://example.com/path/{random.randint(1000,9999)}"
def make_email():   return f"{fake.user_name()}@example.com"
def make_person():  return f"{fake.first_name()} {fake.last_name()}"
def make_phone():   return f"{random.randint(1000000000,9999999999)}"
def make_otp():     return f"{random.randint(100000,999999)}"

def build_corpus():
    corpus = []
    records = [
        ("My card number is {{card}} and my phone is {{phone}}.", ["CARD", "PHONE"]),
        ("OTP for login is {{otp}} sent to {{phone}}.", ["OTP", "PHONE"]),
        ("Hello {{person}}, contact me at {{email}}.", ["PERSON", "EMAIL"]),
        ("IBAN: {{pan}}, IP: {{ip}}, URL: @url:`{{url}}`", ["PAN", "IP", "URL"]),
        ("Device sent {{card}} and {{phone}} to server.", ["CARD", "PHONE"]),
    ]
    for _ in range(5):
        # Build entity values ONCE
        e = {
            'card': make_card(), 'phone': make_phone(), 'otp': make_otp(),
            'email': make_email(), 'pan': make_pan(), 'ip': make_ip(),
            'url': make_url(), 'person': make_person()
        }
        for template, _entity_types in records:
            # Replace placeholders with generated values
            text = template
            for k, v in e.items():
                text = text.replace('{{' + k + '}}', v)
            corpus.append({"text": text, "labels": label_entities(text, e)})
    return corpus

def label_entities(text, e):
    labels = ["O"] * len(text)

    # Generic pattern-based labeling
    patterns = [
        ('CARD', e['card']),
        ('PHONE', e['phone']),
        ('OTP', e['otp']),
        ('EMAIL', e['email']),
        ('PAN', e['pan']),
        ('IP', e['ip']),
        ('URL', e['url']),
        ('PERSON', e['person']),
    ]

    for etype, value in patterns:
        if value in text:
            i = text.find(value)
            labels[i] = f"B-{etype}"
            for j in range(1, len(value)):
                labels[i+j] = f"I-{etype}"
    return labels

corpus = build_corpus()
with open("data/corpus/train.jsonl", "w") as f:
    for rec in corpus:
        f.write(json.dumps(rec) + "\n")

# Show what was generated
print(f"Wrote {len(corpus)} records")
for i, r in enumerate(corpus):
    print(f"  {i}: {r['text'][:80]}... -> {r['labels']}")
