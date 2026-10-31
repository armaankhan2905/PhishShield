import json
import random
import re
from faker import Faker

fake = Faker('en_US')
random.seed(42)

# Entity generators with validation
def make_card():
    """Generate valid Luhn card number."""
    while True:
        num = f"{random.randint(1000000000000000, 9999999999999999)}"
        if validate_luhn(num):
            return num

def make_pan():
    """Generate valid PAN format: ABCDE1234F."""
    return f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=5))}{random.randint(1000, 9999)}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}"

def make_ip():
    """Generate valid IPv4."""
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def make_url():
    """Generate realistic URLs."""
    domains = ["example.com", "test.org", "demo.net", "sample.io", "fake.co"]
    paths = ["login", "signup", "checkout", "verify", "account", "dashboard", "api", "auth"]
    return f"https://{random.choice(domains)}/{random.choice(paths)}/{random.randint(1000, 9999)}"

def make_email():
    """Generate realistic emails."""
    return fake.email()

def make_person():
    """Generate realistic names."""
    return fake.name()

def make_phone():
    """Generate Indian phone numbers (10 digits, start 6-9)."""
    return f"{random.randint(6000000000, 9999999999)}"

def make_otp():
    """Generate 4-8 digit OTP."""
    return f"{random.randint(1000, 99999999)}"

def validate_luhn(number):
    """Luhn algorithm check."""
    digits = [int(d) for d in number]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0

# Templates organized by entity types they contain
TEMPLATES = [
    # CARD + PHONE
    "My card number is {{card}} and my phone is {{phone}}.",
    "Please charge {{card}} to my account, call me at {{phone}} if needed.",
    "Card {{card}} on file, phone {{phone}} for verification.",
    "Transaction on {{card}}, confirm at {{phone}}.",
    "Update card {{card}} or contact {{phone}}.",
    "Card ending {{card[-4:]}} linked to {{phone}}.",
    "Use {{card}} for payment, SMS to {{phone}}.",
    "Refund to {{card}}, notify {{phone}}.",
    
    # OTP + PHONE
    "OTP for login is {{otp}} sent to {{phone}}.",
    "Your verification code is {{otp}}. Do not share with anyone calling from {{phone}}.",
    "OTP {{otp}} delivered to {{phone}}.",
    "Use {{otp}} to verify. We will call {{phone}} if you have issues.",
    "Your one-time password: {{otp}}. Sent to mobile {{phone}}.",
    "OTP {{otp}} for transaction. Callback number {{phone}}.",
    
    # PERSON + EMAIL
    "Hello {{person}}, contact me at {{email}}.",
    "Reach out to {{person}} via {{email}}.",
    "{{person}} can be reached at {{email}} for support.",
    "Escalate to {{person}} at {{email}}.",
    "Send the report to {{person}} <{{email}}>.",
    "CC: {{person}} <{{email}}> on this thread.",
    "{{person}} from {{email}} will join the call.",
    
    # PAN + IP + URL
    "IBAN: {{pan}}, IP: {{ip}}, URL: {{url}}",
    "Server {{ip}} hosts {{url}}. PAN: {{pan}}.",
    "Access {{url}} from {{ip}}. Tax ID {{pan}}.",
    "Deploy to {{ip}}/{{url}}. PAN {{pan}} for billing.",
    "Whitelist {{ip}} for {{url}}. PAN {{pan}}.",
    "Route through {{ip}}, serve {{url}}. Invoice {{pan}}.",
    
    # CARD + PHONE (device context)
    "Device sent {{card}} and {{phone}} to server.",
    "App submitted {{card}} and {{phone}} for KYC.",
    "Form values: card={{card}}, phone={{phone}}.",
    "POST data contains {{card}} and {{phone}}.",
    "Request body: card={{card}}, mobile={{phone}}.",
    "Wallet stored {{card}} and {{phone}}.",
    "Checkout: card={{card}}, phone={{phone}}.",
    
    # OTP + EMAIL
    "OTP {{otp}} sent to {{email}}.",
    "Verify with {{otp}}. We emailed {{email}}.",
    "Code {{otp}} delivered to {{email}}.",
    "Reset link to {{email}}. OTP {{otp}}.",
    "OTP {{otp}} for {{email}}.",
    "Email {{email}} received code {{otp}}.",
    
    # Mixed entities
    "User {{person}} ({{email}}) paid with {{card}}. OTP {{otp}} sent to {{phone}}.",
    "{{person}} from {{email}} logged in from {{ip}}. Card {{card}} used.",
    "Transfer {{card}} to account. Contact {{person}} at {{phone}} or {{email}}.",
    "Verify {{email}} via OTP {{otp}}. Card {{card}} on file.",
    "Ship to {{person}}. Pay {{card}}. Call {{phone}}. Visit {{url}}.",
    "Order for {{person}}: email {{email}}, phone {{phone}}, card {{card}}.",
    "PAN {{pan}} holder {{person}} at {{email}}. IP {{ip}}.",
    "Login from {{ip}} as {{person}} ({{email}}). OTP {{otp}}.",
    "Card {{card}} issued to {{person}}. Statements to {{email}}.",
    "Refund {{card}} to {{person}}. Contact {{phone}} or {{email}}.",
    
    # Short messages
    "Card: {{card}}.",
    "OTP: {{otp}}.",
    "Phone: {{phone}}.",
    "Email: {{email}}.",
    "PAN: {{pan}}.",
    "IP: {{ip}}.",
    "URL: {{url}}.",
    "Name: {{person}}.",
    
    # Conversational
    "Hey, my card is {{card}} and my phone is {{phone}}.",
    "Can you send money to {{phone}}? Use card {{card}}.",
    "My email is {{email}}, call {{phone}} if urgent.",
    "Verify at {{url}} with OTP {{otp}}.",
    "Login from {{ip}} with PAN {{pan}}.",
    "Contact {{person}} at {{email}} or {{phone}}.",
    "Pay using {{card}}, send receipt to {{email}}.",
    "OTP {{otp}} for card {{card}} ending.",
    "Update phone to {{phone}} and email to {{email}}.",
    "PAN {{pan}} linked to card {{card}}.",
    
    # Technical / logs
    "[INFO] card={{card}} phone={{phone}} ip={{ip}}",
    "[DEBUG] user={{person}} email={{email}} otp={{otp}}",
    "[ERROR] payment failed for {{card}}. Contact {{phone}}.",
    "[AUDIT] access from {{ip}} to {{url}} by {{person}}",
    "[API] POST /charge {card: {{card}}, otp: {{otp}}}",
    "[LOG] KYC: pan={{pan}}, phone={{phone}}, email={{email}}",
    "[SYS] session from {{ip}} as {{person}} ({{email}})",
    "[WEB] form: card={{card}} phone={{phone}} email={{email}}",
    
    # Emails / messages
    "From: {{person}} <{{email}}>\\nTo: support@example.com\\nSubject: Card {{card}} issue\\nPlease refund {{card}}.",
    "Dear {{person}}, your OTP is {{otp}}. Do not share with anyone. Regards, Team.",
    "Hi {{person}}, we noticed login from {{ip}}. Verify at {{url}}.",
    "Your PAN {{pan}} is linked. Update at {{url}} or call {{phone}}.",
    "Transaction alert: {{card}} used at {{url}}. Contact {{phone}} if not you.",
    "Welcome {{person}}! Confirm email {{email}} and phone {{phone}}.",
    "Your order is confirmed. Card {{card}} charged. Details to {{email}}.",
    "Security alert: login from {{ip}}. OTP {{otp}} sent to {{phone}}.",
    "Invoice for {{person}}. PAN {{pan}}. Pay at {{url}}.",
    "Your account {{email}} was accessed from {{ip}}. Card {{card}} on file.",
]

def label_entities(text, e):
    """Label entities in text using character-level B-/I- tags."""
    labels = ["O"] * len(text)
    
    # Map lowercase keys to uppercase entity types
    entity_type_map = {
        'card': 'CARD',
        'phone': 'PHONE',
        'otp': 'OTP',
        'email': 'EMAIL',
        'pan': 'PAN',
        'ip': 'IP',
        'url': 'URL',
        'person': 'PERSON',
        'card[-4:]': 'CARD',
    }
    
    # Sort by length descending to avoid partial matches
    entities = [(entity_type_map.get(k, k.upper()), v) for k, v in e.items() if v is not None]
    entities.sort(key=lambda x: -len(x[1]))
    
    for etype, value in entities:
        start = 0
        while True:
            idx = text.find(value, start)
            if idx == -1:
                break
            # Check if already labeled (avoid overlaps)
            if all(labels[i] == "O" for i in range(idx, idx + len(value))):
                labels[idx] = f"B-{etype}"
                for j in range(1, len(value)):
                    labels[idx + j] = f"I-{etype}"
            start = idx + 1
    
    return labels

def build_large_corpus(num_samples=10000):
    """Build large corpus with variations."""
    corpus = []
    
    # Base templates with entity placeholders
    base_templates = [
        "My card number is {{card}} and my phone is {{phone}}.",
        "OTP for login is {{otp}} sent to {{phone}}.",
        "Hello {{person}}, contact me at {{email}}.",
        "PAN: {{pan}}, IP: {{ip}}, URL: {{url}}",
        "Device sent {{card}} and {{phone}} to server.",
    ]
    
    # Variations for each template type
    variations = {
        "card_phone": [
            "My card number is {{card}} and my phone is {{phone}}.",
            "Please charge {{card}} to my account, call me at {{phone}} if needed.",
            "Card {{card}} on file, phone {{phone}} for verification.",
            "Transaction on {{card}}, confirm at {{phone}}.",
            "Update card {{card}} or contact {{phone}}.",
            "Card ending {{card[-4:]}} linked to {{phone}}.",
            "Use {{card}} for payment, SMS to {{phone}}.",
            "Refund to {{card}}, notify {{phone}}.",
            "My card is {{card}}. Call {{phone}}.",
            "Card {{card}} / Phone {{phone}}.",
        ],
        "otp_phone": [
            "OTP for login is {{otp}} sent to {{phone}}.",
            "Your verification code is {{otp}}. Do not share with anyone calling from {{phone}}.",
            "OTP {{otp}} delivered to {{phone}}.",
            "Use {{otp}} to verify. We will call {{phone}} if you have issues.",
            "Your one-time password: {{otp}}. Sent to mobile {{phone}}.",
            "OTP {{otp}} for transaction. Callback number {{phone}}.",
            "Code {{otp}} to {{phone}}.",
            "OTP {{otp}}. Phone {{phone}}.",
        ],
        "person_email": [
            "Hello {{person}}, contact me at {{email}}.",
            "Reach out to {{person}} via {{email}}.",
            "{{person}} can be reached at {{email}} for support.",
            "Escalate to {{person}} at {{email}}.",
            "Send the report to {{person}} <{{email}}>.",
            "CC: {{person}} <{{email}}> on this thread.",
            "{{person}} from {{email}} will join the call.",
            "Email {{person}} at {{email}}.",
            "Contact: {{person}} <{{email}}>.",
        ],
        "pan_ip_url": [
            "IBAN: {{pan}}, IP: {{ip}}, URL: {{url}}",
            "Server {{ip}} hosts {{url}}. PAN: {{pan}}.",
            "Access {{url}} from {{ip}}. Tax ID {{pan}}.",
            "Deploy to {{ip}}/{{url}}. PAN {{pan}} for billing.",
            "Whitelist {{ip}} for {{url}}. PAN {{pan}}.",
            "Route through {{ip}}, serve {{url}}. Invoice {{pan}}.",
            "Visit {{url}} from {{ip}}. PAN {{pan}}.",
            "IP {{ip}} → {{url}}. PAN {{pan}}.",
        ],
        "mixed": [
            "User {{person}} ({{email}}) paid with {{card}}. OTP {{otp}} sent to {{phone}}.",
            "{{person}} from {{email}} logged in from {{ip}}. Card {{card}} used.",
            "Transfer {{card}} to account. Contact {{person}} at {{phone}} or {{email}}.",
            "Verify {{email}} via OTP {{otp}}. Card {{card}} on file.",
            "Ship to {{person}}. Pay {{card}}. Call {{phone}}. Visit {{url}}.",
            "Order for {{person}}: email {{email}}, phone {{phone}}, card {{card}}.",
            "PAN {{pan}} holder {{person}} at {{email}}. IP {{ip}}.",
            "Login from {{ip}} as {{person}} ({{email}}). OTP {{otp}}.",
            "Card {{card}} issued to {{person}}. Statements to {{email}}.",
            "Refund {{card}} to {{person}}. Contact {{phone}} or {{email}}.",
        ]
    }
    
    # Generate samples
    for _ in range(num_samples):
        # Pick a random variation type
        var_type = random.choice(list(variations.keys()))
        template = random.choice(variations[var_type])
        
        # Generate entities
        e = {
            'card': make_card(),
            'phone': make_phone(),
            'otp': make_otp(),
            'email': make_email(),
            'pan': make_pan(),
            'ip': make_ip(),
            'url': make_url(),
            'person': make_person(),
            'card[-4:]': None,  # placeholder
        }
        e['card[-4:]'] = e['card'][-4:]
        
        # Replace placeholders
        text = template
        for k, v in e.items():
            if '{{' + k + '}}' in text:
                text = text.replace('{{' + k + '}}', v)
        
        # Remove any remaining placeholders
        text = re.sub(r'\{\{.*?\}\}', '', text)
        
        # Label entities
        labels = label_entities(text, e)
        
        corpus.append({"text": text, "labels": labels})
    
    return corpus

if __name__ == "__main__":
    import os
    os.makedirs("data/corpus", exist_ok=True)
    
    print("Generating 10,000 corpus examples...")
    corpus = build_large_corpus(10000)
    
    with open("data/corpus/train.jsonl", "w") as f:
        for rec in corpus:
            f.write(json.dumps(rec) + "\n")
    
    print(f"Wrote {len(corpus)} records to data/corpus/train.jsonl")
    
    # Show stats
    entity_counts = {}
    for rec in corpus:
        for label in rec["labels"]:
            if label != "O":
                entity_counts[label] = entity_counts.get(label, 0) + 1
    
    print("\nEntity distribution:")
    for label, count in sorted(entity_counts.items()):
        print(f"  {label}: {count}")
    
    print("\nSample records:")
    for i in [0, 1, 2]:
        rec = corpus[i]
        print(f"\n--- Record {i} ---")
        print(f"Text: {rec['text']}")
        print(f"Labels: {rec['labels']}")
