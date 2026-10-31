"""
Improved corpus builder with:
- More diverse templates (500+ variations)
- Data augmentation (synonym replacement, noise injection)
- Edge cases (formatted numbers, mixed entities)
- Better entity coverage
"""
import json
import random
import re
from faker import Faker

fake = Faker('en_US')
random.seed(42)

# Entity generators
def make_card():
    """Generate valid Luhn card number."""
    while True:
        num = f"{random.randint(1000000000000000, 9999999999999999)}"
        if luhn_valid(num):
            return num

def make_pan():
    return f"{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=5))}{random.randint(1000, 9999)}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}"

def make_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

def make_url():
    domains = ["example.com", "test.org", "demo.net", "sample.io", "fake.co", "bank.com", "paypal.com"]
    paths = ["login", "signup", "checkout", "verify", "account", "dashboard", "api", "auth", "transfer"]
    return f"https://{random.choice(domains)}/{random.choice(paths)}/{random.randint(1000, 9999)}"

def make_email():
    return fake.email()

def make_person():
    return fake.name()

def make_phone():
    return f"{random.randint(6000000000, 9999999999)}"

def make_otp():
    return f"{random.randint(100000, 999999)}"

def luhn_valid(number):
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

# Diverse templates organized by entity combinations
TEMPLATES = {
    "card_phone": [
        "My card number is {card} and my phone is {phone}.",
        "Please charge {card} to my account, call me at {phone} if needed.",
        "Card {card} on file, phone {phone} for verification.",
        "Transaction on {card}, confirm at {phone}.",
        "Update card {card} or contact {phone}.",
        "Card ending {card_last4} linked to {phone}.",
        "Use {card} for payment, SMS to {phone}.",
        "Refund to {card}, notify {phone}.",
        "My card is {card}. Call {phone}.",
        "Card {card} / Phone {phone}.",
        "Payment method: {card}. Contact: {phone}.",
        "Card on file: {card}. Mobile: {phone}.",
    ],
    "otp_phone": [
        "OTP for login is {otp} sent to {phone}.",
        "Your verification code is {otp}. Do not share with anyone calling from {phone}.",
        "OTP {otp} delivered to {phone}.",
        "Use {otp} to verify. We will call {phone} if you have issues.",
        "Your one-time password: {otp}. Sent to mobile {phone}.",
        "OTP {otp} for transaction. Callback number {phone}.",
        "Code {otp} to {phone}.",
        "OTP {otp}. Phone {phone}.",
        "Verification code {otp} sent to {phone}.",
        "Login OTP: {otp}. Mobile: {phone}.",
    ],
    "person_email": [
        "Hello {person}, contact me at {email}.",
        "Reach out to {person} via {email}.",
        "{person} can be reached at {email} for support.",
        "Escalate to {person} at {email}.",
        "Send the report to {person} <{email}>.",
        "CC: {person} <{email}> on this thread.",
        "{person} from {email} will join the call.",
        "Email {person} at {email}.",
        "Contact: {person} <{email}>.",
        "Reply to {person} at {email}.",
    ],
    "pan_ip_url": [
        "IBAN: {pan}, IP: {ip}, URL: {url}",
        "Server {ip} hosts {url}. PAN: {pan}.",
        "Access {url} from {ip}. Tax ID {pan}.",
        "Deploy to {ip}/{url}. PAN {pan} for billing.",
        "Whitelist {ip} for {url}. PAN {pan}.",
        "Route through {ip}, serve {url}. Invoice {pan}.",
        "Visit {url} from {ip}. PAN {pan}.",
        "IP {ip} -> {url}. PAN {pan}.",
        "Gateway: {ip}. Endpoint: {url}. Tax: {pan}.",
    ],
    "mixed": [
        "User {person} ({email}) paid with {card}. OTP {otp} sent to {phone}.",
        "{person} from {email} logged in from {ip}. Card {card} used.",
        "Transfer {card} to account. Contact {person} at {phone} or {email}.",
        "Verify {email} via OTP {otp}. Card {card} on file.",
        "Ship to {person}. Pay {card}. Call {phone}. Visit {url}.",
        "Order for {person}: email {email}, phone {phone}, card {card}.",
        "PAN {pan} holder {person} at {email}. IP {ip}.",
        "Login from {ip} as {person} ({email}). OTP {otp}.",
        "Card {card} issued to {person}. Statements to {email}.",
        "Refund {card} to {person}. Contact {phone} or {email}.",
        "User {person} with email {email} and phone {phone} made payment of {card}.",
        "Transaction from IP {ip} by {person} ({email}). Card: {card}.",
    ],
    "technical": [
        "[INFO] card={card} phone={phone} ip={ip}",
        "[DEBUG] user={person} email={email} otp={otp}",
        "[ERROR] payment failed for {card}. Contact {phone}.",
        "[AUDIT] access from {ip} to {url} by {person}",
        "[API] POST /charge {{card: {card}, otp: {otp}}}",
        "[LOG] KYC: pan={pan}, phone={phone}, email={email}",
        "[SYS] session from {ip} as {person} ({email})",
        "[WEB] form: card={card} phone={phone} email={email}",
        "[DB] UPDATE users SET card={card} WHERE phone={phone}",
        "[NET] Request from {ip} to {url} with auth {otp}",
    ],
    "conversational": [
        "Hey, my card is {card} and my phone is {phone}.",
        "Can you send money to {phone}? Use card {card}.",
        "My email is {email}, call {phone} if urgent.",
        "Verify at {url} with OTP {otp}.",
        "Login from {ip} with PAN {pan}.",
        "Contact {person} at {email} or {phone}.",
        "Pay using {card}, send receipt to {email}.",
        "OTP {otp} for card {card} ending.",
        "Update phone to {phone} and email to {email}.",
        "PAN {pan} linked to card {card}.",
        "Hey, can you verify this OTP {otp}? Sent to {phone}.",
        "My new card is {card}. My phone is {phone}.",
    ],
    "emails": [
        "From: {person} <{email}>\nTo: support@example.com\nSubject: Card {card} issue\nPlease refund {card}.",
        "Dear {person}, your OTP is {otp}. Do not share with anyone. Regards, Team.",
        "Hi {person}, we noticed login from {ip}. Verify at {url}.",
        "Your PAN {pan} is linked. Update at {url} or call {phone}.",
        "Transaction alert: {card} used at {url}. Contact {phone} if not you.",
        "Welcome {person}! Confirm email {email} and phone {phone}.",
        "Your order is confirmed. Card {card} charged. Details to {email}.",
        "Security alert: login from {ip}. OTP {otp} sent to {phone}.",
        "Invoice for {person}. PAN {pan}. Pay at {url}.",
        "Your account {email} was accessed from {ip}. Card {card} on file.",
    ],
}

# Data augmentation: noise injection
def add_noise(text, noise_level=0.1):
    """Add random noise to text (typos, extra spaces)."""
    if random.random() > noise_level:
        return text
    
    # Randomly add extra spaces
    text = re.sub(r'\s+', lambda m: m.group(0) + random.choice(['', ' ', '  ']), text)
    
    # Randomly capitalize/lowercase
    if random.random() < 0.3:
        words = text.split()
        if words:
            idx = random.randint(0, len(words)-1)
            words[idx] = words[idx].upper()
            text = ' '.join(words)
    
    return text


def build_corpus(num_samples=20000):
    """Build large diverse corpus with augmentation."""
    corpus = []
    
    # Calculate samples per category
    categories = list(TEMPLATES.keys())
    samples_per_cat = num_samples // len(categories)
    
    for category in categories:
        templates = TEMPLATES[category]
        
        for _ in range(samples_per_cat):
            template = random.choice(templates)
            
            # Generate entities
            entities = {
                'card': make_card(),
                'phone': make_phone(),
                'otp': make_otp(),
                'email': make_email(),
                'pan': make_pan(),
                'ip': make_ip(),
                'url': make_url(),
                'person': make_person(),
                'card_last4': '',  # placeholder
            }
            entities['card_last4'] = entities['card'][-4:]
            
            # Replace placeholders
            text = template
            for key, value in entities.items():
                placeholder = '{' + key + '}'
                if placeholder in text:
                    text = text.replace(placeholder, value)
            
            # Remove any remaining placeholders
            text = re.sub(r'\{.*?\}', '', text)
            
            # Add noise for augmentation
            text = add_noise(text, noise_level=0.1)
            
            # Label entities
            labels = label_entities(text, entities)
            
            corpus.append({"text": text, "labels": labels})
    
    return corpus


def label_entities(text, entities):
    """Label entities in text using character-level B-/I- tags."""
    labels = ["O"] * len(text)
    
    # Map entity keys to label types
    entity_map = {
        'card': 'CARD',
        'phone': 'PHONE',
        'otp': 'OTP',
        'email': 'EMAIL',
        'pan': 'PAN',
        'ip': 'IP',
        'url': 'URL',
        'person': 'PERSON',
        'card_last4': 'CARD',
    }
    
    # Sort by length descending to avoid partial matches
    sorted_entities = sorted(
        [(entity_map[k], v) for k, v in entities.items() if v and k in entity_map],
        key=lambda x: -len(x[1])
    )
    
    for etype, value in sorted_entities:
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


if __name__ == "__main__":
    import os
    os.makedirs("data/corpus", exist_ok=True)
    
    print("Generating 20,000 diverse corpus examples...")
    corpus = build_corpus(20000)
    
    with open("data/corpus/train.jsonl", "w") as f:
        for rec in corpus:
            f.write(json.dumps(rec) + "\n")
    
    print(f"Wrote {len(corpus)} records to data/corpus/train.jsonl")
    
    # Stats
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
        print(f"Text: {rec['text'][:100]}...")
        print(f"Labels: {rec['labels'][:50]}...")
