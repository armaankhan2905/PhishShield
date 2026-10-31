"""Template-generated Indian SMS (legitimate alerts and scams) for training only.

Owner: Govind. The public SMS corpora are casual UK chat and spam, so the text
model reads ordinary Indian bank alerts (amounts, masked accounts, OTPs) as
spam. These templates add both classes in the same transactional style, so the
model has to learn the wording that separates them (requests, threats, prizes)
rather than "has amounts = phishing".

Limits: synthetic, written by the project team, and used in the TRAIN split
only. They are never used for validation, calibration or reported accuracy.
Real, redacted messages collected by the team should replace them.
"""
from __future__ import annotations

import random
from typing import List

BANKS = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Bank", "PNB", "Bank of Baroda", "Canara Bank", "Yes Bank", "IDFC FIRST Bank"]
MERCHANTS = ["AMAZON", "FLIPKART", "SWIGGY", "ZOMATO", "BIGBASKET", "IRCTC", "UBER", "OLA", "MYNTRA", "BOOKMYSHOW", "DMART", "JIO"]
APPS = ["Paytm", "PhonePe", "Google Pay", "BHIM", "Amazon Pay", "CRED"]
COURIERS = ["Delhivery", "Blue Dart", "Ekart", "India Post", "DTDC", "Xpressbees"]
NAMES = ["Ramesh", "Priya", "Anil Kumar", "Sneha", "Mohammed Irfan", "Kavita", "Rahul", "Deepa", "Suresh", "Neha"]
OFFICIAL = ["https://www.onlinesbi.sbi", "https://www.hdfcbank.com", "https://www.icicibank.com", "https://www.amazon.in/orders",
            "https://www.flipkart.com/account", "https://www.irctc.co.in", "https://www.incometax.gov.in"]
SHADY = ["http://sbi-kyc-update.xyz", "https://hdfc-reward.top/claim", "http://bit.ly/3xKyc9", "https://icici-secure.info/login",
         "http://paytm-kyc.online", "https://indiapost-track.top/pay", "http://refund-incometax.site", "https://tinyurl.com/kyc-upd8"]


def _amt(r): return f"{r.choice(['Rs', 'Rs.', 'INR', '₹'])} {r.choice([99, 120, 249, 499, 1250, 2300, 4999, 15000, 25000])}{r.choice(['', '.00'])}"
def _acct(r): return f"{r.choice(['A/c', 'a/c', 'Acct'])} {r.choice(['XX', '**', 'X'])}{r.randint(1000, 9999)}"
def _date(r): return f"{r.randint(1, 28):02d}-{r.choice(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])}-{r.choice([24, 25])}"
def _otp(r): return str(r.randint(100000, 999999))
def _mobile(r): return f"{r.choice([6, 7, 8, 9])}{r.randint(100000000, 999999999)}"
def _ref(r): return str(r.randint(10**11, 10**12 - 1))


LEGIT = [
    lambda r: f"{_amt(r)} debited from {_acct(r)} on {_date(r)} to {r.choice(MERCHANTS)}. Avl bal {_amt(r)}. Not you? Call 1800{r.randint(1000000, 9999999)} -{r.choice(BANKS)}",
    lambda r: f"Dear Customer, your {_acct(r)} is credited with {_amt(r)} on {_date(r)} by UPI ref {_ref(r)}. -{r.choice(BANKS)}",
    lambda r: f"{_otp(r)} is your OTP for transaction of {_amt(r)} at {r.choice(MERCHANTS)}. Valid for 5 mins. Do not share this OTP with anyone. -{r.choice(BANKS)}",
    lambda r: f"OTP for login is {_otp(r)}. Never share your OTP, PIN or password with anyone. {r.choice(BANKS)} never asks for these.",
    lambda r: f"Your {r.choice(BANKS)} Credit Card XX{r.randint(1000, 9999)} was used for {_amt(r)} at {r.choice(MERCHANTS)} on {_date(r)}. If not done by you, block the card from the mobile app.",
    lambda r: f"EMI of {_amt(r)} for loan {_acct(r)} is due on {_date(r)}. Please maintain sufficient balance. -{r.choice(BANKS)}",
    lambda r: f"Payment of {_amt(r)} to {r.choice(NAMES)} successful via {r.choice(APPS)}. UPI Ref No {_ref(r)}.",
    lambda r: f"Your order from {r.choice(MERCHANTS).title()} has been shipped and will be delivered by {_date(r)}. Track it in the app.",
    lambda r: f"Your {r.choice(COURIERS)} shipment AWB {r.randint(10**9, 10**10)} is out for delivery today. Delivery partner will call before arriving.",
    lambda r: f"Recharge of {_amt(r)} on your number is successful. Validity till {_date(r)}. Thank you for choosing {r.choice(['Jio', 'Airtel', 'Vi'])}.",
    lambda r: f"PNR {r.randint(10**9, 10**10)}: Train {r.randint(10000, 22999)} coach B{r.randint(1, 6)} seat {r.randint(1, 72)} confirmed for {_date(r)}. Happy journey -IRCTC",
    lambda r: f"Your ITR for AY 2024-25 has been processed. Refund of {_amt(r)} will be credited to your pre-validated bank account.",
    lambda r: f"Statement for your {r.choice(BANKS)} credit card is ready. Total due {_amt(r)}, payment due date {_date(r)}. Visit {r.choice(OFFICIAL)}",
    lambda r: f"Your KYC has been successfully updated. Thank you for banking with {r.choice(BANKS)}.",
    lambda r: f"Dear Customer, cheque no {r.randint(100000, 999999)} for {_amt(r)} has been cleared on {_date(r)}. -{r.choice(BANKS)}",
    lambda r: f"Your {r.choice(MERCHANTS).title()} order is out for delivery. Share OTP {r.randint(1000, 9999)} with the delivery partner only at the time of delivery.",
    lambda r: f"Your account balance on {_date(r)} is {_amt(r)}. For details visit {r.choice(OFFICIAL)} or the mobile app. -{r.choice(BANKS)}",
    lambda r: f"Hi {r.choice(NAMES)}, your appointment at the clinic is confirmed for {_date(r)} at {r.randint(9, 18)}:00. Reply C to cancel.",
    lambda r: f"Your electricity bill of {_amt(r)} for {r.choice(['Oct', 'Nov', 'Sep'])} is generated. Due date {_date(r)}. Pay via your bank app or the official portal.",
    lambda r: f"FD of {_amt(r)} booked in your {_acct(r)} at 7.1% p.a. Maturity {_date(r)}. -{r.choice(BANKS)}",
]

SCAM = [
    lambda r: f"Dear Customer, your {r.choice(BANKS)} account will be blocked today. Update your KYC immediately at {r.choice(SHADY)}",
    lambda r: f"Your {r.choice(BANKS)} netbanking is suspended. Verify your PAN at {r.choice(SHADY)} within 24 hours to avoid blocking.",
    lambda r: f"Congratulations! You have won {_amt(r)} in the {r.choice(['KBC', 'Jio', 'Airtel'])} lucky draw. Pay {_amt(r)} processing fee to claim your prize.",
    lambda r: f"Your electricity connection will be disconnected tonight at 9.30 PM as your bill is not updated. Call our officer {_mobile(r)} immediately.",
    lambda r: f"{r.choice(BANKS)} reward points worth {_amt(r)} expire today. Redeem now at {r.choice(SHADY)}",
    lambda r: f"Income tax refund of {_amt(r)} approved. Submit your bank account details at {r.choice(SHADY)} to receive it.",
    lambda r: f"Part time job offer! Earn {_amt(r)} per day by liking videos. WhatsApp {_mobile(r)} to start.",
    lambda r: f"Your {r.choice(COURIERS)} parcel is on hold due to incomplete address. Pay {_amt(r)} redelivery fee at {r.choice(SHADY)}",
    lambda r: f"Your parcel contains illegal items and a case is registered. Call {_mobile(r)} immediately to avoid arrest.",
    lambda r: f"Dear user, your {r.choice(APPS)} KYC has expired and your wallet will be blocked. Call {_mobile(r)} to complete KYC.",
    lambda r: f"Your Aadhaar is linked to illegal activity. Share your Aadhaar number and OTP with our officer to avoid legal action.",
    lambda r: f"You have a pending traffic challan of {_amt(r)}. Pay now at {r.choice(SHADY)} to avoid penalty.",
    lambda r: f"Hi Mum, I lost my phone, this is my new number. Please send {_amt(r)} urgently, will return tomorrow.",
    lambda r: f"Our bank executive will help you get your refund. Install AnyDesk and share the code shown on your screen.",
    lambda r: f"Your SIM card will be deactivated in 2 hours due to pending e-KYC. Call {_mobile(r)} now.",
    lambda r: f"I have sent {_amt(r)} to your number by mistake, please return it to my UPI {r.choice(NAMES).split()[0].lower()}{r.randint(10, 99)}@ybl.",
    lambda r: f"Dear customer, share the OTP you just received to cancel the wrong transaction of {_amt(r)} from your account.",
    lambda r: f"Your credit card limit increase of {_amt(r)} is approved. Enter your card number and CVV at {r.choice(SHADY)} to activate.",
    lambda r: f"Get a pre-approved loan of {_amt(r)} at 0% interest. Pay {_amt(r)} registration charges to {_mobile(r)} via UPI.",
    lambda r: f"URGENT: Your {r.choice(BANKS)} debit card is blocked. Click {r.choice(SHADY)} and login to unblock.",
]


def generate(n_per_class: int = 1500, seed: int = 7) -> List[dict]:
    r = random.Random(seed)
    rows = []
    for label, templates in ((0, LEGIT), (1, SCAM)):
        for _ in range(n_per_class):
            rows.append({"text": r.choice(templates)(r), "label": label, "source": "synthetic_in", "kind": "sms"})
    return rows
