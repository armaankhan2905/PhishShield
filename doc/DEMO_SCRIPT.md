# PhishShield demo script

**Presenter:** Atharvva (lead) · **Driver at the keyboard:** Ryan · Armaan and Govind take judge questions on detection and models.

Every number below is from `data/eval.json` (`metrics_sha256 e3cf332d…`) and [MODEL_CARD.md](MODEL_CARD.md). Don't round them differently on stage.

## Before you go on (10 minutes before)

| Check | How | Expected |
|---|---|---|
| Server running | `python -m src.pipeline.demo` | Prints `PhishShield (local mode) on http://localhost:8000` |
| Ollama running | `ollama list` shows `qwen2.5:3b` | Header chip: **Local AI explanations** |
| Models loaded | Open http://localhost:8000 | Header: **Running on this computer · Models ready · Local AI explanations** |
| Extension loaded | `chrome://extensions` → PhishShield on; popup says **Server ready** | — |
| Gmail test inbox | The demo emails are already in the inbox, unread | — |
| Tabs open in this order | 1 `/?sample=sbi-kyc-sms` · 2 `/?sample=bank-otp-alert` · 3 `/?sample=kyc-reminder` · 4 `/` (Upload tab) · 5 Gmail · 6 `/results` · 7 `/how-it-works` | — |
| Backup | `doc/screenshots/` open in a folder; a screen recording of this demo on the desktop | — |

Warm the AI model once before the demo (check any phishing sample), since the first answer is slower.

Every sample can also be opened directly: `/?sample=<name>`, where name is `sbi-kyc-sms`, `lottery-fee`, `fake-paypal-email`, `lookalike-link`, `bank-otp-alert`, `amazon-shipping` or `kyc-reminder`.

## 3-minute version

| Time | Screen | Say (roughly) | They should see |
|---|---|---|---|
| 0:00 | Title slide | "Every Indian with a phone has had this SMS. Your KYC is pending, your account will be blocked, click here. PhishShield tells you if it's a scam, and exactly why." | — |
| 0:15 | Tab 1: SBI KYC SMS | "This is a real-style scam. PhishShield says phishing, 100 out of 100. Every point has a reason. These two are **proven**: the link is on `sbi-kyc.xyz`, which isn't an SBI domain, and the message asks for details through it. The models agree, and the risky phrases are highlighted." | Red **Phishing likely**, Proven / Model / Pattern reasons, highlighted text, links table |
| 0:45 | Scroll to Explanation | "This explanation is written by an AI model running **on this laptop**. It only sees the findings and a copy of the message with personal data removed. If it adds anything that wasn't found, we throw it away." | AI explanation + "Written by a local AI model…" |
| 1:00 | Tab 2: Bank OTP alert | "The hard part is not crying wolf. A genuine HDFC OTP alert says 'do not share'. That's a warning, not a request, so it's green." | Green **No phishing signs found · 0/100** |
| 1:10 | Tab 3: KYC reminder | "And 'update your KYC within 24 hours on our official website': urgent, but there's no link, number or payment to act on. Noted, but safe." | Green **29/100**, "Noted, but not enough to flag" |
| 1:25 | Tab 4: Upload `hdfc-suspended.eml` | "Saved emails work too. We read the real sender and reply-to. This link *shows* hdfcbank.com but really goes to a lookalike domain. The hidden text meant to fool filters is ignored, and the attachment isn't opened." | Phishing 100, `LINK_TEXT_MISMATCH`, sender mismatch, "attachments not opened" |
| 1:50 | Tab 5: Gmail | "Same engine, inside Gmail. Open the scam email and the banner appears above it, with the reasons. Open a real bank email and it's green." | Red banner on the scam; green on the real email |
| 2:15 | Tab 6: Results | "We measured it on data it never trained on. Emails F1 0.94. Links: 98% precision with 0.8% false alarms. On 3,630 ordinary SMS it raised **one** false alarm. We chose fewer false alarms over catching every last scam, and we show the trade-off." | Headline tiles |
| 2:40 | Tab 7: How it works → Privacy | "Everything you saw ran on this laptop. Nothing is stored or logged, and the hosted demo says so on every page when it isn't local." | Privacy section |
| 2:55 | Closing slide | "PhishShield: explainable, local, measured. Thank you." | — |

## 5-minute version (if you have time)

Add between 1:25 and 1:50:
- **Fake PayPal email** (`/?sample=fake-paypal-email`): sender `paypa1-security.com`, reply-to Gmail. Point at the **Proven** labels for the look-alike sender and the reply-to mismatch.
- **Lookalike link** (`/?sample=lookalike-link`): `amaz0n-refund.in`. "Zero instead of o, plus 'refund'. We fold look-alike characters before comparing with 37 brands."

Add after the Results page:
- **The trade-off, honestly:** "The old weighted formula from our first plan catches more SMS: F1 0.92 vs 0.77. But it raised 198 false alarms on those 3,630 ordinary messages; we raise one. Our 'phishing' verdict needs proven technical evidence, so a model alone can only say 'suspicious'."
- **Extension on any website:** open `link-outlines`; risky links are outlined with reasons on hover.

## If something goes wrong

| Problem | Do this |
|---|---|
| AI explanation is slow or missing | Keep talking. The plain summary is already there, and the label says why. Say: "Without the local model we fall back to a summary built from the same findings." |
| Server crashes | Restart: `python -m src.pipeline.demo` (about 5 s to load models). Meanwhile, show the screenshots in `doc/screenshots/`. |
| Gmail banner doesn't appear | Use the Gmail test page: `python -m src.pipeline.demo --dev`, then http://localhost:8000/dev/extension/dev/gmail.html. Say it's the same extension code on a test copy of Gmail. |
| No internet | Nothing changes: everything runs locally. Skip Render. |
| A judge pastes their own message | Let them. If it's borderline, read the reasons out loud. That's the point of showing them. |

## Don't say
- "100% accurate", "catches all phishing", "on-device" for the hosted demo.
- Indian-message numbers as accuracy: the 36 hand-written messages are synthetic and are only there to show behaviour.
