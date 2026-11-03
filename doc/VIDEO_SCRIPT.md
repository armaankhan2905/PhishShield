# PhishShield demo video: script and shot list

**Length:** 2:45 (stay under 3:00). **Format:** 1920×1080 screen recording + voice-over, no music needed.
**Record with:** OBS Studio or the Windows Snipping Tool's screen recorder (Win + Shift + R). Record each shot separately and join them; retakes are easier.

**Setup before recording:**
- Server running in local mode with `GROQ_API_KEY` set.
- Browser zoom 125% so text is readable at 1080p.
- Dark or light theme, but the same for every shot.
- Close other tabs and notifications.
- The extension loaded in real Chrome, and the sample emails from `demo/samples/` in a test Gmail inbox.

| # | Time | Shot (what's on screen) | Voice-over | On-screen caption |
|---|---|---|---|---|
| 1 | 0:00–0:12 | A phone-style SMS: "URGENT: your SBI KYC is pending…" (`/?sample=sbi-kyc-sms` text, zoomed) | "This message reaches millions of Indians. It looks official. It isn't." | PhishShield · The Cupids · Graviton 2026 |
| 2 | 0:12–0:40 | `/?sample=sbi-kyc-sms`: result appears, scroll slowly through **Why** | "PhishShield checks it in milliseconds. Phishing, 100 out of 100, and every point has a reason. The link is on `sbi-kyc.xyz`, which isn't an SBI domain, and the message asks for your details through it. Those are proven facts, not guesses." | Proven · Pattern · Model |
| 3 | 0:40–0:55 | Scroll to **Explanation** | "An AI model explains it in plain words. It only sees what the checks found, with personal details removed." | Redacted copy only · nothing stored |
| 4 | 0:55–1:15 | `/?sample=bank-otp-alert`, then `/?sample=kyc-reminder` | "Just as important: real messages stay green. A bank OTP that says *don't share* is a warning, not a request. An urgent KYC reminder with nothing to click stays safe." | Low false alarms |
| 5 | 1:15–1:40 | Upload tab → drop `demo/samples/hdfc-suspended.eml` | "Saved emails work too. This link *shows* hdfcbank.com but goes somewhere else. Hidden text meant to fool filters is ignored, and the attachment is never opened." | Link text ≠ real link |
| 6 | 1:40–2:05 | Real Gmail: open the SBI email (red banner), then the HDFC statement (green) | "And it works inside Gmail. Open an email and PhishShield checks it automatically, right above the message." | Chrome extension |
| 7 | 2:05–2:30 | `/results`: hold on the tiles, then scroll the table | "We measured it on data it never saw. Email F1 0.94. Links: 98% precision with under 1% false alarms. On 3,630 ordinary text messages, one false alarm. Every number here is generated, not typed." | Measured on held-out data |
| 8 | 2:30–2:45 | `/how-it-works` → Privacy, then the logo | "Explainable, measured, and private by default. PhishShield." | github.com/armaankhan2905/PhishShield |

**After recording:**
- Every number in the voice-over must match `/results` (`metrics_sha256 ca1d8651…`).
- Don't show real personal emails or the test inbox's address book.
- Export as MP4 (H.264), under 100 MB.

**If the real-Gmail shot isn't possible:** record shot 6 on the Gmail test page (`python -m src.pipeline.demo --dev` → `/dev/extension/dev/gmail.html`) and caption it **"Extension on a Gmail test page"**. Don't present it as real Gmail.
