# Judge Q&A

Short, honest answers. Numbers from `data/eval.json` and [MODEL_CARD.md](MODEL_CARD.md).
Who answers: **A** Armaan (rules, scoring) · **G** Govind (models, evaluation) · **R** Ryan (app, privacy, deploy) · **At** Atharvva (extension, demo).

## Accuracy

**How accurate is it?** (G)
On data it never trained on, flagging "suspicious or phishing":
- **Emails:** F1 0.941 with 4.5% false alarms (n = 2,543).
- **Links:** precision 0.98, recall 0.61, 0.8% false alarms.
- **Recent OpenPhish phishing links on domains we never saw:** 68.5% caught.
- **Popular websites wrongly flagged:** 0.8%.
- **Ordinary SMS wrongly flagged:** 1 in 3,630.

**Why is SMS recall only 0.62?** (A)
We chose not to cry wolf. A message is only rated phishing with proven technical evidence, and wording alone tops out at "suspicious". Many dataset SMS are spam with no link or number to act on, and those stay safe by design. The old weighted formula catches more SMS (F1 0.92) but flags 198 of 3,630 ordinary messages; we flag 1. The trade-off is one setting (`SAFE_BELOW`), tuned on validation data.

**Did you test on the training data?** (G)
No.
- **Splits:** data is split by registered domain for links and by near-duplicate groups for messages; a script checks that no domain or text appears in two splits.
- **Tuning:** scoring was tuned on a separate validation split.
- **Test set:** measured once, and two runs give byte-identical results.
- **Fully held out:** OpenPhish, Tranco and UCI SMS were never used for training at all.

**Where's the Indian data?** (G)
That's our biggest limitation. Public phishing datasets are Western and old (Enron-era email, UK SMS). We added template-generated Indian SMS **to training only**, which fixed the text model rating real bank alerts as phishing. The 36 hand-written Indian test messages are synthetic and only show behaviour; they're not an accuracy claim. Next step: collect real, redacted messages.

**What did you get wrong along the way?** (G)
- **SMS/email labels:** we mislabelled short spam emails as SMS. We fixed it after seeing one test run, and disclosed it in the model card.
- **Unfair comparison:** we had made the old formula look worse on links than it is, then corrected it.
- **Synthetic overlap:** 4 hand-written tests matched training templates, so we removed them.

## How it works

**Isn't this just a keyword filter?** (A)
No. Keywords are the weakest evidence we use, and they're capped. The strong evidence is technical:
- **Link checks:** the link's real owner (Public Suffix List), look-alike characters (`paypa1`, `rnicrosoft`, Cyrillic `а`), brand plus phishing words (`sbi-kyc`), and a brand in front of someone else's domain (`paypal.com.login.ru`).
- **Sender checks:** display name vs sending domain, and link text vs real target.

Plus two calibrated models.

**What do the models do?** (G)
- **URL model:** gradient-boosted trees on 54 spelling features of the link (never visits it).
- **Text model:** TF-IDF + logistic regression on the wording.

Both are calibrated, about 4 MB together, and take milliseconds. A model alone can make a message "suspicious" but never "phishing".

**Why not a big LLM to classify?** (R)
Speed, cost, privacy and explainability. Checks take tens of milliseconds on a laptop with no GPU. The local LLM only *explains*, from findings it can't change, and its answers are rejected if they add anything.

**How do you stop false alarms on real bank messages?** (A)
- **Requests vs mentions:** we look for requests, not mentions ("never share your OTP" is not a request).
- **Something to act on:** a message needs a link, number, app or payment request to go beyond safe.
- **Matching identity:** wording counts half when every link and the sender belong to the brand named.
- **No auto-trust:** no domain is ever trusted automatically, and free hosting sites (Google Forms, GitHub Pages…) are never treated as proof of identity.

## Privacy and deployment

**Does my data leave my computer?** (R)
In local mode, no: the server, both models and the AI explainer run on your machine, and nothing is stored or logged (we test that). The hosted demo is different: messages go to our server, and every page says so.

**What does the extension send?** (At)
Only to the server address you set, by default your own computer. Gmail emails go only when you open them. Link checking on other sites only runs automatically when the server is local, because it sends the page's outgoing links.

**What happens if the AI model or a component is down?** (R)
It degrades visibly, never silently:
- **AI model down:** a plain summary is used.
- **A detection model missing:** that check shows as unavailable and confidence drops. We never show green on partial checks.
- **Server down:** the extension shows grey "Couldn't check this message".

All of this is in 133 automated tests.

**Can it run without internet?** (R)
Yes. Domain parsing uses a bundled Public Suffix List, the models are local files, and links are never fetched.

## Scope

**What doesn't it do?** (R)
- English only.
- No Hindi or Hinglish rules yet.
- Doesn't open links or attachments, and doesn't check domain age or reputation lists. That's deliberate for safety, and these are optional next steps.
- The extension hasn't been published to the Chrome Web Store.

**What would you do next?** (all)
1. Real Indian messages for training and false-alarm measurement.
2. Hindi and Hinglish.
3. Publish the extension.
4. Opt-in reputation checks.
5. A feedback button that never stores message text.
