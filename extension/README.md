# PhishShield Chrome extension

Checks emails you open in Gmail and outlines risky links on other websites,
using your local PhishShield server. Nothing is analysed inside the extension
itself: it sends the message to the server you choose (by default
`http://localhost:8000`, on your own computer) and shows the result.

## Install

**Easiest:** start the server (`python -m src.pipeline.demo`), open http://localhost:8000/extension
(**Get the extension** in the app), and follow its four steps. It downloads the extension as a zip,
shows exactly where to click, and confirms by itself once the extension is installed (or tells you
when a newer version is available).

Browsers don't let a website install an extension by itself. One-click installs only come from the
Chrome Web Store: after publishing there, set `PHISHSHIELD_EXTENSION_STORE_URL` to the store page and
the app's button becomes **Add to Chrome**.

### By hand (unpacked)

1. Start the server from the repo root:
   ```bash
   python -m src.pipeline.demo
   ```
2. In Chrome, open `chrome://extensions`, switch on **Developer mode**, click **Load unpacked**, and pick this `extension/` folder.
3. Click the PhishShield icon. It should say **Server ready**.
4. Open Gmail and open an email. A banner appears above it within a second or two.

## What it does

| Where | What you see |
|---|---|
| **Gmail** (open email) | A banner above the email. **Red** phishing likely · **amber** suspicious · **green** no phishing signs · **grey** "Low risk: limited checks" (some checks unavailable) or "Couldn't check this message" (server not reachable). Up to 3 reasons; **Details** shows the rest, the explanation and which checks ran. On non-safe emails, flagged phrases are highlighted and risky links outlined. |
| **Other websites** | Links to other sites that look risky are outlined in red (risky) or amber (be careful). Hover for the reason. The icon badge counts them. |
| **Stop page** | Clicking a risky link (on any site, or in a Gmail email) shows a full-screen warning first: where the link really goes and why it was stopped, with **Go back** (default, also Esc) and **Open anyway**. A link the page scan hasn't reached yet is checked on the spot (up to 2.5 s). Can be turned off in Settings. |
| **Address-bar protection** | Any page a tab is about to open (a typed or pasted address, a bookmark, a link from another app, or a preview card a page builds without a real link) is checked first. A phishing verdict, or a suspicious one with proven evidence, opens `stop/stop.html` in its place. Uses the same server and privacy rule as link checking; never blocks browsing if the server is down or slow (2.5 s). |
| **Toolbar popup** | Server status and a box to paste any message or link and check it. |
| **Settings** | Server address, Gmail on/off, link checking: *Automatic* (only when the server is on this computer), *On*, or *Off*, and the stop page on/off. |

## Privacy

- **Local server (default):** messages and links go to `localhost` only.
- **Any other server address:** Chrome asks you to allow it, and results show "This message was sent to the PhishShield server" when the server runs in hosted mode.
- Link checking on ordinary websites sends that page's outgoing links to the server. *Automatic* only does this with a local server.
- The extension stores only its settings. It doesn't keep messages or results; the background worker caches the last 50 results in memory to avoid re-checking the same email.

## How it's built

| File | Job |
|---|---|
| `manifest.json` | Manifest V3. Host permission only for `localhost:8000` / `127.0.0.1:8000`; other servers are optional permissions |
| `background.js` | The only part that calls the API (Gmail's origin would be blocked by CORS). Timeout, cache, badge |
| `shared/verdict.js` | Turns an API response into headline, reasons, highlights and link risks. Shared by everything; unit-tested in Node |
| `content/ui.js` | Banner in a closed Shadow DOM. All API text inserted with `textContent`, never HTML |
| `content/gmail.js` | Finds opened emails (Gmail selectors in one `SEL` object), extracts sender, subject, text and links (unwrapping `google.com/url?q=`), shows the banner |
| `content/links.js` | Outlines risky outgoing links on other sites; checks an unscanned link when it's clicked |
| `content/app-bridge.js` | On the PhishShield app's own pages only: marks the page with the installed version so **Get the extension** can confirm the install |
| `popup/`, `options/` | Toolbar popup and settings page |

Reply-To isn't visible in Gmail's page, so it isn't sent; the server's reply-to check only applies to `.eml` uploads.

## Test without installing

Chrome extensions can't run in every browser (for example, the Claude app's built-in one), so the same scripts can run on test pages served by the PhishShield server:

```bash
python -m src.pipeline.demo --dev
```

- **Gmail look-alike:** <http://localhost:8000/dev/extension/dev/gmail.html>. Sample buttons swap emails the way Gmail does; **Simulate server offline** shows the error state.
- **Ordinary page with mixed links:** <http://localhost:8000/dev/extension/dev/links.html>
- **Popup:** <http://localhost:8000/dev/extension/popup/popup.html>

On these pages the scripts call the API on the same origin instead of going through the background worker. `--dev` only adds these static pages; the normal server doesn't serve them.

Unit tests for the shared logic:

```bash
node --test extension/test/*.test.js
```
