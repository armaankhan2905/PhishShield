/* PhishShield for Gmail: checks each opened email and shows a banner above it.
 *
 * Owner: Atharva. Gmail is a single-page app that swaps messages without reloading,
 * so a MutationObserver looks for message bodies we haven't checked yet.
 * Selectors (Gmail's own class names) live in SEL; if Gmail changes them, fix them
 * here. Reply-To isn't shown in Gmail's page, so it isn't sent.
 */
(function () {
  "use strict";
  const PS = globalThis.PS, PSUI = globalThis.PSUI;

  const SEL = {
    body: "div.a3s",                       // message body
    message: "div.adn, div[data-message-id]",  // one message in a thread
    sender: "span.gD[email], span[email].go, span[email]",
    subject: "h2.hP",
  };
  const MAX_TEXT = 20000;
  const MAX_LINKS = 200;
  const DONE = "phishshieldChecked";

  function unwrapGoogle(href) {
    try {
      const u = new URL(href);
      if (/(^|\.)google\.[a-z.]+$/.test(u.hostname) && u.pathname === "/url") {
        const q = u.searchParams.get("q") || u.searchParams.get("url");
        if (q && /^https?:\/\//i.test(q)) return q;
      }
    } catch (e) { /* not a URL */ }
    return href;
  }

  function extract(body) {
    const msg = body.closest(SEL.message) || body.parentElement;
    const senderEl = msg.querySelector(SEL.sender);
    const name = senderEl ? (senderEl.getAttribute("name") || senderEl.textContent || "").trim() : "";
    const addr = senderEl ? senderEl.getAttribute("email") : "";
    const subjectEl = document.querySelector(SEL.subject);
    const links = [];
    const seen = new Set();
    body.querySelectorAll("a[href]").forEach((a) => {
      const href = unwrapGoogle(a.href);
      if (!/^https?:/i.test(href) || links.length >= MAX_LINKS) return;
      const text = (a.innerText || a.textContent || "").trim().slice(0, 500);
      const key = text + "\u0000" + href;
      if (seen.has(key)) return;
      seen.add(key);
      links.push({ text, href });
    });
    return {
      text: (body.innerText || body.textContent || "").slice(0, MAX_TEXT),
      kind: "email",
      email: addr ? { from: name ? `${name} <${addr}>` : addr, reply_to: "", subject: subjectEl ? subjectEl.textContent.trim() : "" } : null,
      links,
    };
  }

  async function check(body) {
    body.dataset[DONE] = "1";
    const payload = extract(body);
    if (!payload.text.trim() && !payload.links.length) return;
    const ui = PSUI.banner();
    body.parentElement.insertBefore(ui.host, body);
    const resp = await PS.send({ type: "analyze", payload });
    if (!resp.ok) { ui.update({ error: resp.error }); return; }
    const result = resp.data;
    ui.update(result);
    if (result.verdict === "safe") return;  // minor notes stay in the banner; don't mark up a safe email
    PSUI.markPhrases(body, PS.bodySpans(result));
    const risks = PS.linkRisks(result);
    // Findings name a link by its real target, or by the URL as written in the text.
    body.querySelectorAll("a[href]").forEach((a) =>
      PSUI.markLink(a, risks[unwrapGoogle(a.href)] || risks[(a.textContent || "").trim()]));
  }

  function scan() {
    document.querySelectorAll(SEL.body).forEach((body) => {
      if (!body.dataset[DONE] && body.offsetParent !== null) check(body);
    });
  }

  PS.settings().then((s) => {
    if (!s.gmail) return;
    if (s.stopPage) PSUI.guardClicks();  // the whole email is checked on open, so only marked links are stopped
    let timer = null;
    new MutationObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(scan, 400);
    }).observe(document.body, { childList: true, subtree: true });
    scan();
  });
})();
