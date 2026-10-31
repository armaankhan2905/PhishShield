/* PhishShield page UI: the warning banner and in-page highlights.
 *
 * Owner: Atharvva. The banner lives in a closed Shadow DOM so the host page's CSS can't
 * restyle or read it, and every string from the API is inserted with textContent,
 * never as HTML. Highlights wrap existing text nodes; they never rewrite the page's markup.
 */
(function (root) {
  "use strict";
  const PS = root.PS;

  const STYLE = `
    :host { all: initial; display: block; margin: 8px 0 12px; }
    .ps { font: 13px/1.45 "Segoe UI", Roboto, Arial, sans-serif; border-radius: 8px; padding: 10px 12px;
          border: 1px solid var(--line); background: var(--bg); color: #1f2328; max-width: 860px; }
    .head { display: flex; align-items: center; gap: 10px; }
    .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); flex: none; }
    .title { font-weight: 600; font-size: 14px; flex: 1; color: var(--ink); }
    .brand { font-size: 11px; color: #57606a; letter-spacing: .02em; }
    .sub { margin: 4px 0 0 20px; color: #3d444d; }
    ul { margin: 6px 0 0 20px; padding: 0 0 0 16px; }
    li { margin: 2px 0; }
    button { font: inherit; font-size: 12px; background: none; border: 1px solid var(--line); color: var(--ink);
             border-radius: 6px; padding: 2px 8px; cursor: pointer; }
    button:focus-visible { outline: 2px solid #1d4ed8; outline-offset: 2px; }
    .more { margin: 8px 0 0 20px; padding-top: 8px; border-top: 1px dashed var(--line); color: #3d444d; }
    .more p { margin: 4px 0; }
    .meta { font-size: 11.5px; color: #57606a; }
    .danger  { --bg: #fdecea; --line: #f4b4ac; --accent: #b42318; --ink: #7a1a12; }
    .warn    { --bg: #fff6e0; --line: #f2d08a; --accent: #b54708; --ink: #7a3306; }
    .safe    { --bg: #e8f5ee; --line: #a6dbbc; --accent: #067647; --ink: #054f31; }
    .limited, .error, .loading { --bg: #f2f4f7; --line: #d0d5dd; --accent: #667085; --ink: #344054; }
    @media (prefers-color-scheme: dark) {
      .ps { color: #e6e9ef; }
      .sub, .more { color: #c4cad4; } .brand, .meta { color: #9aa3b2; }
      .danger  { --bg: #3a1714; --line: #7a2b23; --ink: #fca5a0; }
      .warn    { --bg: #3a2a10; --line: #7a5a1c; --ink: #fcd38d; }
      .safe    { --bg: #10301f; --line: #1f6b44; --ink: #8ee0b4; }
      .limited, .error, .loading { --bg: #22262e; --line: #3a404b; --ink: #d0d5dd; }
    }`;

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  /** A banner element plus update(result | {error} | null). */
  function banner() {
    const host = document.createElement("phishshield-banner");
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    const box = el("div", "ps loading");
    box.setAttribute("role", "status");
    shadow.append(style, box);

    function update(result) {
      const p = PS.presentation(result);
      box.className = "ps " + p.tone;
      box.replaceChildren();
      const head = el("div", "head");
      head.append(el("span", "dot"), el("span", "title", p.title), el("span", "brand", "PhishShield"));
      box.append(head, el("p", "sub", p.subtitle));
      if (!result || result.error) return;

      const all = PS.reasons(result);
      if (all.length && result.verdict === "safe") box.append(el("p", "sub meta", "Noted, but not enough to flag:"));
      if (all.length) {
        const ul = el("ul");
        all.slice(0, 3).forEach((r) => ul.append(el("li", null, r.reason)));
        box.append(ul);
      }
      const more = el("div", "more");
      more.hidden = true;
      all.slice(3).forEach((r) => more.append(el("p", null, "• " + r.reason)));
      if (result.explanation) more.append(el("p", null, result.explanation));
      const note = PS.hostedNote(result);
      if (note) more.append(el("p", "meta", note));
      more.append(el("p", "meta", "Confidence: " + result.confidence + " · checks: " +
        Object.entries(result.coverage || {}).map(([k, v]) => k.replace("_", " ") + " " + v).join(", ")));
      const toggle = el("button", null, "Details");
      toggle.setAttribute("aria-expanded", "false");
      toggle.addEventListener("click", () => {
        more.hidden = !more.hidden;
        toggle.textContent = more.hidden ? "Details" : "Hide details";
        toggle.setAttribute("aria-expanded", String(!more.hidden));
      });
      head.append(toggle);
      box.append(more);
    }
    update(null);
    return { host, update };
  }

  // Fixed dark text on yellow: readable whether the page (or Gmail's theme) is light or dark.
  const MARK_STYLE = "background:#ffe08a;color:#1f2328;border-radius:2px;box-shadow:0 0 0 1px #e0a800 inset;";

  /** Wrap occurrences of each flagged phrase inside `scope` (text nodes only). */
  function markPhrases(scope, spans) {
    const phrases = spans.filter((s) => s.text && s.text.trim().length >= 2);
    if (!phrases.length) return 0;
    let count = 0;
    phrases.forEach((s) => {
      const walker = document.createTreeWalker(scope, NodeFilter.SHOW_TEXT, {
        acceptNode: (n) => (n.parentElement && n.parentElement.closest("mark[data-phishshield], phishshield-banner, script, style")
          ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
      });
      const hits = [];
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        const i = n.data.indexOf(s.text);
        if (i >= 0) hits.push([n, i]);
      }
      hits.forEach(([node, i]) => {
        const range = document.createRange();
        range.setStart(node, i);
        range.setEnd(node, i + s.text.length);
        const mark = document.createElement("mark");
        mark.dataset.phishshield = "";
        mark.title = "PhishShield: " + s.reasons.join(" · ");
        mark.setAttribute("style", MARK_STYLE);
        range.surroundContents(mark);
        count++;
      });
    });
    return count;
  }

  /** Outline a risky link and explain it on hover. Returns true if marked. */
  const RISKS = new WeakMap();  // link element -> {level, reasons}, for the stop page

  function markLink(a, risk) {
    if (!risk || a.dataset.phishshieldLink) return false;
    RISKS.set(a, risk);
    a.dataset.phishshieldLink = risk.level;
    const color = risk.level === "risky" ? "#b42318" : "#b54708";
    a.style.setProperty("outline", "2px solid " + color, "important");
    a.style.setProperty("outline-offset", "1px", "important");
    a.style.setProperty("border-radius", "2px", "important");
    const prior = a.getAttribute("title");
    a.title = (risk.level === "risky" ? "PhishShield: risky link. " : "PhishShield: be careful. ") +
      risk.reasons.join(" · ") + (prior ? "\n\n" + prior : "");
    return true;
  }

  // --- stop page: a full-screen warning before a risky link opens -----------------------------

  const STOP_STYLE = `
    :host { all: initial; }
    .veil { position: fixed; inset: 0; z-index: 2147483647; background: rgba(11, 18, 16, .72); display: grid; place-items: center;
            padding: 16px; font: 15px/1.5 "Segoe UI", Roboto, Arial, sans-serif; }
    .card { background: #fff; color: #1f2328; max-width: 520px; width: 100%; border-radius: 16px; padding: 24px 24px 20px;
            box-shadow: 0 30px 80px rgba(0,0,0,.45); border-top: 6px solid var(--accent); }
    .risky { --accent: #b42318; --ink: #7a1a12; --soft: #fdecea; }
    .caution { --accent: #b54708; --ink: #7a3306; --soft: #fff6e0; }
    .brand { font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: #57606a; }
    h1 { font-size: 24px; line-height: 1.2; margin: 6px 0 8px; color: var(--ink); }
    .dest { background: var(--soft); border-radius: 10px; padding: 10px 12px; margin: 12px 0; word-break: break-all;
            font: 13px/1.45 ui-monospace, Consolas, monospace; color: #1f2328; }
    .dest b { display: block; font: 600 12px "Segoe UI", Roboto, Arial, sans-serif; color: #57606a; margin-bottom: 2px; }
    ul { margin: 8px 0 0; padding-left: 20px; } li { margin: 3px 0; }
    .row { display: flex; gap: 10px; margin-top: 20px; flex-wrap: wrap; }
    button { font: 600 15px "Segoe UI", Roboto, Arial, sans-serif; border-radius: 10px; padding: 10px 18px; cursor: pointer; border: 1px solid #d0d5dd; }
    .back { background: #0b2b26; color: #fff; border-color: #0b2b26; flex: 1; }
    .go { background: #fff; color: #57606a; }
    button:focus-visible { outline: 3px solid #1d4ed8; outline-offset: 2px; }
    .note { font-size: 12.5px; color: #57606a; margin-top: 12px; }
    @media (prefers-color-scheme: dark) {
      .card { background: #1b1f24; color: #e6e9ef; } .dest { color: #e6e9ef; } .brand, .note, .dest b { color: #9aa3b2; }
      .risky { --ink: #fca5a0; --soft: #3a1714; } .caution { --ink: #fcd38d; --soft: #3a2a10; }
      .go { background: #1b1f24; color: #c4cad4; border-color: #3a404b; }
      .back { background: #daf1de; color: #0b2b26; border-color: #daf1de; }
    }`;

  let stopOpen = false;

  /** Shows the stop page for *href*. Resolves true when the user chooses to open the link anyway. */
  function stopPage(href, risk) {
    return new Promise((resolve) => {
      stopOpen = true;
      const host = document.createElement("phishshield-stop");
      const shadow = host.attachShadow({ mode: "closed" });
      const style = document.createElement("style");
      style.textContent = STOP_STYLE;
      const veil = el("div", "veil");
      const card = el("div", "card " + (risk.level === "risky" ? "risky" : "caution"));
      card.setAttribute("role", "alertdialog");
      card.setAttribute("aria-modal", "true");
      const title = el("h1", null, risk.level === "risky" ? "Stop. This link looks risky." : "Be careful with this link.");
      title.id = "t";
      card.setAttribute("aria-labelledby", "t");
      let host_ = href;
      try { host_ = new URL(href).hostname; } catch (e) { /* keep the raw address */ }
      const dest = el("div", "dest");
      dest.append(el("b", null, "It really goes to"), document.createTextNode(host_ + (host_ !== href ? "  ·  " + href.slice(0, 200) : "")));
      const ul = el("ul");
      (risk.reasons || []).slice(0, 5).forEach((r) => ul.append(el("li", null, r)));
      const back = el("button", "back", "Go back (recommended)");
      const go = el("button", "go", "Open anyway");
      const row = el("div", "row");
      row.append(back, go);
      card.append(el("div", "brand", "PhishShield"), title,
        el("div", null, "PhishShield checked this link before opening it. Here's why it was stopped:"), ul, dest, row,
        el("div", "note", "Never enter passwords, OTPs, card details or your UPI PIN on a page you reached this way."));
      veil.append(card);
      shadow.append(style, veil);
      document.documentElement.append(host);
      const prevFocus = document.activeElement;
      const done = (open) => {
        stopOpen = false;
        host.remove();
        document.removeEventListener("keydown", onKey, true);
        if (prevFocus && prevFocus.focus) try { prevFocus.focus(); } catch (e) { /* page may have changed */ }
        resolve(open);
      };
      const onKey = (e) => {
        if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); done(false); }
        if (e.key === "Tab") { e.preventDefault(); (shadow.activeElement === back ? go : back).focus(); }
      };
      back.addEventListener("click", () => done(false));
      go.addEventListener("click", () => done(true));
      veil.addEventListener("click", (e) => { if (e.target === veil) done(false); });
      document.addEventListener("keydown", onKey, true);
      back.focus();
    });
  }

  function webLink(a) {
    try { return /^https?:$/.test(new URL(a.href).protocol); } catch (e) { return false; }
  }

  /**
   * Stops clicks on risky links and shows the stop page first. *checkUnknown(a)* (optional) checks a link
   * that hasn't been checked yet and resolves to its risk or null; it gets CHECK_TIMEOUT_MS.
   */
  const CHECK_TIMEOUT_MS = 2500;
  function guardClicks(checkUnknown) {
    const handler = async (e) => {
      if (stopOpen || e.defaultPrevented || (e.type === "auxclick" && e.button !== 1) || (e.type === "click" && e.button !== 0)) return;
      const a = e.target && e.target.closest ? e.target.closest("a[href]") : null;
      if (!a || !webLink(a) || a.dataset.phishshieldAllowed) return;
      let risk = RISKS.get(a);
      if (!risk && !checkUnknown) return;
      const newTab = e.type === "auxclick" || e.ctrlKey || e.metaKey || e.shiftKey || a.target === "_blank";
      e.preventDefault();
      e.stopImmediatePropagation();
      if (!risk) {
        risk = await Promise.race([checkUnknown(a).catch(() => null),
                                   new Promise((r) => setTimeout(() => r(null), CHECK_TIMEOUT_MS))]);
      }
      const open = risk ? await stopPage(a.href, risk) : true;
      if (!open) return;
      a.dataset.phishshieldAllowed = "1";  // the user decided; don't ask again for this link on this page
      if (root.__phishshieldTestPage) return;  // extension/dev test pages never follow their sample links
      await PS.send({ type: "allow", url: a.href });  // so the address-bar check doesn't stop it a second time
      if (newTab) window.open(a.href, "_blank", "noopener");
      else location.assign(a.href);
    };
    window.addEventListener("click", handler, true);
    window.addEventListener("auxclick", handler, true);
  }

  root.PSUI = { banner, markPhrases, markLink, stopPage, guardClicks };
})(globalThis);
