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
  function markLink(a, risk) {
    if (!risk || a.dataset.phishshieldLink) return false;
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

  root.PSUI = { banner, markPhrases, markLink };
})(globalThis);
