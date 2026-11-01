/* PhishShield on ordinary web pages: outlines risky links and explains them on hover.
 *
 * Owner: Atharva. Only links to other sites are checked (a page's own links are the
 * site's business), at most MAX_LINKS per page. Sending a page's links anywhere is a
 * privacy decision, so "auto" only scans when the API runs on this machine; with a
 * hosted API it stays off unless switched on in the options page.
 */
(function () {
  "use strict";
  const PS = globalThis.PS, PSUI = globalThis.PSUI;
  const MAX_LINKS = 150;
  const sent = new Set();
  let flagged = 0;

  function candidates() {
    const out = [];
    document.querySelectorAll("a[href]").forEach((a) => {
      if (out.length >= MAX_LINKS || a.dataset.phishshieldLink) return;
      let u;
      try { u = new URL(a.href); } catch (e) { return; }
      if (!/^https?:$/.test(u.protocol) || u.hostname === location.hostname || sent.has(a.href)) return;
      sent.add(a.href);
      out.push({ text: (a.innerText || "").trim().slice(0, 300), href: a.href });
    });
    return out;
  }

  async function scan() {
    const links = candidates();
    if (!links.length) return;
    const resp = await PS.send({ type: "links", links });
    if (!resp.ok) return;  // no server: stay silent on ordinary pages
    const risks = PS.linkRisks(resp.data);
    document.querySelectorAll("a[href]").forEach((a) => {
      if (PSUI.markLink(a, risks[a.href])) flagged++;
    });
    PS.send({ type: "badge", count: flagged });
  }

  // A link clicked before the page scan reached it is checked on the spot.
  async function checkOne(a) {
    let host = "";
    try { host = new URL(a.href).hostname; } catch (e) { return null; }
    if (host === location.hostname) return null;
    const resp = await PS.send({ type: "links", links: [{ text: (a.innerText || "").trim().slice(0, 300), href: a.href }] });
    if (!resp.ok) return null;
    const risk = PS.linkRisks(resp.data)[a.href];
    if (risk && PSUI.markLink(a, risk)) { flagged++; PS.send({ type: "badge", count: flagged }); }
    return risk || null;
  }

  PS.settings().then((s) => {
    const on = s.linkScan === "on" || (s.linkScan === "auto" && PS.isLocalApi(s.apiBase));
    if (!on) return;
    if (s.stopPage) PSUI.guardClicks(checkOne);
    let timer = null;
    new MutationObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(scan, 1500);
    }).observe(document.body, { childList: true, subtree: true });
    scan();
  });
})();
