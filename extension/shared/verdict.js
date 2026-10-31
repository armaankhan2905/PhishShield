/* PhishShield shared logic: turns an /api/analyze response into what the UI shows.
 *
 * Owner: Atharvva. Loaded as a classic script by the content scripts and the popup
 * (defines globalThis.PS), and require()-able from Node for tests.
 * Rules from doc/API.md this file enforces:
 *   - reasons and highlights come only from the response's findings
 *   - confidence "low" with a safe verdict is "Low risk: limited checks", never green
 *   - a failed request is "Couldn't check this message", never safe
 */
(function (root) {
  "use strict";

  const DEFAULTS = { apiBase: "http://localhost:8000", gmail: true, linkScan: "auto" };
  const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

  function isLocalApi(apiBase) {
    try { return LOCAL_HOSTS.has(new URL(apiBase).hostname); } catch (e) { return false; }
  }

  /** Headline for a result: tone drives colour, title/subtitle are shown as text. */
  function presentation(result) {
    if (!result) return { tone: "loading", title: "Checking…", subtitle: "PhishShield is analysing this message." };
    if (result.error) {
      return { tone: "error", title: "Couldn't check this message",
               subtitle: result.error === "offline"
                 ? "The PhishShield server isn't reachable. Start it with: python -m src.pipeline.demo"
                 : "The check failed (" + result.error + "). Treat the message with normal caution." };
    }
    const score = typeof result.score === "number" ? " · " + result.score + "/100" : "";
    if (result.verdict === "phishing") {
      return { tone: "danger", title: "Phishing likely" + score, subtitle: "Don't click links, reply, or share codes or details." };
    }
    if (result.verdict === "suspicious") {
      return { tone: "warn", title: "Suspicious" + score, subtitle: "Check the reasons below before you act on this message." };
    }
    if (result.confidence === "low") {
      return { tone: "limited", title: "Low risk: limited checks" + score,
               subtitle: "Some checks weren't available, so this isn't a full all-clear." };
    }
    return { tone: "safe", title: "No phishing signs found" + score, subtitle: "Nothing in this message matched known phishing patterns." };
  }

  /** Findings that added points, strongest first, one per distinct reason. */
  function reasons(result, max) {
    if (!result || !Array.isArray(result.findings)) return [];
    const seen = new Set();
    const out = [];
    result.findings
      .filter(function (f) { return f.contribution > 0; })
      .sort(function (a, b) { return b.contribution - a.contribution; })
      .forEach(function (f) {
        if (seen.has(f.reason)) return;
        seen.add(f.reason);
        out.push({ id: f.id, label: f.label, reason: f.reason, tier: f.tier, field: f.field, text: f.text,
                   contribution: f.contribution });
      });
    return typeof max === "number" ? out.slice(0, max) : out;
  }

  /** Body spans to highlight (UTF-16 offsets, as JavaScript strings use). Overlaps are merged. */
  function bodySpans(result) {
    if (!result || !Array.isArray(result.findings)) return [];
    const spans = result.findings
      .filter(function (f) { return f.field === "body" && f.start_u16 != null && f.end_u16 > f.start_u16 && f.contribution > 0; })
      .map(function (f) { return { start: f.start_u16, end: f.end_u16, reasons: [f.reason], text: f.text }; })
      .sort(function (a, b) { return a.start - b.start || b.end - a.end; });
    const merged = [];
    spans.forEach(function (s) {
      const last = merged[merged.length - 1];
      if (last && s.start < last.end) {
        last.end = Math.max(last.end, s.end);
        if (last.reasons.indexOf(s.reasons[0]) < 0) last.reasons.push(s.reasons[0]);
      } else {
        merged.push({ start: s.start, end: s.end, reasons: s.reasons.slice(), text: s.text });
      }
    });
    return merged;
  }

  /** Split text into plain and highlighted pieces for rendering with textContent. */
  function segments(text, spans) {
    const out = [];
    let at = 0;
    (spans || []).forEach(function (s) {
      if (s.start < at || s.end > text.length) return;
      if (s.start > at) out.push({ text: text.slice(at, s.start) });
      out.push({ text: text.slice(s.start, s.end), mark: true, title: s.reasons.join("\n") });
      at = s.end;
    });
    if (at < text.length) out.push({ text: text.slice(at) });
    return out;
  }

  /** url -> { level: "risky" | "caution", reasons: [...] } for links the response flagged. */
  function linkRisks(result) {
    const map = {};
    if (!result || !Array.isArray(result.findings)) return map;
    result.findings.forEach(function (f) {
      if (f.family !== "link" && f.source !== "url-model") return;
      if (!f.text || f.contribution <= 0) return;
      const entry = map[f.text] || (map[f.text] = { level: "caution", points: 0, reasons: [] });
      entry.points += f.contribution;
      if (f.tier === "confirmed" || f.source === "url-model") entry.level = "risky";
      if (entry.reasons.indexOf(f.reason) < 0) entry.reasons.push(f.reason);
    });
    Object.keys(map).forEach(function (url) {
      if (map[url].level === "caution" && map[url].points < 8) delete map[url];  // e.g. "not https" alone
    });
    return map;
  }

  function hostedNote(result) {
    return result && result.mode === "hosted"
      ? "This message was sent to the PhishShield server for analysis. It isn't stored." : "";
  }

  const PS = { DEFAULTS: DEFAULTS, isLocalApi: isLocalApi, presentation: presentation, reasons: reasons,
               bodySpans: bodySpans, segments: segments, linkRisks: linkRisks, hostedNote: hostedNote };

  /* Messaging and settings: the real extension uses chrome.* APIs. When the same scripts are
     opened from the PhishShield dev server (python -m src.pipeline.demo --dev), there is no
     extension context, so they call the API on the same origin and use the defaults. */
  const hasExt = typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id;

  PS.settings = function () {
    if (hasExt && chrome.storage && chrome.storage.sync) {
      return new Promise(function (resolve) { chrome.storage.sync.get(DEFAULTS, resolve); });
    }
    return Promise.resolve(Object.assign({}, DEFAULTS, { apiBase: root.location ? root.location.origin : DEFAULTS.apiBase }));
  };

  PS.send = function (msg) {
    if (hasExt) {
      return new Promise(function (resolve) {
        chrome.runtime.sendMessage(msg, function (resp) {
          resolve(resp || { ok: false, error: chrome.runtime.lastError ? "extension" : "no response" });
        });
      });
    }
    // Dev pages only (same-origin PhishShield server).
    if (msg.type === "health") {
      return fetch("/api/health").then(function (r) { return r.json(); })
        .then(function (data) { return { ok: true, data: data }; }, function () { return { ok: false, error: "offline" }; });
    }
    const body = msg.type === "links" ? { text: "", links: msg.links } : msg.payload;
    return fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      .then(function (r) { return r.ok ? r.json().then(function (d) { return { ok: true, data: d }; }) : { ok: false, error: "http " + r.status }; },
            function () { return { ok: false, error: "offline" }; });
  };

  if (typeof module !== "undefined" && module.exports) module.exports = PS;
  root.PS = PS;
})(typeof globalThis !== "undefined" ? globalThis : this);
