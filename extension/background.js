/* PhishShield background service worker: the only part of the extension that talks to the API.
 *
 * Owner: Atharvva. Content scripts on mail.google.com can't call the API themselves (Gmail's
 * origin would be blocked by CORS), so they send {type: "analyze" | "links" | "health"}
 * messages here. host_permissions cover the local server; any other API address must be
 * granted from the options page.
 */
"use strict";

const DEFAULTS = { apiBase: "http://localhost:8000", gmail: true, linkScan: "auto" };
const TIMEOUT_MS = 15000;
const CACHE_MAX = 50;
const cache = new Map();  // payload JSON -> response; Gmail re-renders the same message often

function settings() {
  return new Promise((resolve) => chrome.storage.sync.get(DEFAULTS, resolve));
}

function apiUrl(base, path) {
  const u = new URL(path, base);
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("bad api address");
  return u.toString();
}

async function call(path, init, timeout) {
  const { apiBase } = await settings();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout || TIMEOUT_MS);
  try {
    const r = await fetch(apiUrl(apiBase, path), Object.assign({ signal: ctrl.signal }, init));
    if (!r.ok) return { ok: false, error: "http " + r.status };
    return { ok: true, data: await r.json() };
  } catch (e) {
    return { ok: false, error: e.name === "AbortError" ? "timeout" : "offline" };
  } finally {
    clearTimeout(timer);
  }
}

async function analyze(payload) {
  const key = JSON.stringify(payload);
  if (cache.has(key)) return cache.get(key);
  const resp = await call("/api/analyze", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: key,
  });
  if (resp.ok) {
    cache.set(key, resp);
    if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
  }
  return resp;
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    switch (msg && msg.type) {
      case "analyze":
        return analyze(msg.payload);
      case "links":
        return analyze({ text: "", links: (msg.links || []).slice(0, 200) });
      case "health":
        return call("/api/health", { method: "GET" }, 3000);
      case "badge":
        if (sender.tab) {
          chrome.action.setBadgeText({ tabId: sender.tab.id, text: msg.count ? String(msg.count) : "" });
          chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: "#b42318" });
        }
        return { ok: true };
      default:
        return { ok: false, error: "unknown message" };
    }
  })().then(reply);
  return true;  // reply asynchronously
});
