/* PhishShield background service worker: the only part of the extension that talks to the API.
 *
 * Owner: Atharva. Content scripts on mail.google.com can't call the API themselves (Gmail's
 * origin would be blocked by CORS), so they send {type: "analyze" | "links" | "health"}
 * messages here. host_permissions cover the local server; any other API address must be
 * granted from the options page.
 */
"use strict";

const DEFAULTS = { apiBase: "http://localhost:8000", gmail: true, linkScan: "auto", stopPage: true };
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
const NAV_TIMEOUT_MS = 2500;
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

// --- address-bar protection --------------------------------------------------------------
// Every page a tab is about to open (typed or pasted address, bookmark, link from another app, a
// preview card a page builds without a real link) is checked here. A risky one is replaced by
// stop/stop.html before the site can be used. "Open anyway" is remembered for the browser session.

function isLocalApi(base) {
  try { return LOCAL_HOSTS.has(new URL(base).hostname); } catch (e) { return false; }
}

async function allowed(url) {
  const { allow = [] } = await chrome.storage.session.get("allow");
  return allow.includes(url);
}

async function allow(url) {
  const { allow = [] } = await chrome.storage.session.get("allow");
  if (!allow.includes(url)) await chrome.storage.session.set({ allow: allow.concat([url]).slice(-500) });
}

// Whole-page navigations are stopped more sparingly than links are outlined, so ordinary browsing
// (a Google Form, a shortened link) isn't interrupted: "risky" needs a phishing verdict, and
// "be careful" a suspicious one backed by proven evidence.
function riskFor(result, url) {
  const found = (result.findings || []).filter((f) => f.contribution > 0).sort((a, b) => b.contribution - a.contribution);
  const proven = found.some((f) => f.tier === "confirmed");
  const level = result.verdict === "phishing" ? "risky" : result.verdict === "suspicious" && proven ? "caution" : null;
  if (!level) return null;
  const reasons = [];
  found.forEach((f) => { if (reasons.indexOf(f.reason) < 0) reasons.push(f.reason); });
  return { level, reasons: reasons.slice(0, 5), url };
}

chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0 || !/^https?:/i.test(d.url)) return;
  const s = await settings();
  const scanning = s.linkScan === "on" || (s.linkScan === "auto" && isLocalApi(s.apiBase));
  if (!s.stopPage || !scanning) return;
  let target;
  try { target = new URL(d.url); } catch (e) { return; }
  try { if (target.origin === new URL(s.apiBase).origin) return; } catch (e) { /* bad setting: check anyway */ }
  if (await allowed(d.url)) return;
  const resp = await Promise.race([
    analyze({ text: d.url, kind: "url" }),
    new Promise((r) => setTimeout(() => r({ ok: false }), NAV_TIMEOUT_MS)),
  ]);
  if (!resp.ok) return;  // no server or too slow: never block browsing on our own failure
  const risk = riskFor(resp.data, d.url);
  if (!risk) return;
  const id = String(Date.now()) + Math.random().toString(16).slice(2, 8);
  await chrome.storage.session.set({ ["stop:" + id]: risk });
  chrome.tabs.update(d.tabId, { url: chrome.runtime.getURL("stop/stop.html") + "#" + id });
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    switch (msg && msg.type) {
      case "allow":  // the user chose "Open anyway" on a stop page
        if (/^https?:/i.test(msg.url || "")) await allow(msg.url);
        return { ok: true };
      case "stopInfo": {
        const key = "stop:" + msg.id;
        const got = await chrome.storage.session.get(key);
        return { ok: !!got[key], data: got[key] };
      }
      case "closeTab":
        if (sender.tab) chrome.tabs.remove(sender.tab.id);
        return { ok: true };
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
