/* Shared by every PhishShield page: header, server status and small DOM helpers.
   All text from the API is inserted with textContent, never as HTML. */
"use strict";

const PAGES = [["/", "Check a message"], ["/results", "Results"], ["/how-it-works", "How it works"], ["/extension", "Get the extension"]];

function h(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  Object.entries(attrs || {}).forEach(([k, v]) => {
    if (v == null || v === false) return;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  });
  kids.flat().forEach((k) => k != null && n.append(k instanceof Node ? k : document.createTextNode(String(k))));
  return n;
}

const fmt = {
  pct: (x, d = 1) => (x == null ? "–" : (x * 100).toFixed(d) + "%"),
  num: (x, d = 3) => (x == null ? "–" : Number(x).toFixed(d)),
  int: (x) => (x == null ? "–" : Number(x).toLocaleString("en-IN")),
};

let HEALTH = null;

async function loadHealth() {
  try {
    const r = await fetch("/api/health");
    HEALTH = r.ok ? await r.json() : null;
  } catch (e) { HEALTH = null; }
  return HEALTH;
}

function renderHeader() {
  const here = location.pathname.replace(/\/$/, "") || "/";
  const status = h("div", { class: "status", id: "status", "aria-live": "polite" }, h("span", { class: "chip", text: "Connecting…" }));
  document.getElementById("top").replaceChildren(h("div", { class: "wrap" },
    h("a", { class: "brand", href: "/" }, h("b", { text: "PhishShield" })),
    h("nav", { "aria-label": "Pages" }, PAGES.map(([href, name]) =>
      h("a", { href, "aria-current": href === here ? "page" : null, text: name }))),
    status));
  loadHealth().then((s) => {
    const chips = [];
    if (!s) chips.push(h("span", { class: "chip bad", text: "Server offline" }));
    else {
      chips.push(h("span", { class: "chip " + (s.mode === "hosted" ? "off" : "ok"), text: s.mode === "hosted" ? "Hosted demo" : "Running on this computer" }));
      const ready = s.models.url === "loaded" && s.models.text === "loaded";
      chips.push(h("span", { class: "chip " + (ready ? "ok" : "off"), title: "URL model: " + s.models.url + ", text model: " + s.models.text,
                             text: ready ? "Models ready" : "Models " + s.models.url + "/" + s.models.text }));
      chips.push(h("span", { class: "chip " + (s.explainer.available ? "ok" : "off"), title: s.explainer.detail,
                             text: s.explainer.available ? "Local AI explanations" : "Template explanations" }));
    }
    status.replaceChildren(...chips);
    const note = document.getElementById("hostedNote");
    if (note && s && s.mode === "hosted") {
      note.hidden = false;
      note.textContent = "This is the hosted demo: messages you check here are sent to the PhishShield server for analysis. " +
        "They aren't stored or logged. For private use, run PhishShield on your own computer.";
    }
  });
}

document.addEventListener("DOMContentLoaded", renderHeader);
