/* Analyse page. Uses the same result logic as the extension (extension/shared/verdict.js,
   served at /shared/verdict.js) so the web app and the Gmail banner always agree. */
"use strict";

const SAMPLES = [
  { name: "SBI KYC SMS", tag: "phishing", kind: "message",
    text: "URGENT: Dear customer, your SBI KYC is pending and your account will be blocked today. Verify at http://sbi-kyc.xyz/login" },
  { name: "Lottery fee", tag: "scam", kind: "message",
    text: "Congratulations! You have won Rs 25,00,000 in the KBC lottery 🎉. Pay Rs 5,000 processing fee to receive your prize. Call 9876543210" },
  { name: "Fake PayPal email", tag: "phishing", kind: "email",
    email: { from: "PayPal Support <service@paypa1-security.com>", reply_to: "paypal.help.desk@gmail.com", subject: "Your account is limited" },
    text: "Dear user,\nWe noticed unusual activity. Your PayPal account is restricted.\nLogin at https://paypa1.com/secure to restore access within 24 hours." },
  { name: "Lookalike link", tag: "phishing", kind: "url", text: "http://amaz0n-refund.in/claim" },
  { name: "Bank OTP alert", tag: "legit", kind: "message",
    text: "123456 is your OTP for txn of Rs 500 at Amazon. Valid 5 mins. Do not share it with anyone -HDFC Bank" },
  { name: "Amazon shipping", tag: "legit", kind: "message",
    text: "Your Amazon order has shipped. Track it at https://www.amazon.in/gp/your-orders" },
  { name: "KYC reminder", tag: "borderline", kind: "message",
    text: "Dear customer, update your KYC within 24 hours using our official website." },
];

const $ = (id) => document.getElementById(id);
let kind = "message";
let file = null;
let busy = false;

/* --- input ------------------------------------------------------------------- */

function selectTab(k) {
  kind = k;
  document.querySelectorAll('[role="tab"]').forEach((t) => {
    const on = t.dataset.kind === k;
    t.setAttribute("aria-selected", String(on));
    $("pane-" + t.dataset.kind).hidden = !on;
  });
}

function setFile(f) {
  file = f || null;
  $("fileName").textContent = file ? file.name + " · " + Math.ceil(file.size / 1024) + " KB" : "";
}

function loadSample(s) {
  selectTab(s.kind);
  if (s.kind === "message") $("msgText").value = s.text;
  if (s.kind === "url") $("urlText").value = s.text;
  if (s.kind === "email") {
    $("emFrom").value = s.email.from; $("emReply").value = s.email.reply_to;
    $("emSubject").value = s.email.subject; $("emBody").value = s.text;
  }
  check();
}

function request() {
  if (kind === "message") return { text: $("msgText").value, kind: "auto" };
  if (kind === "url") return { text: $("urlText").value.trim(), kind: "url" };
  if (kind === "email") {
    const from = $("emFrom").value.trim(), reply = $("emReply").value.trim(), subject = $("emSubject").value.trim();
    return { text: $("emBody").value, kind: "email", email: from || reply || subject ? { from, reply_to: reply, subject } : null };
  }
  return null;
}

/* --- calls ----------------------------------------------------------------------- */

async function post(url, body, isForm) {
  const r = await fetch(url, isForm ? { method: "POST", body } :
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof data.detail === "string" ? data.detail : "The check failed (" + r.status + ").");
  return data;
}

async function check() {
  if (busy) return;
  let req = null, form = null;
  if (kind === "file") {
    if (!file) { $("fileIn").click(); return; }
    form = new FormData();
    form.append("file", file);
  } else {
    req = request();
    if (!req.text.trim()) { showMessage("Nothing to check", "Paste a message, email or link first."); return; }
  }
  busy = true;
  $("checkBtn").disabled = true;
  showMessage(null);
  try {
    const result = form ? await post("/api/analyze/file", form, true) : await post("/api/analyze", req);
    const text = form ? result.text : req.text;
    render(result, text);
    if (shouldExplain(result)) explain(form ? { text: result.text, kind: result.kind, email: result.email,
      links: result.links || [] } : req, result);
  } catch (e) {
    showError(e.message === "Failed to fetch" ? "offline" : e.message);
  } finally {
    busy = false;
    $("checkBtn").disabled = false;
  }
}

function shouldExplain(result) {
  return HEALTH && HEALTH.explainer && HEALTH.explainer.available && result.verdict !== "safe";
}

async function explain(req, result) {
  const box = $("explainBox");
  if (!box) return;
  box.replaceChildren(h("p", null, h("span", { class: "spin", "aria-hidden": "true" }),
    "Writing a plain-English explanation with the AI model on this computer…"));
  try {
    const out = await post("/api/explain", req);
    if (!document.body.contains(box)) return;  // another message was checked meanwhile
    if (out.verdict !== result.verdict) throw new Error("verdict changed");
    box.replaceChildren(h("p", { text: out.explanation }),
      h("p", { class: "src", text: out.source === "llm"
        ? "Written by a local AI model (" + out.model + ") from the findings above. It can't add new reasons."
        : "Plain summary (" + (out.detail || "AI model not used") + ")." }));
  } catch (e) {
    box.replaceChildren(h("p", { text: result.explanation }), h("p", { class: "src", text: "Plain summary (the AI explanation failed)." }));
  }
}

/* --- rendering ------------------------------------------------------------------------ */

const CHECK_NAMES = { rules: "Rules", anomaly: "Sender & links", url_model: "URL model", text_model: "Text model" };
const TIER_NAMES = { confirmed: "Proven", heuristic: "Pattern", ml: "Model" };

function showMessage(title, sub) {
  const box = $("result");
  if (!title) {
    box.replaceChildren(h("div", { class: "verdict loading" }, h("div", { class: "title" },
      h("span", { class: "spin", "aria-hidden": "true" }), h("b", { text: "Checking…" }))));
    return;
  }
  box.replaceChildren(h("div", { class: "empty" }, h("b", { text: title }), sub));
}

function showError(err) {
  const p = PS.presentation({ error: err });
  $("result").replaceChildren(h("div", { class: "verdict error" }, h("div", { class: "title" }, h("b", { text: p.title })),
    h("p", { text: err === "offline" ? p.subtitle : err })));
}

function render(result, text) {
  const p = PS.presentation(result);
  const box = $("result");
  const parts = [];

  const marker = h("i", { style: "left:" + Math.max(0, Math.min(100, result.score)) + "%" });
  parts.push(h("div", { class: "verdict " + p.tone },
    h("div", { class: "title" }, h("b", { text: p.title.replace(/ · \d+\/100$/, "") }),
      h("span", { class: "muted", text: "Score " + result.score + "/100 · confidence " + result.confidence })),
    h("p", { text: p.subtitle }),
    h("div", { class: "meter", role: "img", "aria-label": "Risk score " + result.score + " out of 100" }, marker),
    h("div", { class: "scale" }, h("span", { text: "0 safe" }), h("span", { text: "30" }), h("span", { text: "70" }), h("span", { text: "100 phishing" })),
    h("div", { class: "checks" }, Object.entries(result.coverage).map(([k, v]) =>
      h("span", { class: "chip " + (v === "ran" ? "ok" : v === "failed" ? "bad" : "off"), title: v,
                  text: (CHECK_NAMES[k] || k) + (v === "ran" ? "" : " · " + v) })))));

  if (PS.hostedNote(result)) parts.push(h("p", { class: "notice", text: PS.hostedNote(result) }));
  if (result.file) parts.push(h("p", { class: "muted small", text: "File: " + result.file.name + " (" + result.file.type +
    (result.file.pages ? ", " + result.file.pages + " pages" : "") +
    (result.file.attachments && result.file.attachments.length ? ", attachments not opened: " + result.file.attachments.join(", ") : "") +
    (result.file.hidden_html_blocks ? ", " + result.file.hidden_html_blocks + " hidden text blocks ignored" : "") + ")" }));

  const reasons = PS.reasons(result);
  if (reasons.length) {
    const items = reasons.map((r, i) => h("li", { hidden: i >= 5 },
      h("span", { class: "tier " + r.tier, text: TIER_NAMES[r.tier] || r.tier }),
      h("span", { text: r.reason }),
      h("span", { class: "pts", text: "+" + r.contribution })));
    const more = reasons.length > 5 ? h("button", { type: "button", class: "samples-more", style: "margin-top:8px",
      onclick: (e) => { items.forEach((li) => { li.hidden = false; }); e.target.remove(); },
      text: "Show all " + reasons.length + " reasons" }) : null;
    parts.push(h("div", { class: "section" },
      h("h3", { text: result.verdict === "safe" ? "Noted, but not enough to flag" : "Why" }),
      h("ul", { class: "reasons" }, items), more));
  }

  const spans = result.verdict === "safe" ? [] : PS.bodySpans(result);
  if (spans.length && text) {
    parts.push(h("div", { class: "section" }, h("h3", { text: "Flagged in the message" }),
      h("div", { class: "text" }, PS.segments(text, spans).map((s) =>
        s.mark ? h("mark", { title: s.title, text: s.text }) : document.createTextNode(s.text)))));
  }

  if (result.urls && result.urls.length) {
    const risks = PS.linkRisks(result);
    parts.push(h("div", { class: "section" }, h("h3", { text: "Links" }), h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, h("th", { text: "Link" }), h("th", { text: "Risk" }), h("th", { class: "num", text: "URL model" }))),
      h("tbody", null, result.urls.map((u) => {
        const risk = risks[u.url];
        return h("tr", null,
          h("td", { class: "url", text: u.url }),
          h("td", null, h("span", { class: "risk " + (risk ? risk.level : "ok"), text: risk ? (risk.level === "risky" ? "Risky" : "Be careful") : "No issue found" }),
            risk ? h("div", { class: "small muted", text: risk.reasons.join(" · ") }) : null),
          h("td", { class: "num", text: u.score == null ? "–" : Math.round(u.score * 100) + "%" }));
      }))))));
  }

  parts.push(h("div", { class: "section" }, h("h3", { text: "Explanation" }),
    h("div", { class: "explain", id: "explainBox" }, h("p", { text: result.explanation }),
      h("p", { class: "src", text: shouldExplain(result) ? "" : "Plain summary built from the findings." }))));

  parts.push(h("p", { class: "muted small", style: "margin-top:12px", text: "Checked in " + Math.round(result.latency_ms) + " ms · " +
    (result.mode === "hosted" ? "on the PhishShield server" : "on this computer") + " · analysis " + result.analysis_id.slice(0, 8) }));
  box.replaceChildren(...parts);
  if (window.innerWidth < 960) box.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* --- wiring -------------------------------------------------------------------------- */

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('[role="tab"]').forEach((t) => t.addEventListener("click", () => selectTab(t.dataset.kind)));
  $("checkBtn").addEventListener("click", check);
  document.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) check(); });
  $("fileIn").addEventListener("change", (e) => setFile(e.target.files[0]));
  const drop = $("drop");
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => { if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]); });
  $("samples").replaceChildren(...SAMPLES.map((s) => h("button", { type: "button", onclick: () => loadSample(s) },
    s.name + " ", h("small", { text: s.tag }))));
});
