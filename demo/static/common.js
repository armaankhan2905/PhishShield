// Shared by every PhishShield page: header/nav, helpers, API calls.
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const pct = (x) => `${(x * 100).toFixed(1)}%`;
const num = (x) => (x == null ? "—" : x);
const ms = (x) => (x == null ? "" : `${x < 0.1 ? x.toFixed(3) : x.toFixed(2)} ms`);
const kv = (rows) => `<dl class="kv">${rows.filter((r) => r[1] != null && r[1] !== "").map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;

const LOCAL = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
const WHERE = LOCAL ? "Local" : "Hosted demo";

const SAMPLES = {
  "Checkout form": "Name: Priya Sharma\nCard number: 4532 0151 1283 0366\nExpiry: 09/28\nPhone: +91 98765 43210\nEmail: priya.sharma@example.com",
  "Bank SMS": "Your OTP is 482913 for txn of Rs 2,499 at AMAZON. Do not share. If not you, call 1800-123-4567 or visit https://bank.example.com/report",
  "KYC upload": "PAN: ABCDE1234F\nRegistered mobile 9876543210\nLogin from IP 203.0.113.42 at 10:42",
  "Support chat": "hey, my card 4111-1111-1111-1111 got declined. reach me at test@example.com or 9123456789. verification code 0042",
};

const PAGES = [
  ["/", "Live demo"],
  ["/ask", "Ask documents"],
  ["/pipeline", "Pipeline"],
  ["/training", "Model training"],
  ["/evaluation", "Evaluation"],
];

function renderChrome() {
  const here = location.pathname.replace(/\/$/, "") || "/";
  $("top").innerHTML = `
    <header>
      <a class="brand" href="/">
        <div class="logo" aria-hidden="true"></div>
        <div><h1>PhishShield</h1><p class="tag">Spot phishing, scams and lookalike links before you click.</p></div>
      </a>
      <div id="status" class="pill"><span class="dot"></span><span id="statusText">Connecting…</span></div>
    </header>
    <nav class="tabs" aria-label="Pages">
      ${PAGES.map(([href, name], i) => `<a href="${href}"${href === here ? ' aria-current="page"' : ""}><span>0${i + 1}</span>${name}</a>`).join("")}
    </nav>`;
  const i = PAGES.findIndex(([href]) => href === here);
  const nx = $("next");
  if (nx && i >= 0) {
    const prev = PAGES[i - 1], next = PAGES[i + 1];
    nx.innerHTML = (prev ? `<a href="${prev[0]}"><small>← Previous</small>${prev[1]}</a>` : "<span></span>") +
                   (next ? `<a class="fwd" href="${next[0]}"><small>Next →</small>${next[1]}</a>` : "");
  }
  const f = $("foot");
  if (f) f.innerHTML = `
    <span>Detection runs on ${LOCAL ? "the local Python backend" : "this demo's server (in real use it runs on-device)"}.</span>
    <span>Types: CARD · PHONE · PAN · EMAIL · IP · URL · OTP</span>
    <span>API: <code>POST /api/sanitize</code> · <code>GET /api/pipeline</code></span>`;
  fetch("/api/health").then((r) => r.ok && setStatus(true, `${WHERE} · 0 leaks`)).catch(() => setStatus(false, "Backend offline"));
}

function setStatus(ok, text) {
  $("status").classList.toggle("bad", !ok);
  $("statusText").textContent = text;
}

function renderOutput(s) {
  if (!s) return '<span class="empty">Safe-to-share text appears here.</span>';
  return esc(s).replace(/\[REDACTED:([A-Z]+)\]/g, '<span class="ph">[REDACTED:$1]</span>');
}

function addSamples(el, onPick) {
  for (const [name, text] of Object.entries(SAMPLES)) {
    const b = document.createElement("button");
    b.className = "sample"; b.textContent = name;
    b.onclick = () => onPick(text);
    el.appendChild(b);
  }
}

// The last text typed on any page, so Pipeline can replay the demo's input.
const lastInput = {
  get() { try { return sessionStorage.getItem("pl:last"); } catch { return null; } },
  set(v) { try { sessionStorage.setItem("pl:last", v); } catch {} },
};

// Debounced, race-safe POST /api/sanitize driver for a textarea.
function liveSanitize(textarea, { onResult, onError }) {
  let last = null, timer = null, seq = 0;
  const go = async () => {
    const text = textarea.value;
    if (text === last) return;
    last = text;
    lastInput.set(text);
    const id = ++seq;
    try {
      const r = await fetch("/api/sanitize", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }),
      });
      const body = await r.json();
      if (id !== seq) return;
      if (!r.ok) throw new Error(typeof body.detail === "string" ? body.detail : "Request rejected");
      onResult(body);
      setStatus(body.leaked === 0, body.leaked === 0 ? `${WHERE} · 0 leaks` : `${body.leaked} leaked`);
    } catch (e) {
      if (id !== seq) return;
      last = null;
      onError(e);
      setStatus(false, "Blocked");
    }
  };
  const run = (now) => { clearTimeout(timer); now ? go() : (timer = setTimeout(go, 180)); };
  textarea.addEventListener("input", () => run(false));
  return run;
}

// Floating sparks behind every page (decorative).
function sparks(n = 14) {
  for (let i = 0; i < n; i++) {
    const p = document.createElement("i");
    p.className = "pt"; p.setAttribute("aria-hidden", "true");
    p.style.left = `${Math.random() * 100}vw`;
    p.style.animationDuration = `${8 + Math.random() * 12}s`;
    p.style.animationDelay = `${-Math.random() * 20}s`;
    document.body.appendChild(p);
  }
}

// The lens: raw text underneath, the sanitized view revealed inside a moving
// circle. Redaction bars are the same width as the text they hide.
// The card scrolls for long text (PDF pages); the lens lives in content
// coordinates, so it stays on the same words while you scroll.
function lens(stage) {
  stage.innerHTML = '<div class="lens-content"><div class="layer raw"></div><div class="layer safe" aria-hidden="true"></div><div class="ring" aria-hidden="true"></div></div><div class="scroll-hint" aria-hidden="true" hidden>Scroll for more ↓</div>';
  const content = stage.querySelector(".lens-content"), raw = stage.querySelector(".raw"), safe = stage.querySelector(".safe");
  const hint = stage.querySelector(".scroll-hint");
  const at = (x, y) => { content.style.setProperty("--x", `${x}px`); content.style.setProperty("--y", `${y}px`); content.style.setProperty("--r", "90px"); };
  // Idle: orbit over the text that's currently in view.
  let t = 0, auto = setInterval(() => {
    t += 0.03;
    const view = stage.clientHeight, h = Math.min(view, raw.offsetHeight - stage.scrollTop), w = stage.clientWidth;
    at(w / 2 + Math.cos(t) * Math.min(190, w / 3), stage.scrollTop + h / 2 + Math.sin(t * 1.3) * Math.max(8, Math.min(80, h / 2 - 40)));
  }, 30);
  const stop = () => { clearInterval(auto); auto = null; };
  let last = null; // last pointer position (viewport coords), to re-aim after a scroll
  const aim = () => { if (!last) return; const r = stage.getBoundingClientRect(); at(last.x - r.left + stage.scrollLeft, last.y - r.top + stage.scrollTop); };
  const move = (e) => { last = { x: e.clientX, y: e.clientY }; aim(); };
  const updateHint = () => { hint.hidden = stage.scrollHeight - stage.clientHeight - stage.scrollTop < 8; };
  stage.addEventListener("pointerenter", stop);
  stage.addEventListener("pointermove", move);
  stage.addEventListener("pointerdown", (e) => { stop(); move(e); });
  stage.addEventListener("pointerleave", () => { last = null; });
  stage.addEventListener("scroll", () => { aim(); updateHint(); }, { passive: true });
  return {
    show(text, dets) {
      let html = "", cur = 0;
      for (const d of dets) {
        html += esc(text.slice(cur, d.start)) + `<span class="s" data-l="${esc(d.label)}">${esc(text.slice(d.start, d.end))}</span>`;
        cur = d.end;
      }
      html += esc(text.slice(cur));
      raw.innerHTML = text ? html : '<span class="empty">Type something below to inspect it…</span>';
      safe.innerHTML = text ? html : "";
      requestAnimationFrame(updateHint);
    },
    // Back to the top when new content (e.g. another PDF page) is shown.
    reset() { stage.scrollTop = 0; requestAnimationFrame(updateHint); },
  };
}

// ---- private knowledge base -------------------------------------------------
// A random id per browser scopes the server-side RAG index, so visitors of a
// shared deployment never see (or clear) each other's documents.
const SID = (() => {
  const make = () => (crypto.randomUUID ? crypto.randomUUID().replace(/-/g, "") : Math.random().toString(36).slice(2) + Date.now().toString(36));
  try {
    let s = localStorage.getItem("pl:sid");
    if (!s || !/^[A-Za-z0-9_-]{8,64}$/.test(s)) { s = make(); localStorage.setItem("pl:sid", s); }
    return s;
  } catch { return (window._plSid ??= make()); }
})();
const ragFetch = (url, opts = {}) => fetch(url, { ...opts, headers: { ...(opts.headers || {}), "X-PL-Session": SID } });

// ---- PDFs -----------------------------------------------------------------
const SAMPLE_PDFS = { "Bank statement PDF": "bank_statement.pdf", "KYC form PDF": "kyc_form.pdf" };

// POST a PDF to /api/document; the server sanitizes every page (and indexes it for RAG).
async function uploadPdf(blob, name, index = true) {
  const fd = new FormData();
  fd.append("file", blob, name);
  fd.append("index", String(index));
  const r = await ragFetch("/api/document", { method: "POST", body: fd });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof body.detail === "string" ? body.detail : "Upload failed");
  return body;
}

async function samplePdf(file) {
  const r = await fetch(`/samples/${file}`);
  if (!r.ok) throw new Error("Sample not found");
  return r.blob();
}

// Wire a hidden <input type=file> + sample buttons to one handler(blob, name).
function pdfPickers(fileInput, samplesEl, onPdf) {
  fileInput.addEventListener("change", () => {
    const f = fileInput.files[0];
    if (f) onPdf(f, f.name);
    fileInput.value = "";
  });
  for (const [label, file] of Object.entries(SAMPLE_PDFS)) {
    const b = document.createElement("button");
    b.className = "sample pdf"; b.textContent = label;
    b.onclick = async () => onPdf(await samplePdf(file), file);
    samplesEl.appendChild(b);
  }
}

let _pipeline = null;
const getPipeline = () => (_pipeline ??= fetch("/api/pipeline").then((r) => {
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}));

renderChrome();
sparks();
