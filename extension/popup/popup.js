/* Popup: server status and a paste-to-check box. Every string goes in with textContent. */
(function () {
  "use strict";
  const PS = globalThis.PS;
  const $ = (id) => document.getElementById(id);

  function li(text) { const n = document.createElement("li"); n.textContent = text; return n; }

  function show(result) {
    const p = PS.presentation(result);
    $("result").hidden = false;
    $("result").className = p.tone;
    $("title").textContent = p.title;
    $("subtitle").textContent = p.subtitle;
    $("reasons").replaceChildren(...(result && !result.error ? PS.reasons(result, 5).map((r) => li(r.reason)) : []));
    const text = $("text");
    text.replaceChildren();
    const spans = result && !result.error && result.verdict !== "safe" ? PS.bodySpans(result) : [];
    $("textLabel").hidden = text.hidden = !spans.length;
    PS.segments($("msg").value, spans).forEach((s) => {
      const n = document.createElement(s.mark ? "mark" : "span");
      n.textContent = s.text;
      if (s.title) n.title = s.title;
      text.append(n);
    });
    $("explanation").textContent = result && !result.error ? result.explanation || "" : "";
    $("meta").textContent = result && !result.error
      ? ["Confidence: " + result.confidence, PS.hostedNote(result)].filter(Boolean).join(" · ") : "";
  }

  async function check() {
    const text = $("msg").value;
    if (!text.trim()) { $("msg").focus(); return; }
    $("check").disabled = true;
    show(null);
    const resp = await PS.send({ type: "analyze", payload: { text } });
    show(resp.ok ? resp.data : { error: resp.error });
    $("check").disabled = false;
  }

  async function status() {
    const resp = await PS.send({ type: "health" });
    const s = $("status");
    if (!resp.ok) { s.textContent = "Server offline"; s.className = "status bad"; return; }
    const m = resp.data.models || {};
    const ready = m.url === "loaded" && m.text === "loaded";
    s.textContent = ready ? "Server ready" : "Server up · models " + [m.url, m.text].join("/");
    s.className = "status " + (ready ? "ok" : "");
  }

  $("check").addEventListener("click", check);
  $("msg").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) check(); });
  status();
})();
