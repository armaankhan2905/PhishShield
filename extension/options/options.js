/* Options: server address and where to check. A non-local address needs the user's
   permission for that origin (requested on Save, which counts as a user gesture). */
(function () {
  "use strict";
  const PS = globalThis.PS;
  const $ = (id) => document.getElementById(id);

  function normalise(value) {
    const u = new URL(value.trim() || PS.DEFAULTS.apiBase);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Use an http:// or https:// address.");
    return u.origin;
  }

  async function save() {
    const out = $("saved");
    let apiBase;
    try { apiBase = normalise($("apiBase").value); } catch (e) { out.textContent = e.message; out.className = "status bad"; return; }
    if (!PS.isLocalApi(apiBase) && chrome.permissions) {
      const granted = await chrome.permissions.request({ origins: [apiBase + "/*"] });
      if (!granted) { out.textContent = "Permission for " + apiBase + " was not granted, so nothing was saved."; out.className = "status bad"; return; }
    }
    await chrome.storage.sync.set({ apiBase, gmail: $("gmail").checked, linkScan: $("linkScan").value });
    $("apiBase").value = apiBase;
    out.textContent = "Saved. Reload open tabs to apply.";
    out.className = "status ok";
  }

  async function test() {
    const out = $("testResult");
    out.textContent = "Testing…";
    out.className = "status";
    const resp = await PS.send({ type: "health" });
    if (!resp.ok) { out.textContent = "Can't reach the saved server (" + resp.error + "). Save first if you changed it."; out.className = "status bad"; return; }
    const m = resp.data.models || {};
    out.textContent = "Connected · URL model " + m.url + " · text model " + m.text;
    out.className = "status ok";
  }

  PS.settings().then((s) => {
    $("apiBase").value = s.apiBase;
    $("gmail").checked = s.gmail;
    $("linkScan").value = s.linkScan;
  });
  $("save").addEventListener("click", save);
  $("test").addEventListener("click", test);
})();
