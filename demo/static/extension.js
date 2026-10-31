/* "Get the extension" page. The extension marks the app's pages with
   <html data-phishshield-extension="<version>"> (extension/content/app-bridge.js),
   which is how this page knows it's installed. */
"use strict";

const $ = (id) => document.getElementById(id);
let INFO = null;

function newer(a, b) {  // is version a newer than b?
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0);
  }
  return false;
}

function browserName() {
  const ua = navigator.userAgent;
  if (/Edg\//.test(ua)) return "edge";
  if (/OPR\/|Opera/.test(ua)) return "opera";
  if (/Firefox\//.test(ua)) return "firefox";
  if (/Chrome\//.test(ua)) return "chrome";
  return "other";
}

function render() {
  const installed = document.documentElement.dataset.phishshieldExtension;
  const box = $("installStatus");
  const browser = browserName();
  const parts = [];
  if (installed && INFO && newer(INFO.version, installed)) {
    parts.push(h("h2", { text: "Update available" }),
      h("p", { text: "You have version " + installed + "; this server has " + INFO.version + ". Download it again, replace the old " +
        "folder's contents, then click the reload icon on PhishShield in the extensions page." }));
    box.className = "card install warn";
  } else if (installed) {
    parts.push(h("h2", { text: "PhishShield extension is installed" }),
      h("p", { text: "Version " + installed + ". Open Gmail and open any email: a PhishShield banner appears above it. " +
        "Tabs that were already open need a refresh." }),
      h("div", { class: "row" }, h("a", { class: "btn", href: "https://mail.google.com", target: "_blank", rel: "noopener", text: "Open Gmail" })));
    box.className = "card install ok";
    $("steps").hidden = true;
  } else if (browser === "firefox" || browser === "other") {
    parts.push(h("h2", { text: "Use Chrome or Edge" }),
      h("p", { text: "The PhishShield extension runs in Google Chrome and Microsoft Edge. Open this page in one of them to install it." }));
    box.className = "card install warn";
  } else if (INFO && INFO.store_url) {
    parts.push(h("h2", { text: "Not installed yet" }),
      h("p", { text: "Install it from the Chrome Web Store in one click." }),
      h("div", { class: "row" }, h("a", { class: "btn", href: INFO.store_url, target: "_blank", rel: "noopener", text: "Add to Chrome" })));
    box.className = "card install";
    $("steps").hidden = true;
  } else {
    parts.push(h("h2", { text: "Not installed yet" }),
      h("p", { text: "Follow the four steps below. This page will notice as soon as it's on." }));
    box.className = "card install";
  }
  box.replaceChildren(...parts);
}

document.addEventListener("DOMContentLoaded", async () => {
  if (browserName() === "edge") $("extUrl").textContent = "edge://extensions";
  $("copyBtn").addEventListener("click", async () => {
    const text = $("extUrl").textContent;
    try { await navigator.clipboard.writeText(text); $("copied").textContent = "Copied. Paste it into a new tab."; }
    catch (e) { const r = document.createRange(); r.selectNodeContents($("extUrl")); getSelection().removeAllRanges(); getSelection().addRange(r);
                $("copied").textContent = "Press Ctrl + C to copy."; }
  });
  try {
    INFO = await (await fetch("/api/extension")).json();
    $("downloadBtn").href = INFO.download;
    $("zipName").textContent = "phishshield-extension-" + INFO.version + ".zip";
    $("versionNote").textContent = "Version " + INFO.version;
  } catch (e) { /* the download link still works */ }
  render();
  window.addEventListener("phishshield-extension", render);
  // The extension may load after this page; keep checking for a while so the page updates without a refresh.
  let tries = 0;
  const timer = setInterval(() => {
    tries++;
    if (document.documentElement.dataset.phishshieldExtension || tries > 300) { clearInterval(timer); render(); }
  }, 2000);
});
