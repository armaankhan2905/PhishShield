/* Tells the PhishShield web app that this extension is installed, and which version, so its
   "Get the extension" page can confirm the install. Runs only on the app's own pages
   (see manifest.json) and shares nothing but the version number. */
(function () {
  "use strict";
  const version = chrome.runtime.getManifest().version;
  document.documentElement.dataset.phishshieldExtension = version;
  window.dispatchEvent(new CustomEvent("phishshield-extension", { detail: { version } }));
})();
