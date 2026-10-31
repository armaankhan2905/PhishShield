/* Stop page shown in place of a risky site (opened by background.js). Text from the API is
   inserted with textContent only. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const id = location.hash.slice(1);
  let url = "";

  function goBack() {
    // A tab that was opened just for this site has nowhere to go back to: close it.
    if (history.length > 1) history.back();
    else chrome.runtime.sendMessage({ type: "closeTab" });
  }

  chrome.runtime.sendMessage({ type: "stopInfo", id }, (resp) => {
    if (!resp || !resp.ok) {
      $("title").textContent = "This warning has expired.";
      $("why").textContent = "Go back and open the link again to re-check it.";
      $("go").hidden = true;
      return;
    }
    const risk = resp.data;
    url = risk.url;
    if (risk.level !== "risky") {
      document.body.classList.add("caution");
      $("card").classList.add("caution");
      $("title").textContent = "Be careful with this site.";
      document.title = "PhishShield: be careful with this site";
    }
    (risk.reasons || []).forEach((r) => { const li = document.createElement("li"); li.textContent = r; $("reasons").append(li); });
    $("url").textContent = url;
  });

  $("back").addEventListener("click", goBack);
  $("go").addEventListener("click", () => {
    if (!url) return;
    chrome.runtime.sendMessage({ type: "allow", url }, () => location.replace(url));
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") goBack(); });
  $("back").focus();
})();
