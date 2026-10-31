/* Sample emails for the Gmail test page. Opening one replaces the thread the way Gmail
   does (no reload), so the content script's MutationObserver has to pick it up. */
(function () {
  "use strict";

  const SAMPLES = {
    "SBI phishing": {
      subject: "Account blocked: complete KYC",
      name: "SBI Alerts", email: "alert@sbi-kyc.xyz",
      body: [
        "Dear customer,",
        "Your SBI KYC is pending and your account will be blocked within 24 hours.",
        "Verify your details now at ", ["onlinesbi.sbi", "http://sbi-kyc.xyz/login"], " to avoid suspension.",
        "Regards, SBI Team",
      ],
    },
    "HDFC statement (legit)": {
      subject: "Your account statement is ready",
      name: "HDFC Bank", email: "alerts@hdfcbank.net",
      body: [
        "Dear Customer,",
        "Your statement for October is ready. ",
        ["View statement", "https://www.hdfcbank.com/personal/statement"], " in NetBanking.",
        "Never share your OTP, PIN or password with anyone. HDFC Bank never asks for them.",
      ],
    },
    "Lottery, no link": {
      subject: "Congratulations!!",
      name: "KBC Lottery", email: "kbc.winner2024@gmail.com",
      body: [
        "Congratulations! You have won Rs 25,00,000 in the KBC lottery 🎉🎉.",
        "Pay Rs 5,000 processing fee to receive your prize. Reply with your bank account details.",
      ],
    },
    "Meeting note (legit)": {
      subject: "Re: project sync",
      name: "Priya Sharma", email: "priya@example.org",
      body: ["Hi, moving our sync to 4pm tomorrow. Notes are on the shared doc. See you then 🙂"],
    },
    "HTML in email text": {
      subject: "Weird message",
      name: "Unknown", email: "x@example.net",
      body: ["This text contains <script>alert('xss')</script> and <img src=x onerror=alert(1)> as plain words. ",
             "Login at ", ["https://paypa1.com/secure", "https://paypa1.com/secure"], " to unlock your PayPal account."],
    },
  };

  function render(name) {
    const s = SAMPLES[name];
    document.getElementById("subject").textContent = s.subject;
    const msg = document.createElement("div");
    msg.className = "adn";
    msg.dataset.messageId = Math.random().toString(36).slice(2);
    const head = document.createElement("div");
    head.className = "sender";
    const from = document.createElement("span");
    from.className = "gD";
    from.setAttribute("email", s.email);
    from.setAttribute("name", s.name);
    from.textContent = s.name;
    const addr = document.createElement("span");
    addr.className = "addr";
    addr.textContent = "<" + s.email + ">";
    head.append(from, " ", addr);
    const body = document.createElement("div");
    body.className = "a3s aiL";
    s.body.forEach((part) => {
      if (Array.isArray(part)) {
        const a = document.createElement("a");
        a.textContent = part[0];
        a.href = part[1];
        a.addEventListener("click", (e) => e.preventDefault());  // test page: never follow sample links
        body.append(a);
      } else {
        const p = document.createElement(part.endsWith(" ") ? "span" : "div");
        p.textContent = part;
        body.append(p);
      }
    });
    msg.append(head, body);
    document.getElementById("thread").replaceChildren(msg);
    history.replaceState(null, "", "#" + encodeURIComponent(name));
  }

  // "Simulate server offline": make the API calls fail the way a stopped server does.
  const realFetch = window.fetch.bind(window);
  window.fetch = function (url, init) {
    if (document.getElementById("offline").checked && String(url).includes("/api/")) {
      return Promise.reject(new TypeError("Failed to fetch"));
    }
    return realFetch(url, init);
  };

  const bar = document.getElementById("samples");
  Object.keys(SAMPLES).forEach((name) => {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = name;
    b.addEventListener("click", () => render(name));
    bar.append(b);
  });
  const start = decodeURIComponent(location.hash.slice(1));
  render(SAMPLES[start] ? start : "SBI phishing");
})();
