/* Results page: renders /api/eval (data/eval.json). No numbers live in this file. */
"use strict";

const SETS = [
  ["text_test_email", "Emails", "test split"],
  ["text_test_sms", "SMS", "test split"],
  ["url_test", "Links", "test split, fixed sample"],
  ["openphish", "Recent phishing links", "OpenPhish, domains never seen in training"],
  ["tranco", "Popular websites", "Tranco top sites, all legitimate"],
  ["uci_sms_ham", "Ordinary SMS", "UCI collection, all legitimate"],
  ["uci_sms_spam", "Spam SMS", "UCI collection; spam, not phishing"],
  ["curated", "Indian messages", "hand-written, synthetic"],
];
const LAYERS = [
  ["system_flagged", "PhishShield (suspicious or phishing)"],
  ["system_phishing", "PhishShield (phishing only)"],
  ["rules_only", "Rules alone"],
  ["url_model", "URL model alone"],
  ["text_model", "Text model alone"],
  ["baseline_35_30_35", "Old 35/30/35 formula"],
];

function tile(k, v, n) {
  return h("div", { class: "tile" }, h("div", { class: "k", text: k }), h("div", { class: "v", text: v }), h("div", { class: "n", text: n }));
}

function render(d) {
  const m = d.metrics, sys = (s) => (m[s] || {}).system_flagged || {};
  const out = [];

  out.push(h("section", null, h("h2", { text: "Headline" }), h("div", { class: "tiles" },
    tile("Emails · F1", fmt.num(sys("text_test_email").f1, 3), "false alarms " + fmt.pct(sys("text_test_email").fpr) + " · n=" + fmt.int(sys("text_test_email").n)),
    tile("SMS · F1", fmt.num(sys("text_test_sms").f1, 3), "false alarms " + fmt.pct(sys("text_test_sms").fpr) + " · n=" + fmt.int(sys("text_test_sms").n)),
    tile("Links · F1", fmt.num(sys("url_test").f1, 3), "false alarms " + fmt.pct(sys("url_test").fpr) + " · n=" + fmt.int(sys("url_test").n)),
    tile("Recent phishing caught", fmt.pct(sys("openphish").recall, 0), "OpenPhish · n=" + fmt.int(sys("openphish").n)),
    tile("Popular sites flagged", fmt.pct(sys("tranco").fpr), sys("tranco").fp + " of " + fmt.int(sys("tranco").n) + " (lower is better)"),
    tile("Ordinary SMS flagged", fmt.pct(sys("uci_sms_ham").fpr, 2), sys("uci_sms_ham").fp + " of " + fmt.int(sys("uci_sms_ham").n) + " (lower is better)"))));

  const rows = [];
  SETS.forEach(([key, name, note]) => {
    if (!m[key]) return;
    LAYERS.forEach(([layer, label], i) => {
      const v = m[key][layer];
      if (!v) return;
      rows.push(h("tr", null,
        h("td", null, i === 0 ? h("b", { text: name }) : "", i === 0 ? h("div", { class: "small muted", text: note }) : null),
        h("td", { text: label }),
        h("td", { class: "num", text: fmt.int(v.n) }),
        h("td", { class: "num", text: fmt.num(v.precision) }),
        h("td", { class: "num", text: fmt.num(v.recall) }),
        h("td", { class: "num", text: fmt.num(v.f1) }),
        h("td", { class: "num", text: fmt.pct(v.fpr, 2) })));
    });
  });
  out.push(h("section", { class: "card" }, h("h2", { text: "Every test set, every layer" }),
    h("p", { class: "muted small", text: "Positive = flagged. Precision: of what was flagged, how much was really phishing. Recall: of the phishing, how much was caught. False alarms: share of legitimate messages flagged." }),
    h("div", { class: "tablewrap" }, h("table", null,
      h("thead", null, h("tr", null, ["Test set", "What was measured", "n", "Precision", "Recall", "F1", "False alarms"].map((t, i) =>
        h("th", { class: i >= 2 ? "num" : null, text: t })))),
      h("tbody", null, rows)))));

  if (d.curated_by_group) {
    out.push(h("section", { class: "card" }, h("h2", { text: "Hand-written Indian messages, by type" }),
      h("p", { class: "muted small", text: "Synthetic examples written by the team. They show behaviour on Indian formats; they aren't an accuracy claim." }),
      h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, h("th", { text: "Type" }), h("th", { text: "Truth" }), h("th", { class: "num", text: "n" }), h("th", { text: "PhishShield said" }))),
        h("tbody", null, Object.entries(d.curated_by_group).map(([g, v]) => h("tr", null,
          h("td", { text: g.replace(/_/g, " ") }), h("td", { text: v.label ? "scam" : "legitimate" }), h("td", { class: "num", text: v.n }),
          h("td", { text: Object.entries(v.verdicts).map(([k, c]) => c + " " + k).join(", ") }))))))));
  }

  const ev = d.evasion;
  if (ev && ev.by_trick) {
    const NAMES = { invisible: "Invisible characters inside words", lookalike_letters: "Cyrillic look-alike letters (аccount)",
                    styled: "Styled letters (𝐒𝐁𝐈)", digit_swap: "Numbers for letters (v3rify, acc0unt)",
                    disguised_link: "Disguised links (hxxp://, sbi-kyc[.]xyz)" };
    out.push(h("section", { class: "card" }, h("h2", { text: "Filter-dodging tricks" }),
      h("p", { class: "muted small", text: "The same " + fmt.int(ev.messages) + " phishing messages, each rewritten with one trick " +
        "scammers use to slip past filters. Caught = scored suspicious or phishing. 'Without' is the same engine with trick-undoing switched off." }),
      h("div", { class: "tiles" },
        tile("Undisguised", fmt.pct((ev.undisguised || {}).recall, 1), "the same messages without tricks"),
        tile("Disguised, without trick-undoing", fmt.pct(ev.without.recall, 1), "n=" + fmt.int(ev.n) + " disguised messages"),
        tile("Disguised, with trick-undoing", fmt.pct(ev.with.recall, 1), "same messages, same engine")),
      h("div", { class: "tablewrap" }, h("table", null,
        h("thead", null, h("tr", null, h("th", { text: "Trick" }), h("th", { class: "num", text: "n" }),
          h("th", { class: "num", text: "Undisguised" }), h("th", { class: "num", text: "Without" }), h("th", { class: "num", text: "With" }))),
        h("tbody", null, Object.entries(ev.by_trick).map(([k, v]) => h("tr", null,
          h("td", { text: NAMES[k] || k }), h("td", { class: "num", text: fmt.int(v.n) }),
          h("td", { class: "num", text: fmt.pct(v.undisguised, 1) }),
          h("td", { class: "num", text: fmt.pct(v.without, 1) }), h("td", { class: "num", text: fmt.pct(v.with, 1) }))))))));
  }

  const cal = d.calibration || {};
  const s = d.scoring || {};
  out.push(h("section", { class: "card" }, h("h2", { text: "How the scoring was tuned" }),
    h("p", { class: "muted small", text: "Scoring settings were chosen on a separate validation split, keeping false alarms at or below " +
      fmt.pct(cal.fpr_limit, 0) + ", before the test sets above were measured once." }),
    h("dl", { class: "kv" },
      h("dt", { text: "Safe below" }), h("dd", { text: s.SAFE_BELOW + " / 100" }),
      h("dt", { text: "Phishing from" }), h("dd", { text: s.PHISHING_FROM + " / 100 (needs proven evidence)" }),
      h("dt", { text: "Most a model can add" }), h("dd", { text: s.ML_MAX + " points" }),
      h("dt", { text: "URL model counts from" }), h("dd", { text: "probability " + s.URL_FLOOR }),
      h("dt", { text: "Text model counts from" }), h("dd", { text: "probability " + s.TEXT_FLOOR }),
      cal.chosen_val ? [h("dt", { text: "Validation, messages" }), h("dd", { text: "precision " + fmt.num(cal.chosen_val.text.precision) + " · recall " + fmt.num(cal.chosen_val.text.recall) + " · false alarms " + fmt.pct(cal.chosen_val.text.fpr) })] : [],
      cal.chosen_val ? [h("dt", { text: "Validation, links" }), h("dd", { text: "precision " + fmt.num(cal.chosen_val.url.precision) + " · recall " + fmt.num(cal.chosen_val.url.recall) + " · false alarms " + fmt.pct(cal.chosen_val.url.fpr) })] : [])));

  const mc = d.model_cards || {};
  out.push(h("section", { class: "card" }, h("h2", { text: "Models and this run" }), h("dl", { class: "kv" },
    mc.url ? [h("dt", { text: "URL model" }), h("dd", { text: mc.url.version + " · trained on " + fmt.int(mc.url.train_n) + " URLs" })] : [],
    mc.text ? [h("dt", { text: "Text model" }), h("dd", { text: mc.text.version + " · trained on " + fmt.int(mc.text.train_n) + " messages" })] : [],
    h("dt", { text: "Measured" }), h("dd", { text: (d.run || {}).generated + " · commit " + (d.run || {}).commit }),
    h("dt", { text: "Reproducible" }), h("dd", { class: "mono", text: "metrics_sha256 " + ((d.run || {}).metrics_sha256 || "").slice(0, 16) })),
    h("h3", { style: "margin-top:14px", text: "Read these numbers with care" }),
    h("ul", null, (d.notes || []).map((n) => h("li", { class: "small", text: n })))));

  document.getElementById("out").replaceChildren(...out);
}

fetch("/api/eval").then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
  .then(render)
  .catch(() => document.getElementById("out").replaceChildren(h("p", { class: "notice",
    text: "No results yet. Run: python -m src.eval.phish_bench" })));
