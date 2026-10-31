// Unit tests for extension/shared/verdict.js. Run: node --test extension/test
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const PS = require("../shared/verdict.js");

const f = (o) => Object.assign({ id: "f1", label: "X", text: "x", reason: "r", tier: "heuristic", family: "content",
  field: "body", source: "rule", start_u16: null, end_u16: null, contribution: 5 }, o);

test("headline never shows green when checks are limited or the call failed", () => {
  assert.equal(PS.presentation({ verdict: "safe", confidence: "low", score: 3 }).tone, "limited");
  assert.equal(PS.presentation({ verdict: "safe", confidence: "high", score: 3 }).tone, "safe");
  assert.equal(PS.presentation({ error: "offline" }).tone, "error");
  assert.match(PS.presentation({ error: "offline" }).title, /Couldn't check/);
  assert.equal(PS.presentation(null).tone, "loading");
  assert.equal(PS.presentation({ verdict: "phishing", confidence: "medium", score: 88 }).tone, "danger");
  assert.equal(PS.presentation({ verdict: "suspicious", confidence: "high", score: 40 }).tone, "warn");
});

test("reasons come only from findings that added points, strongest first, de-duplicated", () => {
  const r = PS.reasons({ findings: [
    f({ reason: "weak", contribution: 2 }), f({ reason: "zero", contribution: 0 }),
    f({ reason: "strong", contribution: 40 }), f({ reason: "strong", contribution: 10 }),
  ] });
  assert.deepEqual(r.map((x) => x.reason), ["strong", "weak"]);
});

test("body spans use UTF-16 offsets and merge overlaps", () => {
  const text = "🎁 You won a prize! Claim now";
  const res = { findings: [
    f({ start_u16: 3, end_u16: 10, text: "You won", reason: "a" }),
    f({ start_u16: 7, end_u16: 18, text: "won a prize", reason: "b" }),
    f({ start_u16: 20, end_u16: 25, text: "Claim", reason: "c", contribution: 0 }),  // no points: not highlighted
  ] };
  const spans = PS.bodySpans(res);
  assert.equal(spans.length, 1);
  assert.equal(text.slice(spans[0].start, spans[0].end), "You won a prize");
  assert.deepEqual(spans[0].reasons, ["a", "b"]);
  const segs = PS.segments(text, spans);
  assert.equal(segs.map((s) => s.text).join(""), text);
  assert.deepEqual(segs.filter((s) => s.mark).map((s) => s.text), ["You won a prize"]);
});

test("link risks: confirmed or URL-model findings are risky; weak heuristics alone are ignored", () => {
  const risks = PS.linkRisks({ findings: [
    f({ family: "link", tier: "confirmed", text: "http://sbi-kyc.xyz/login", reason: "imitates SBI", contribution: 30 }),
    f({ family: "link", text: "http://example.org/", reason: "not https", contribution: 4 }),
    f({ family: "ml", source: "url-model", tier: "ml", text: "http://odd.top/a", reason: "model", contribution: 12 }),
    f({ family: "link", text: "https://bit.ly/x", reason: "shortened", contribution: 10 }),
  ] });
  assert.equal(risks["http://sbi-kyc.xyz/login"].level, "risky");
  assert.equal(risks["http://odd.top/a"].level, "risky");
  assert.equal(risks["https://bit.ly/x"].level, "caution");
  assert.equal(risks["http://example.org/"], undefined);
});

test("hosted mode is disclosed; local API detection", () => {
  assert.match(PS.hostedNote({ mode: "hosted" }), /sent to the PhishShield server/);
  assert.equal(PS.hostedNote({ mode: "local" }), "");
  assert.equal(PS.isLocalApi("http://localhost:8000"), true);
  assert.equal(PS.isLocalApi("http://127.0.0.1:8000"), true);
  assert.equal(PS.isLocalApi("https://phishshield.onrender.com"), false);
  assert.equal(PS.isLocalApi("not a url"), false);
});
