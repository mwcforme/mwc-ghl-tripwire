/**
 * Local battery for api/tripwire.js — RESCOPED 2026-09-21: conversion and
 * attribution are owned by Curve; the dispatch/sendfail signals were removed
 * (commit ecdbe24). Verifies, against the REAL Supabase with email disabled:
 * all remaining legs ok on live data, no dispatch/sendfail legs remain,
 * healthy estate -> no findings, no warm-container state carryover, dry mode
 * writes/sends nothing, run marker fresh for the deadman.
 * Run: node battery.mjs
 */
import handler from "./api/tripwire.js";

const results = [];
function check(name, cond, detail = "") {
  results.push([name, !!cond]);
  console.log((cond ? "PASS " : "FAIL ") + name + (cond ? "" : " :: " + detail));
}
const mkRes = () => ({ statusCode: 200, body: null, json(x) { this.body = x; } });
const AUTH = process.env.CRON_SECRET ? { authorization: "Bearer " + process.env.CRON_SECRET } : {};
delete process.env.GOOGLE_OAUTH_REFRESH_TOKEN; // email leg disabled locally

const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const H = { apikey: KEY, Authorization: "Bearer " + KEY };

const r1 = mkRes();
await handler({ method: "GET", url: "/api/tripwire", headers: AUTH }, r1);
console.log("\n--- run 1 (live data, no email) ---");
console.log(JSON.stringify(r1.body, null, 1).slice(0, 900));

check(
  "all remaining legs ok",
  r1.body?.legs && Object.values(r1.body.legs).every((v) => v === "ok"),
  JSON.stringify(r1.body?.legs)
);
check(
  "no dispatch/sendfail legs remain (Curve owns conversion)",
  r1.body?.legs?.dispatch === undefined && r1.body?.legs?.sendfail === undefined,
  JSON.stringify(r1.body?.legs)
);
check("healthy estate -> no findings", (r1.body?.findings ?? []).length === 0, JSON.stringify(r1.body?.findings));
check("no email sent locally", (r1.body?.alerts_sent ?? []).length === 0);

const preDry = await fetch(
  `${URL}/rest/v1/ops_alert_log?select=alert_key&alert_key=like.ghl:*&order=created_at.desc&limit=100`,
  { headers: H }
).then((r) => r.json());

const r2 = mkRes();
await handler({ method: "GET", url: "/api/tripwire", headers: AUTH }, r2);
check("second run clean (no warm-container state carryover)", (r2.body?.findings ?? []).length === 0, JSON.stringify(r2.body?.findings));

const r3 = mkRes();
await handler({ method: "GET", url: "/api/tripwire?dry=1", headers: AUTH }, r3);
const postDry = await fetch(
  `${URL}/rest/v1/ops_alert_log?select=alert_key&alert_key=like.ghl:*&order=created_at.desc&limit=100`,
  { headers: H }
).then((r) => r.json());
check("dry mode writes nothing", JSON.stringify(preDry) === JSON.stringify(postDry));
check("dry mode sends no email", (r3.body?.alerts_sent ?? []).length === 0);

const markers = await fetch(
  `${URL}/rest/v1/ops_alert_log?select=created_at&alert_key=like.ghl:state:run:*&order=created_at.desc&limit=1`,
  { headers: H }
).then((r) => r.json());
const ageMin = markers.length ? (Date.now() - Date.parse(markers[0].created_at)) / 60000 : null;
check("run marker fresh (<10 min, deadman dependency)", ageMin != null && ageMin < 10, "age=" + ageMin);

console.log("\n=== BATTERY: " + results.filter((r) => r[1]).length + "/" + results.length + " passed ===");
process.exit(results.some((r) => !r[1]) ? 1 : 0);
