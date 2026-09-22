/**
 * Local battery for api/deadman.js — no live email (OAuth torn down pre-import).
 *
 *  1  auth fail-closed: no header / query-param secret -> 401
 *  2  computeStale pure branches: null -> stale; fresh -> not; 40min -> stale
 *  3  fresh marker planted -> live handler silent (paged=false)
 *  4  unreachable Supabase -> 500 LOUD with probe error (not silent 200)
 *  5  env missing -> 500 config_missing (the guard the old file lacked)
 *
 * Run: node deadman-battery.mjs  (same env as battery.mjs)
 */
const results = [];
function check(name, cond, detail = "") {
  results.push([name, !!cond]);
  console.log((cond ? "PASS " : "FAIL ") + name + (cond ? "" : " :: " + detail));
}
const mkRes = () => ({ statusCode: 200, body: null, json(x) { this.body = x; } });

// env teardown BEFORE dynamic import (no module-scope OAuth capture in deadman either)
import { execSync } from "node:child_process";

const OAUTH_KEYS = [
  "GOOGLE_OAUTH_REFRESH_TOKEN",
  "GOOGLE_OAUTH_CLIENT_ID",
  "GOOGLE_OAUTH_CLIENT_SECRET",
  "GOOGLE_OAUTH_TOKEN_URI",
];
for (const k of OAUTH_KEYS) delete process.env[k];
if (process.env.MWC_TRIPWIRE_ENV) {
  for (const line of execSync(`cat "${process.env.MWC_TRIPWIRE_ENV}"`).toString().split("\n")) {
    const m = line.match(/^([A-Z_]+)="([^"]*)"$/);
    if (m && !OAUTH_KEYS.includes(m[1])) process.env[m[1]] = m[2];
  }
}
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY || !process.env.CRON_SECRET) {
  console.error("FATAL: SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY + CRON_SECRET required");
  process.exit(2);
}
const secret = process.env.CRON_SECRET;
const AUTH = { authorization: "Bearer " + secret };

const { default: handler, computeStale } = await import("./api/deadman.js");

const URL = process.env.SUPABASE_URL.replace(/\/$/, "");
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const H = { apikey: KEY, Authorization: "Bearer " + KEY, "Content-Type": "application/json" };
const BASE = `${URL}/rest/v1/ops_alert_log`;

// ---------- 1) auth fail-closed ----------
const ra = mkRes();
await handler({ method: "GET", url: "/api/deadman", headers: {} }, ra);
check("auth: no header -> 401", ra.statusCode === 401, JSON.stringify(ra.body));
const rq = mkRes();
await handler({ method: "GET", url: `/api/deadman?secret=${encodeURIComponent(secret)}`, headers: {} }, rq);
check("auth: query-param secret REJECTED", rq.statusCode === 401, JSON.stringify(rq.body));

// ---------- 2) computeStale pure branches ----------
check("computeStale: no markers (null) -> STALE", computeStale(null).stale === true);
check("computeStale: fresh (5 min) -> not stale", computeStale(Date.now() - 5 * 60000).stale === false);
{
  const s = computeStale(Date.now() - 40 * 60000);
  check("computeStale: 40 min -> stale", s.stale === true);
  check("computeStale: staleMin reported (~40)", typeof s.staleMin === "number" && s.staleMin > 39.9 && s.staleMin < 40.1, "staleMin=" + s.staleMin);
}

// ---------- 3) fresh marker -> silent ----------
{
  const key = `ghl:state:run:battery-fresh-${Date.now()}`;
  const post = await fetch(BASE, {
    method: "POST",
    headers: { ...H, Prefer: "return=representation" },
    body: JSON.stringify({ alert_key: key, check_id: "ghl_state", severity: "run" }),
  });
  check("battery marker planted", post.ok, "POST " + post.status);
  const r1 = mkRes();
  await handler({ method: "GET", url: "/api/deadman", headers: AUTH }, r1);
  check("fresh marker -> silent", r1.body?.paged === false && r1.body?.ok === true, JSON.stringify(r1.body));
  const del = await fetch(`${BASE}?alert_key=eq.${encodeURIComponent(key)}`, { method: "DELETE", headers: H });
  check("battery marker cleaned", del.status === 204 || del.status === 200, "delete " + del.status);
}

// ---------- 4) unreachable Supabase -> LOUD 500 ----------
{
  const saveUrl = process.env.SUPABASE_URL;
  process.env.SUPABASE_URL = "https://definitely-unreachable.invalid";
  const { default: h2 } = await import("./api/deadman.js?bust=1");
  const r2 = mkRes();
  await h2({ method: "GET", url: "/api/deadman", headers: AUTH }, r2);
  process.env.SUPABASE_URL = saveUrl;
  check(
    "probe failure -> 500 LOUD with probe error",
    r2.statusCode === 500 && /probe/i.test(String(r2.body?.error)),
    JSON.stringify(r2.body).slice(0, 200)
  );
}

// ---------- 5) env-missing guard ----------
{
  const saveUrl = process.env.SUPABASE_URL;
  delete process.env.SUPABASE_URL;
  const { default: h3 } = await import("./api/deadman.js?bust=2");
  const r3 = mkRes();
  await h3({ method: "GET", url: "/api/deadman", headers: AUTH }, r3);
  process.env.SUPABASE_URL = saveUrl;
  check(
    "env missing -> 500 with env error",
    r3.statusCode === 500 && /env missing/i.test(String(r3.body?.error)),
    JSON.stringify(r3.body)
  );
}

console.log("\n=== DEADMAN BATTERY: " + results.filter((r) => r[1]).length + "/" + results.length + " passed ===");
process.exit(results.some((r) => !r[1]) ? 1 : 0);
