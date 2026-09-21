/**
 * Local battery for api/deadman.js — stale marker pages, fresh marker silent,
 * missing marker pages, dedupe not needed (hourly cadence is the cap).
 * Run: node deadman-battery.mjs
 */
import handler from "./api/deadman.js";

const results = [];
function check(name, cond, detail = "") {
  results.push([name, !!cond]);
  console.log((cond ? "PASS " : "FAIL ") + name + (cond ? "" : " :: " + detail));
}

// email disabled: no GOOGLE_OAUTH env
delete process.env.GOOGLE_OAUTH_REFRESH_TOKEN;

const mkRes = () => ({ statusCode: 200, body: null, json(x) { this.body = x; } });
const AUTH = process.env.CRON_SECRET ? { authorization: "Bearer " + process.env.CRON_SECRET } : {};

// -- 1) missing markers (no rows at all in a fresh filter) -> paged=true path taken
//    (email fails silently without oauth creds; paged flag still set)
const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const H = { apikey: KEY, Authorization: "Bearer " + KEY, "Content-Type": "application/json" };

// plant a FRESH marker (now) and confirm silence
const now = new Date().toISOString();
await fetch(`${URL}/rest/v1/ops_alert_log`, {
  method: "POST",
  headers: { ...H, Prefer: "return=representation" },
  body: JSON.stringify({ alert_key: `ghl:state:run:battery-fresh-${Date.now()}`, check_id: "ghl_state", severity: "run" }),
});
const r1 = mkRes();
await handler({ method: "GET", url: "/api/deadman", headers: AUTH }, r1);
check("fresh marker -> silent", r1.body?.paged === false && r1.body?.ok === true, JSON.stringify(r1.body));

// age that marker 40 min -> paged
const key = r1.body?.newest_run_marker ? undefined : undefined;
const list = await fetch(`${URL}/rest/v1/ops_alert_log?select=alert_key&alert_key=like.ghl:state:run:battery-fresh-*&order=created_at.desc&limit=1`, { headers: H }).then((r) => r.json());
const k = list[0].alert_key;
const past = new Date(Date.now() - 40 * 60000).toISOString();
const patch = await fetch(`${URL}/rest/v1/ops_alert_log?alert_key=eq.${encodeURIComponent(k)}`, {
  method: "PATCH", headers: H, body: JSON.stringify({ created_at: past }),
});
const r2 = mkRes();
await handler({ method: "GET", url: "/api/deadman", headers: AUTH }, r2);
check("stale marker (40min) -> pages", r2.body?.paged === true && r2.body?.ok === false, JSON.stringify(r2.body));

// cleanup battery marker
const del = await fetch(`${URL}/rest/v1/ops_alert_log?alert_key=eq.${encodeURIComponent(k)}`, { method: "DELETE", headers: H });
check("battery marker cleaned", del.status === 204 || del.status === 200, "delete " + del.status);

console.log("\n=== DEADMAN BATTERY: " + results.filter((r) => r[1]).length + "/" + results.length + " passed ===");
process.exit(results.some((r) => !r[1]) ? 1 : 0);
