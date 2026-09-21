/**
 * Local battery for api/tripwire.js — verifies each check's evaluation logic,
 * the insert-first dedupe, the 6h repeat-cap re-arm, and the blindness legs,
 * against the REAL Supabase (read for state; inserts confined to ghl: keys)
 * with email disabled. Run: node battery.mjs
 */
import handler from "./api/tripwire.js";

const env = {
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
  GHL_API_KEY: process.env.GHL_API_KEY,
  GHL_LOCATION_ID: "Ghstz8eIsHWLeXek47dk",
  CRON_SECRET: "", // no auth locally
};

const results = [];
function check(name, cond, detail = "") {
  results.push([name, !!cond]);
  console.log((cond ? "PASS " : "FAIL ") + name + (cond ? "" : " :: " + detail));
}

function mockRes() {
  return {
    statusCode: 200,
    body: null,
    json(x) {
      this.body = x;
    },
  };
}

// -- 1) healthy run against live data: legs report, findings only for the
//       real known incident (dispatch), everything else suppressed by dedupe.
process.env.SUPABASE_URL = env.SUPABASE_URL;
process.env.SUPABASE_SERVICE_ROLE_KEY = env.SUPABASE_SERVICE_ROLE_KEY;
process.env.GHL_API_KEY = env.GHL_API_KEY;
process.env.GHL_LOCATION_ID = env.GHL_LOCATION_ID;
delete process.env.CRON_SECRET;
// no GOOGLE_OAUTH env -> email leg disabled locally (sent=false, logged)
delete process.env.GOOGLE_OAUTH_REFRESH_TOKEN;

const r1 = mockRes();
await handler({ method: "GET", url: "/api/tripwire", headers: {} }, r1);
const b1 = r1.body;
console.log("\n--- run 1 (live data, no email) ---");
console.log(JSON.stringify(b1, null, 1).slice(0, 1200));

check("handler 200 + shape", b1 && Array.isArray(b1.findings) && b1.legs);
check("platform leg ok (statuspage reachable)", b1?.legs?.platform === "ok", JSON.stringify(b1?.legs));
check("wferrors leg ok (JWT mint works)", b1?.legs?.wferrors === "ok", JSON.stringify(b1?.legs));
check("estate leg ok (PIT public read works)", b1?.legs?.estate === "ok", JSON.stringify(b1?.legs));
check("dispatch leg ok (supabase read works)", b1?.legs?.dispatch === "ok", JSON.stringify(b1?.legs));
check(
  "live dispatch incident detected",
  b1?.findings?.includes("dispatch"),
  "findings=" + JSON.stringify(b1?.findings)
);

// -- 2) dedupe: second run on the same condition -> no second finding
const r2 = mockRes();
await handler({ method: "GET", url: "/api/tripwire", headers: {} }, r2);
const b2 = r2.body;
check(
  "dedupe: same-condition second run silent",
  !b2?.findings?.includes("dispatch"),
  "findings=" + JSON.stringify(b2?.findings)
);

// -- 3) repeat-cap re-arm: age the dispatch alert row past 6h, re-run -> fires again
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
const key = "ghl:alert:dispatch:down";
const past = new Date(Date.now() - 7 * 3.6e6).toISOString();
const patchRes = await fetch(
  `${SUPABASE_URL}/rest/v1/ops_alert_log?alert_key=eq.${encodeURIComponent(key)}`,
  {
    method: "PATCH",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: "Bearer " + SUPABASE_SERVICE_ROLE_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ created_at: past }),
  }
);
console.log("\n--- aged dispatch alert row to -7h (PATCH " + patchRes.status + ") ---");
const r3 = mockRes();
await handler({ method: "GET", url: "/api/tripwire", headers: {} }, r3);
check(
  "repeat-cap: aged condition re-pages once",
  r3.body?.findings?.includes("dispatch"),
  "findings=" + JSON.stringify(r3.body?.findings)
);

// -- 4) re-run again -> re-suppressed (fresh row now blocks)
const r4 = mockRes();
await handler({ method: "GET", url: "/api/tripwire", headers: {} }, r4);
check(
  "post-rearm dedupe holds",
  !r4.body?.findings?.includes("dispatch"),
  "findings=" + JSON.stringify(r4.body?.findings)
);

// -- 5) dry mode: evaluates, sends nothing, writes nothing
const before = await fetch(
  `${SUPABASE_URL}/rest/v1/ops_alert_log?select=alert_key&alert_key=like.ghl:*&order=created_at.desc&limit=50`,
  { headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: "Bearer " + SUPABASE_SERVICE_ROLE_KEY } }
).then((r) => r.json());
const r5 = mockRes();
await handler({ method: "GET", url: "/api/tripwire?dry=1", headers: {} }, r5);
const after = await fetch(
  `${SUPABASE_URL}/rest/v1/ops_alert_log?select=alert_key&alert_key=like.ghl:*&order=created_at.desc&limit=50`,
  { headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: "Bearer " + SUPABASE_SERVICE_ROLE_KEY } }
).then((r) => r.json());
check(
  "dry mode writes nothing",
  JSON.stringify(before) === JSON.stringify(after),
  `before=${before.length} after=${after.length}`
);
check("dry mode sends no email", (r5.body?.alerts_sent ?? []).length === 0);

console.log("\n=== BATTERY: " + results.filter((r) => r[1]).length + "/" + results.length + " passed ===");
process.exit(results.some((r) => !r[1]) ? 1 : 0);
