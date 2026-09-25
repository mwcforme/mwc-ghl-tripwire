/**
 * Local battery for api/meta-workflows.js — the META workflow guard.
 * No live email: OAuth quartet torn down BEFORE dynamic import.
 *
 *  1  auth fail-closed: no header / wrong / query-param secret -> 401
 *  2  healthy live run: leg ok, all 3 workflows present+published, no findings
 *  3  evaluateWatch pure core: missing / unpublished / version / bootstrap
 *  4  dedupe + repeat-cap re-arm + release (battery-prefixed keys only)
 *  5  dry mode: writes NOTHING (full ghl:meta:* row diff, run markers excluded)
 *  6  crash guard: unreachable Supabase -> leg FAIL, run still 200
 *  7  email-fail path: releaseAlert removes the claimed lock
 *  8  warm-container: findings/DRY reset across dry->live on one module
 *  9  email-disable sentinel: googleOAuth() call-time read
 * 10  blindness: 2 failed runs arm the blind page (dry-verified)
 * 11  run marker written on live run (deadman dependency)
 * 12  no query-param auth + header-only contract mirrored
 * 13  describe(): every finding kind produces 4-part lines + subject
 * 14  WATCH set is exactly the 3 Meta workflows (live-verified IDs)
 * 15  recipients: route-scoped META_ALERT_TO override chain (techops off the
 *     Meta guard only; tripwire/deadman keep the project-wide ALERT_TO)
 *
 * Run: node meta-battery.mjs   (same env as battery.mjs)
 */
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

const results = [];
function check(name, cond, detail = "") {
  results.push([name, !!cond]);
  console.log((cond ? "PASS " : "FAIL ") + name + (cond ? "" : " :: " + detail));
}
const mkRes = () => ({ statusCode: 200, body: null, json(x) { this.body = x; } });

// -- 0) env teardown BEFORE any import (dynamic import only) --
const OAUTH_KEYS = [
  "GOOGLE_OAUTH_REFRESH_TOKEN",
  "GOOGLE_OAUTH_CLIENT_ID",
  "GOOGLE_OAUTH_CLIENT_SECRET",
  "GOOGLE_OAUTH_TOKEN_URI",
];
for (const k of OAUTH_KEYS) delete process.env[k];
delete process.env.SUPABASE_SERVICE_ROLE_KEY;
if (process.env.MWC_TRIPWIRE_ENV) {
  for (const line of execSync(`cat "${process.env.MWC_TRIPWIRE_ENV}"`).toString().split("\n")) {
    const m = line.match(/^([A-Z_]+)=\"([^\"]*)\"$/);
    if (m && !OAUTH_KEYS.includes(m[1])) process.env[m[1]] = m[2];
  }
}
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.error("FATAL: SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY required");
  process.exit(2);
}
if (!process.env.CRON_SECRET) {
  console.error("FATAL: CRON_SECRET required (auth fail-closed cases)");
  process.exit(2);
}
const secret = process.env.CRON_SECRET;
const AUTH = { authorization: "Bearer " + secret };

// dynamic import AFTER teardown -> the module sees a clean env
const { default: handler, evaluateWatch, _internals } = await import("./api/meta-workflows.js");

const URL = process.env.SUPABASE_URL.replace(/\/$/, "");
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const H = { apikey: KEY, Authorization: "Bearer " + KEY, "Content-Type": "application/json" };
const BASE = `${URL}/rest/v1/ops_alert_log`;
const BATTERY_NS = "ghl:meta:alert:metamissing:battery"; // battery-owned keys only

async function sbRows(filter) {
  const r = await fetch(
    `${BASE}?select=alert_key,severity,created_at&alert_key=like.${filter}&order=created_at.desc&limit=1000`,
    { headers: H }
  );
  return r.json();
}

const WATCH_IDS = [
  "5158c291-8842-4763-9992-399015f93d2d",
  "29587aae-54fd-47d2-bfe7-ffc33e16839a",
  "ce21e5c0-b893-4573-909b-1d9e8b73937a",
];

// ---------- 1) auth fail-closed ----------
const ra = mkRes();
await handler({ method: "GET", url: "/api/meta-workflows", headers: {} }, ra);
check("auth: no header -> 401", ra.statusCode === 401, JSON.stringify(ra.body));
const rb = mkRes();
await handler({ method: "GET", url: "/api/meta-workflows", headers: { authorization: "Bearer wrong" } }, rb);
check("auth: wrong header -> 401", rb.statusCode === 401, JSON.stringify(rb.body));
const rq = mkRes();
await handler({ method: "GET", url: `/api/meta-workflows?secret=${encodeURIComponent(secret)}`, headers: {} }, rq);
check("auth: query-param secret REJECTED", rq.statusCode === 401, JSON.stringify(rq.body));

// ---------- 2) healthy live run ----------
const r1 = mkRes();
await handler({ method: "GET", url: "/api/meta-workflows", headers: AUTH }, r1);
console.log("\n--- run 1 (live data, email disabled) ---");
console.log(JSON.stringify(r1.body, null, 1).slice(0, 1200));
check("metalist leg ok on live data", r1.body?.legs?.metalist === "ok", JSON.stringify(r1.body?.legs));
{
  const wfs = r1.body?.observed?.workflows ?? [];
  check(
    "all 3 watched META workflows present + published live",
    wfs.length === 3 && wfs.every((w) => w.present && w.status === "published"),
    JSON.stringify(wfs.map((w) => [w.name, w.status]))
  );
  // first-ever run = bootstrap: baselines recorded, NO version findings
  check(
    "bootstrap run: no version findings (baseline recorded, not paged)",
    (r1.body?.findings ?? []).every((f) => f !== "metaver"),
    JSON.stringify(r1.body?.findings)
  );
}
check("no email sent locally", (r1.body?.alerts_sent ?? []).length === 0);
check("delivery_failed present in shape", Array.isArray(r1.body?.delivery_failed));
check("email leg really disabled (no oauth at call time)", !process.env.GOOGLE_OAUTH_REFRESH_TOKEN);

// ---------- 3) evaluateWatch pure core ----------
{
  const watch = [{ id: "a", label: "A" }, { id: "b", label: "B" }, { id: "c", label: "C" }];
  const live = [
    { id: "a", name: "A live", status: "published", version: 5 },
    { id: "b", name: "B live", status: "draft", version: 2 },
    // c intentionally absent -> missing
  ];
  const baselines = { a: { version: 4, status: "published" } };
  const v = evaluateWatch(watch, live, baselines);
  const byId = Object.fromEntries(v.map((x) => [x.id, x]));
  check("core: published+edited -> exactly a version finding", byId.a.findings.length === 1 && byId.a.findings[0].kind === "version" && byId.a.findings[0].from === 4 && byId.a.findings[0].to === 5, JSON.stringify(byId.a.findings));
  check("core: draft -> unpublished finding", byId.b.findings.length === 1 && byId.b.findings[0].kind === "unpublished" && byId.b.findings[0].status === "draft", JSON.stringify(byId.b.findings));
  check("core: absent -> missing finding, name falls back to label", byId.c.findings.length === 1 && byId.c.findings[0].kind === "missing" && byId.c.name === "C" && byId.c.present === false, JSON.stringify(byId.c));
  const boot = evaluateWatch(watch, live, {}); // no baselines anywhere
  check("core: no baseline -> bootstrap (no version finding)", boot.every((x) => !x.findings.some((f) => f.kind === "version")), JSON.stringify(boot.map((x) => x.findings)));
  const bogus = evaluateWatch(watch, live, { a: "not-an-object" });
  check("core: non-object baseline ignored -> bootstrap", !bogus.some((x) => x.id === "a" && x.findings.some((f) => f.kind === "version")), JSON.stringify(bogus.find((x) => x.id === "a").findings));
}

// ---------- 4) dedupe + re-arm + release (battery namespace) ----------
{
  const fp = `test-${Date.now()}`;
  const claimed = await _internals.claimAlert("metamissing", fp, "alert");
  check("claimAlert inserts a fresh lock", claimed === true);
  const again = await _internals.claimAlert("metamissing", fp, "alert");
  check("claimAlert dedupes the same lock", again === false);
  const key = `ghl:meta:alert:metamissing:${fp}`;
  const patch = await fetch(`${BASE}?alert_key=eq.${encodeURIComponent(key)}`, {
    method: "PATCH",
    headers: H,
    body: JSON.stringify({ created_at: new Date(Date.now() - 7 * 3.6e6).toISOString() }),
  });
  check("aged lock patch ok", patch.ok, "PATCH " + patch.status);
  const rearmed = await _internals.claimAlert("metamissing", fp, "alert");
  check("repeat-cap re-arm: aged lock re-claims", rearmed === true);
  await _internals.releaseAlert("metamissing", fp);
  const rows = await sbRows(`ghl:meta:alert:metamissing:${fp}`);
  check("releaseAlert removes the claimed lock", Array.isArray(rows) && rows.length === 0, JSON.stringify(rows));
  const ns = await sbRows(`${BATTERY_NS}*`);
  check("battery namespace clean at end", Array.isArray(ns) && ns.length === 0, JSON.stringify(ns));
}

// ---------- 5) dry mode writes NOTHING ----------
{
  const dryKey = `ghl:meta:state:battery_dry_${Date.now()}`;
  _internals.setDry(true);
  const drySet = await _internals.setState(dryKey, "42");
  check("setState is a no-op in dry mode", drySet === true);
  const rows = await sbRows(dryKey);
  check("dry setState wrote no row", Array.isArray(rows) && rows.length === 0, JSON.stringify(rows));
  const dryClaim = await _internals.claimAlert("metamissing", `dry-fp-${Date.now()}`, "alert");
  check("claimAlert claims without writing in dry mode", dryClaim === true);
  const dryRows = await sbRows(`ghl:meta:alert:metamissing:dry-fp-*`);
  check("dry claimAlert wrote no row", Array.isArray(dryRows) && dryRows.length === 0, JSON.stringify(dryRows));
  _internals.setDry(false);
  // Full-handler dry run vs pre-state: no ghl:meta:* row may appear, disappear,
  // or change severity across the dry invocation. Run markers excluded (the
  // deployed 5-min cron legitimately adds one per tick and must not flake this).
  const freeze = (rows) =>
    JSON.stringify(
      (rows ?? [])
        .filter((r) => !String(r.alert_key).startsWith("ghl:meta:state:run:"))
        .map((r) => [r.alert_key, r.severity])
        .sort((a, b) => String(a[0]).localeCompare(String(a[0])))
    );
  const pre = await sbRows("ghl:meta:*");
  const r3 = mkRes();
  await handler({ method: "GET", url: "/api/meta-workflows?dry=1", headers: AUTH }, r3);
  const post = await sbRows("ghl:meta:*");
  check(
    "dry handler run: zero ghl:meta:* row mutations (excl. cron run markers)",
    freeze(pre) === freeze(post),
    `pre=${pre?.length ?? "?"} post=${post?.length ?? "?"}`
  );
  check("dry handler sends no email", (r3.body?.alerts_sent ?? []).length === 0);
  check("dry handler reports dry:true", r3.body?.dry === true);
}

// ---------- 6) crash guard ----------
{
  const saveUrl = process.env.SUPABASE_URL;
  process.env.SUPABASE_URL = "https://definitely-unreachable.invalid";
  const { default: h2 } = await import("./api/meta-workflows.js?bust=1");
  const r6 = mkRes();
  await h2({ method: "GET", url: "/api/meta-workflows", headers: AUTH }, r6);
  process.env.SUPABASE_URL = saveUrl;
  check(
    "guard: unreachable Supabase -> metalist leg FAIL, run still 200",
    r6.statusCode === 200 && r6.body?.legs?.metalist === "FAIL",
    JSON.stringify({ code: r6.statusCode, legs: r6.body?.legs })
  );
}

// ---------- 7) email-fail releases lock ----------
{
  const fp = `email-fail-${Date.now()}`;
  const claimed = await _internals.claimAlert("metamissing", fp, "alert");
  check("email-fail setup: lock claimed", claimed === true);
  await _internals.releaseAlert("metamissing", fp);
  const rows = await sbRows(`ghl:meta:alert:metamissing:${fp}`);
  check("email-fail: lock RELEASED after failed send", Array.isArray(rows) && rows.length === 0, JSON.stringify(rows));
}

// ---------- 8) warm-container reset ----------
{
  const r8 = mkRes();
  await handler({ method: "GET", url: "/api/meta-workflows?dry=1", headers: AUTH }, r8);
  const r8b = mkRes();
  await handler({ method: "GET", url: "/api/meta-workflows?dry=1", headers: AUTH }, r8b);
  const f8 = r8.body?.findings ?? [];
  const f8b = r8b.body?.findings ?? [];
  check(
    "warm-container: findings stable (no accumulation) across dry runs",
    JSON.stringify(f8) === JSON.stringify(f8b),
    JSON.stringify({ first: f8, second: f8b })
  );
  const r9 = mkRes();
  await handler({ method: "GET", url: "/api/meta-workflows", headers: AUTH }, r9);
  check("warm-container: DRY reset false on next live run", r9.body?.dry === false);
}

// ---------- 9) email-disable sentinel (module design) ----------
{
  const src = readFileSync("./api/meta-workflows.js", "utf8");
  check(
    "module reads OAuth at call time (no module-scope capture)",
    !/const GOOGLE_OAUTH\s*=/.test(src) && /function googleOAuth\(\)/.test(src),
    "googleOAuth() pattern"
  );
  check("handler logs email_skip_no_oauth when unset", src.includes("email_skip_no_oauth"));
  // RFC 2047: Gmail mangles bare UTF-8 in headers (live-verified 2026-09-24)
  check(
    "Subject header RFC 2047-encoded (mimeHeader)",
    /function mimeHeader\(/.test(src) && src.includes("Subject: ${mimeHeader(f.subject)}"),
    "mimeHeader wiring"
  );
}

// ---------- 10) blindness arms at 2 (functional, self-healing) ----------
{
  // One REAL failed probe (garbage PIT via a fresh cache-busted import) with
  // Supabase reachable: the leg counter increments in the guard's own state
  // key; assert it, then HEAL it back to 0 so the deployed guard never
  // inherits a false blind streak from the battery.
  const savePit = process.env.GHL_API_KEY;
  process.env.GHL_API_KEY = "battery-garbage-pit";
  const { default: hbad } = await import("./api/meta-workflows.js?bust=3");
  const x1 = mkRes();
  await hbad({ method: "GET", url: "/api/meta-workflows", headers: AUTH }, x1);
  process.env.GHL_API_KEY = savePit;
  check(
    "blind leg: failed probe -> run 200, metalist FAIL",
    x1.statusCode === 200 && x1.body?.legs?.metalist === "FAIL",
    JSON.stringify(x1.body?.legs)
  );
  check(
    "blind leg: no page at fails=1 (arms at 2)",
    (x1.body?.findings ?? []).every((f) => f !== "blind"),
    JSON.stringify(x1.body?.findings)
  );
  const st = await _internals.getState("ghl:meta:state:leg_metalist");
  check("blind leg: state counter incremented (durable)", st?.value === "1", JSON.stringify(st));
  const healed = await _internals.setState("ghl:meta:state:leg_metalist", "0");
  const st2 = await _internals.getState("ghl:meta:state:leg_metalist");
  check("blind leg: counter healed back to 0", healed && st2?.value === "0", JSON.stringify(st2));
  const src = readFileSync("./api/meta-workflows.js", "utf8");
  check(
    "blindness design: arms at next >= 2 with 1/h claim cap",
    /if \(next >= 2\) \{[\s\S]*?claimAlert\("blind", leg, "warn", T\.LEG_FAIL_ALERT_MIN \/ 60\)/.test(src),
    "blind arm + cap wiring"
  );
}

// ---------- 11) run marker written on live run ----------
{
  const markers = await fetch(
    `${BASE}?select=created_at&alert_key=like.ghl:meta:state:run:*&order=created_at.desc&limit=1`,
    { headers: H }
  ).then((r) => r.json());
  const ageMin = markers.length ? (Date.now() - Date.parse(markers[0].created_at)) / 60000 : null;
  check(
    "run marker fresh (<10 min, deadman dependency)",
    ageMin != null && ageMin < 10,
    "age=" + (ageMin == null ? "null" : ageMin.toFixed(1))
  );
}

// ---------- 13) describe() 4-part contract ----------
{
  const src = readFileSync("./api/meta-workflows.js", "utf8");
  const desc = src.split("function describe(")[1].split("async function checkMetaWorkflows")[0];
  for (const kind of ["missing", "unpublished", "version"]) {
    const blk = desc.split(`case "${kind}":`)[1]?.split("case ")[0] ?? "";
    check(
      `describe(${kind}): 4-part lines (What/Impact/Evidence/Check)`,
      /Impact:/.test(blk) && /Evidence:/.test(blk) && /Check:/.test(blk) && /lines: \[/.test(blk),
      kind + " block shape"
    );
  }
}

// ---------- 14) WATCH set is exactly the 3 live-verified Meta workflows ----------
{
  const src = readFileSync("./api/meta-workflows.js", "utf8");
  check(
    "WATCH = exactly the 3 Meta workflow IDs (live-verified 2026-09-24)",
    WATCH_IDS.every((id) => src.includes(`"${id}"`)) && /02\. NON BOOKED META/.test(src),
    "WATCH literal IDs"
  );
}

// ---------- 15) recipients: route-scoped META_ALERT_TO override chain ----------
{
  const src = readFileSync("./api/meta-workflows.js", "utf8");
  check(
    "ALERT_TO reads META_ALERT_TO first, then ALERT_TO (route-scoped override)",
    /ALERT_TO = \(process\.env\.META_ALERT_TO \|\| process\.env\.ALERT_TO \|\|/.test(src),
    "META_ALERT_TO || ALERT_TO || default chain"
  );
  check(
    "tripwire + deadman do NOT read META_ALERT_TO (project-wide list only)",
    !readFileSync("./api/tripwire.js", "utf8").includes("META_ALERT_TO") &&
      !readFileSync("./api/deadman.js", "utf8").includes("META_ALERT_TO"),
    "META_ALERT_TO must exist only in meta-workflows.js"
  );
}

console.log("\n=== META BATTERY: " + results.filter((r) => r[1]).length + "/" + results.length + " passed ===");
process.exit(results.some((r) => !r[1]) ? 1 : 0);
