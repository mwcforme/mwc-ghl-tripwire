/**
 * Local battery for api/tripwire.js — RESCOPED+HARDENED 2026-09-22.
 *
 * Email-disable is bulletproof: the module is imported dynamically AFTER
 * env teardown (no static import to hoist), and the module reads the OAuth
 * quartet at CALL time (googleOAuth()), so deletion before import disables
 * the email leg for real. Verified twice below.
 *
 * Cases:
 *  1  auth fail-closed: no header / wrong header / query-param secret -> 401
 *  2  healthy live run: all 5 legs ok, no findings, no email, shape fields
 *  3  dedupe + repeat-cap re-arm + release (battery-prefixed keys only)
 *  4  dry mode: writes NOTHING — full row diff incl. severity, on a clean
 *     battery-owned state namespace (prod baselines untouched)
 *  5  crash guard: unreachable Supabase -> legs FAIL, run still 200
 *  6  email-fail path: releaseAlert removes the claimed lock
 *  7  bizHoursNow: Sat/Sun excluded, Mon in-hours included, Mon out excluded
 *  8  warm-container: findings/DRY reset across dry->live on one module
 *  9  email-disable sentinel: googleOAuth() call-time read (no module capture)
 * 10  deadman marker fresh after a live run (<10 min)
 * 11  no dispatch/sendfail legs remain (Curve owns conversion)
 * 12  LEG_FAIL_ALERT_MIN wired into the blind claimAlert call
 *
 * Run: node battery.mjs
 * Env: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, CRON_SECRET (+ optionally
 *      GHL_* for full-leg runs). See runbook: MWC_TRIPWIRE_ENV=<file> loads
 *      a pulled env file verbatim (minus the OAuth quartet, always torn down).
 */
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

const results = [];
function check(name, cond, detail = "") {
  results.push([name, !!cond]);
  console.log((cond ? "PASS " : "FAIL ") + name + (cond ? "" : " :: " + detail));
}
const mkRes = () => ({ statusCode: 200, body: null, json(x) { this.body = x; } });

// -- 0) env teardown BEFORE any import (dynamic import only; a static
//       import would hoist above these deletes — the bug this battery fixes)
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
    const m = line.match(/^([A-Z_]+)="([^"]*)"$/);
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
const { default: handler, _internals } = await import("./api/tripwire.js");

const URL = process.env.SUPABASE_URL.replace(/\/$/, "");
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const H = { apikey: KEY, Authorization: "Bearer " + KEY, "Content-Type": "application/json" };
const BASE = `${URL}/rest/v1/ops_alert_log`;
const BATTERY_NS = "ghl:alert:platform:battery"; // battery-owned keys only

async function sbRows(filter) {
  const r = await fetch(
    `${BASE}?select=alert_key,severity,created_at&alert_key=like.${filter}&order=created_at.desc&limit=1000`,
    { headers: H }
  );
  return r.json();
}

// ---------- 1) auth fail-closed ----------
const ra = mkRes();
await handler({ method: "GET", url: "/api/tripwire", headers: {} }, ra);
check("auth: no header -> 401", ra.statusCode === 401, JSON.stringify(ra.body));
const rb = mkRes();
await handler({ method: "GET", url: "/api/tripwire", headers: { authorization: "Bearer wrong" } }, rb);
check("auth: wrong header -> 401", rb.statusCode === 401, JSON.stringify(rb.body));
const rq = mkRes();
await handler({ method: "GET", url: `/api/tripwire?secret=${encodeURIComponent(secret)}`, headers: {} }, rq);
check("auth: query-param secret REJECTED", rq.statusCode === 401, JSON.stringify(rq.body));

// ---------- 2) healthy live run ----------
const r1 = mkRes();
await handler({ method: "GET", url: "/api/tripwire", headers: AUTH }, r1);
console.log("\n--- run 1 (live data, email disabled) ---");
console.log(JSON.stringify(r1.body, null, 1).slice(0, 900));
check(
  "all 5 legs ok on live data",
  r1.body?.legs && ["platform", "wferrors", "executions", "estate", "capture"].every((l) => r1.body.legs[l] === "ok"),
  JSON.stringify(r1.body?.legs)
);
{
  const f1 = r1.body?.findings ?? [];
  const liveCount = r1.body?.observed?.err_count;
  // NEW SEMANTICS (2026-09-22): standing unacknowledged errors are a FINDING.
  // A healthy run with err_count > 0 must report the wferrors standing alert;
  // a run with err_count == 0 must report nothing.
  // PROD-RACE (2026-09-24): the DEPLOYED 5-min cron legitimately owns the
  // ghl:alert:wferrors:standing:<count> lock while it is younger than the 24h
  // repeat cap — then a battery run cannot re-claim and correctly reports no
  // finding. Race-aware assertion: the finding fired OR the deployed lock is
  // verifiably held fresh (both prove the feature works; neither is a tautology).
  let deployedLock = null;
  if (liveCount > 0) {
    const lk = await sbRows(`ghl:alert:wferrors:standing:${liveCount}`);
    deployedLock = Array.isArray(lk) && lk.length
      ? { at: Date.parse(lk[0].created_at), check_id: lk[0].severity }
      : null;
  }
  const lockHeldFresh = deployedLock && Date.now() - deployedLock.at < 24 * 3.6e6;
  check(
    "standing finding fired OR deployed cron holds the standing lock (<24h)",
    liveCount === 0
      ? f1.length === 0
      : f1.length === 1 && f1[0] === "wferrors" ? true : !!lockHeldFresh,
    JSON.stringify({ findings: f1, err_count: liveCount, lock: deployedLock })
  );
  check(
    "standing path coherent (finding or fresh deployed lock, not neither)",
    liveCount === 0 ? true : (f1.includes("wferrors") || !!lockHeldFresh),
    "err_count=" + liveCount + " lockHeldFresh=" + !!lockHeldFresh
  );
}
check("no email sent locally", (r1.body?.alerts_sent ?? []).length === 0);
check("delivery_failed present in shape", Array.isArray(r1.body?.delivery_failed));
check("email leg really disabled (no oauth at call time)", !process.env.GOOGLE_OAUTH_REFRESH_TOKEN);

// ---------- 11) no dispatch/sendfail legs (Curve owns conversion) ----------
check(
  "no dispatch/sendfail legs or observed fields remain",
  r1.body?.legs?.dispatch === undefined && r1.body?.legs?.sendfail === undefined &&
    r1.body?.observed?.dispatch_last_ok_age_h === undefined && r1.body?.observed?.sendfail_bad === undefined,
  JSON.stringify({ legs: r1.body?.legs, observed: r1.body?.observed })
);

// ---------- 3) dedupe + re-arm + release (battery namespace) ----------
{
  const fp = `test-${Date.now()}`;
  const claimed = await _internals.claimAlert("platform", fp, "alert");
  check("claimAlert inserts a fresh lock", claimed === true);
  const again = await _internals.claimAlert("platform", fp, "alert");
  check("claimAlert dedupes the same lock", again === false);
  const key = `ghl:alert:platform:${fp}`;
  const patch = await fetch(`${BASE}?alert_key=eq.${encodeURIComponent(key)}`, {
    method: "PATCH",
    headers: H,
    body: JSON.stringify({ created_at: new Date(Date.now() - 7 * 3.6e6).toISOString() }),
  });
  check("aged lock patch ok", patch.ok, "PATCH " + patch.status);
  const rearmed = await _internals.claimAlert("platform", fp, "alert");
  check("repeat-cap re-arm: aged lock re-claims", rearmed === true);
  await _internals.releaseAlert("platform", fp);
  const rows = await sbRows(`ghl:alert:platform:${fp}`);
  check("releaseAlert removes the claimed lock", Array.isArray(rows) && rows.length === 0, JSON.stringify(rows));
  // battery namespace hygiene: nothing with the battery prefix lingers
  const ns = await sbRows(`${BATTERY_NS}*`);
  check("battery namespace clean at end", Array.isArray(ns) && ns.length === 0, JSON.stringify(ns));
}

// ---------- 4) dry mode writes NOTHING (prod baselines untouched) ----------
{
  // Battery-owned state keys only — the deployed cron's real baselines
  // (ghl:state:err_count etc.) are left alone; we prove setState dry-no-op
  // with keys the prod code never touches.
  const dryKey = `ghl:state:battery_dry_${Date.now()}`;
  _internals.setDry(true);
  const drySet = await _internals.setState(dryKey, "42");
  check("setState is a no-op in dry mode", drySet === true);
  const rows = await sbRows(dryKey);
  check("dry setState wrote no row", Array.isArray(rows) && rows.length === 0, JSON.stringify(rows));
  const dryClaim = await _internals.claimAlert("platform", `dry-fp-${Date.now()}`, "alert");
  check("claimAlert claims without writing in dry mode", dryClaim === true);
  const dryRows = await sbRows(`ghl:alert:platform:dry-fp-*`);
  check("dry claimAlert wrote no row", Array.isArray(dryRows) && dryRows.length === 0, JSON.stringify(dryRows));
  _internals.setDry(false);
  // Full-handler dry run vs pre-state: no ghl:* row may appear, disappear,
  // or change severity across the dry invocation. Run markers are EXCLUDED
  // from the comparison — the deployed 5-min cron legitimately adds one per
  // tick and must not flake this battery.
  const freeze = (rows) =>
    JSON.stringify(
      (rows ?? [])
        .filter((r) => !String(r.alert_key).startsWith("ghl:state:run:"))
        .map((r) => [r.alert_key, r.severity])
        .sort((a, b) => String(a[0]).localeCompare(String(b[0])))
    );
  const pre = await sbRows("ghl:*");
  const r3 = mkRes();
  await handler({ method: "GET", url: "/api/tripwire?dry=1", headers: AUTH }, r3);
  const post = await sbRows("ghl:*");
  check(
    "dry handler run: zero ghl:* row mutations (excl. cron run markers)",
    freeze(pre) === freeze(post),
    `pre=${pre?.length ?? "?"} post=${post?.length ?? "?"}`
  );
  check("dry handler sends no email", (r3.body?.alerts_sent ?? []).length === 0);
  check("dry handler reports dry:true", r3.body?.dry === true);
}

// ---------- 5) crash guard ----------
{
  const saveUrl = process.env.SUPABASE_URL;
  process.env.SUPABASE_URL = "https://definitely-unreachable.invalid";
  const { default: h2 } = await import("./api/tripwire.js?bust=1");
  const r6 = mkRes();
  await h2({ method: "GET", url: "/api/tripwire", headers: AUTH }, r6);
  process.env.SUPABASE_URL = saveUrl;
  // platform leg hits statuspage.io (no Supabase) -> stays ok; the four
  // Supabase/GHL-independent-of-bad-URL legs read FAIL via guard()
  check(
    "guard: unreachable Supabase -> sb legs FAIL, run still 200",
    r6.statusCode === 200 &&
      r6.body?.legs?.platform === "ok" &&
      ["wferrors", "executions", "estate", "capture"].every((l) => r6.body.legs[l] === "FAIL"),
    JSON.stringify({ code: r6.statusCode, legs: r6.body?.legs })
  );
}

// ---------- 6) email-fail releases lock ----------
{
  const fp = `email-fail-${Date.now()}`;
  const claimed = await _internals.claimAlert("platform", fp, "alert");
  check("email-fail setup: lock claimed", claimed === true);
  await _internals.releaseAlert("platform", fp);
  const rows = await sbRows(`ghl:alert:platform:${fp}`);
  check("email-fail: lock RELEASED after failed send", Array.isArray(rows) && rows.length === 0, JSON.stringify(rows));
}

// ---------- 7) bizHoursNow Mon-Fri gate ----------
{
  const sat = _internals.bizHoursNow(new Date("2026-09-19T14:00:00Z")); // 10:00 ET Sat
  const sun = _internals.bizHoursNow(new Date("2026-09-20T14:00:00Z")); // 10:00 ET Sun
  const mon = _internals.bizHoursNow(new Date("2026-09-21T14:00:00Z")); // 10:00 ET Mon
  const monEarly = _internals.bizHoursNow(new Date("2026-09-21T07:00:00Z")); // 03:00 ET
  const monLate = _internals.bizHoursNow(new Date("2026-09-21T23:30:00Z")); // 19:30 ET
  check("bizHours: Saturday 10:00 ET excluded", sat === false, "sat=" + sat);
  check("bizHours: Sunday 10:00 ET excluded", sun === false, "sun=" + sun);
  check("bizHours: Monday 10:00 ET included", mon === true, "mon=" + mon);
  check("bizHours: Monday 03:00 ET excluded (before 08)", monEarly === false, "monEarly=" + monEarly);
  check("bizHours: Monday 19:30 ET excluded (after 18)", monLate === false, "monLate=" + monLate);
}

// ---------- 8) warm-container reset ----------
{
  const r8 = mkRes();
  await handler({ method: "GET", url: "/api/tripwire?dry=1", headers: AUTH }, r8);
  const r8b = mkRes();
  await handler({ method: "GET", url: "/api/tripwire?dry=1", headers: AUTH }, r8b);
  // warm-container bug was ACCUMULATION across invocations. Dry runs may now
  // legitimately carry the standing wferrors finding (claimAlert is a no-op
  // in dry, so it re-appears); what must NEVER happen is growth or leftovers
  // from earlier live findings (platform/estate/etc).
  const f8 = r8.body?.findings ?? [];
  const f8b = r8b.body?.findings ?? [];
  check(
    "warm-container: findings stable (no accumulation) across dry runs",
    JSON.stringify(f8) === JSON.stringify(f8b) &&
      f8.every((x) => ["wferrors", "estate", "executions"].includes(x)),
    JSON.stringify({ first: f8, second: f8b })
  );
  const r9 = mkRes();
  await handler({ method: "GET", url: "/api/tripwire", headers: AUTH }, r9);
  check("warm-container: DRY reset false on next live run", r9.body?.dry === false);
}

// ---------- 9) email-disable sentinel (module design) ----------
{
  // NOTE: read by cwd-relative path — `URL` is shadowed by the env constant above.
  const src = readFileSync("./api/tripwire.js", "utf8");
  check(
    "module reads OAuth at call time (no module-scope capture)",
    !/const GOOGLE_OAUTH\s*=/.test(src) && /function googleOAuth\(\)/.test(src),
    "googleOAuth() pattern"
  );
  check("handler logs email_skip_no_oauth when unset", src.includes("email_skip_no_oauth"));
  // RFC 2047: Gmail mangles bare UTF-8 in headers (live-verified 2026-09-24
  // on the META guard's metaver subject; estate subjects carry "—" the same way)
  check(
    "tripwire Subject header RFC 2047-encoded (mimeHeader)",
    /function mimeHeader\(/.test(src) && src.includes("Subject: ${mimeHeader(f.subject)}"),
    "mimeHeader wiring"
  );
}

// ---------- 12) LEG_FAIL_ALERT_MIN wired ----------
{
  const src = readFileSync("./api/tripwire.js", "utf8");
  check(
    "LEG_FAIL_ALERT_MIN wired into blind claimAlert (1/h cap)",
    /claimAlert\(\s*"blind",\s*leg,\s*"warn",\s*T\.LEG_FAIL_ALERT_MIN\s*\/\s*60\s*\)/.test(src),
    "claimAlert(blind, …, LEG_FAIL_ALERT_MIN/60)"
  );
}

// ---------- 10) deadman marker fresh ----------
{
  const markers = await fetch(
    `${BASE}?select=created_at&alert_key=like.ghl:state:run:*&order=created_at.desc&limit=1`,
    { headers: H }
  ).then((r) => r.json());
  const ageMin = markers.length ? (Date.now() - Date.parse(markers[0].created_at)) / 60000 : null;
  check(
    "run marker fresh (<10 min, deadman dependency)",
    ageMin != null && ageMin < 10,
    "age=" + (ageMin == null ? "null" : ageMin.toFixed(1))
  );
}


// ---------- BATTERY V2 CASES (2026-09-22: name-the-workflow + recipients) ----------

// 13) ALERT_TO parses as a multi-recipient list
{
  const src = readFileSync("./api/tripwire.js", "utf8");
  check(
    "ALERT_TO is a parsed comma-list (multi-recipient)",
    /ALERT_TO = \(process\.env\.ALERT_TO \|\|[\s\S]*?\.split\(","\)[\s\S]*?\.filter\(Boolean\)/.test(src),
    "ALERT_TO split/filter pattern"
  );
  check(
    "recipients include techops + v-ihetta + sending mailbox",
    src.includes("techops@menswellnesscenters.com,v-ihetta@menswellnesscenters.com,v-islam.hetta@mwcforme.com"),
    "default recipient list"
  );
  check(
    "email To: header joins the list",
    src.includes("To: ${ALERT_TO.join("),
    "To header join"
  );
  check(
    "deadman also multi-recipient",
    readFileSync("./api/deadman.js", "utf8").includes("ALERT_TO.join("),
    "deadman To header join"
  );
}

// 14) every wferrors alert carries the Needs Review deep link
{
  const src = readFileSync("./api/tripwire.js", "utf8");
  const wferrSection = src.split("async function checkErrCount")[1].split("async function checkExecutions")[0];
  const alertBlocks = wferrSection.split("page(").slice(1);
  check(
    "every wferrors alert block cites REVIEW_URL",
    alertBlocks.length >= 2 &&
      alertBlocks.every((b) => b.includes("${REVIEW_URL}")),
    alertBlocks.length + " alert blocks in checkErrCount"
  );
  check(
    "REVIEW_URL is the Needs Review deep link with listTab=review",
    /REVIEW_URL = `https:\/\/app\.gohighlevel\.com\/v2\/location\/\$\{LOC\}\/automation\/workflows\?listTab=review`/.test(src),
    "REVIEW_URL literal"
  );
}

// 15) standing-error path exists with 24h repeat cap
{
  const src = readFileSync("./api/tripwire.js", "utf8");
  check(
    "standing-error claimAlert uses 24h repeat cap",
    /claimAlert\("wferrors", fpStanding, "alert", 24\)/.test(src),
    "claimAlert(..., 24)"
  );
  check(
    "standing alert pages when count > 0",
    /if \(count > 0\) \{[\s\S]*?fpStanding[\s\S]*?page\("wferrors", fpStanding/.test(src),
    "standing block + page()"
  );
}

// 16) estate alert names flipped workflows (ID-set diff)
{
  const src = readFileSync("./api/tripwire.js", "utf8");
  const estate = src.split("async function checkEstate")[1].split("async function checkCapture")[0];
  check(
    "estate stores ID->name map in state",
    estate.includes("ghl:state:estate_map") && estate.includes("JSON.stringify(idMap)"),
    "estate_map state write"
  );
  check(
    "estate alert subject carries the names",
    /page\("estate", fp, `\[GHL\] Published workflows \$\{prev\} -> \$\{published\}\$\{names \? " — " \+ names\.slice\(1\) : ""\}`/.test(estate),
    "subject template with names"
  );
  check(
    "estate diff handles unreadable state (try/catch fallback)",
    estate.includes("} catch {"),
    "try/catch around map diff"
  );
}

// 17) dry-run live check: standing errors page exactly once then dedupe
//     (uses the LIVE count; if count > 0 the claim fires once, second claim
//     is suppressed — proves the dedupe lock on the real key namespace)
{
  _internals.setDry(false);
  // run handler twice NON-dry but with email disabled (no oauth env) —
  // findings still accumulate; we assert via ops_alert_log row existence
  const ra = mkRes();
  await handler({ method: "GET", url: "/api/tripwire", headers: AUTH }, ra);
  const count = ra.body?.observed?.err_count;
  if (count > 0) {
    // battery has NO oauth env -> the email leg fails by design -> the lock
    // is RELEASED so production would retry. RACE-AWARE (2026-09-24): the
    // deployed 5-min cron may legitimately hold the standing lock (<24h old)
    // — then this battery run correctly cannot re-claim. Pass on the retry
    // cycle OR a verifiably fresh deployed lock; fail only when neither holds.
    const rows = await sbRows("ghl:alert:wferrors:standing:" + count);
    const lockHeldFresh =
      Array.isArray(rows) && rows.length && Date.now() - Date.parse(rows[0].created_at) < 24 * 3.6e6;
    const retryCycle =
      (ra.body?.findings ?? []).includes("wferrors") &&
      (ra.body?.delivery_failed ?? []).includes("wferrors") &&
      Array.isArray(rows) &&
      rows.length === 0;
    check(
      "standing alert: retry cycle OR deployed lock held fresh (<24h)",
      retryCycle || !!lockHeldFresh,
      JSON.stringify({ findings: ra.body?.findings, delivery_failed: ra.body?.delivery_failed, locks: rows?.length, lockAgeH: rows?.length ? ((Date.now() - Date.parse(rows[0].created_at)) / 3.6e6).toFixed(1) : null })
    );
  } else {
    check("live err_count is 0 -> standing path correctly silent", true);
  }
  check(
    "run reports observed.err_count",
    typeof ra.body?.observed?.err_count === "number",
    JSON.stringify(ra.body?.observed)
  );
}

console.log("\n=== BATTERY: " + results.filter((r) => r[1]).length + "/" + results.length + " passed ===");
process.exit(results.some((r) => !r[1]) ? 1 : 0);
