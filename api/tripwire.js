/**
 * GHL tripwire — scheduled failure detection for the MWC GHL estate.
 *
 * Runs as a Vercel cron (every 5 minutes, see vercel.json) — no laptop
 * involved. Read-only against GHL and Supabase; the ONLY writes are dedupe
 * rows in public.ops_alert_log (same insert-first pattern as mwc-admin's
 * /api/health/booking) and alert emails via the Gmail API.
 *
 * Signals (each route verified live before wiring — see the sentinel skill
 * ghl-error-tripwire / references/signal-verification-2026-09-21.md):
 *
 *  A  blindness      per-leg probe failures (2+ consecutive)          -> pages (1/h cap)
 *  B  platform       statuspage.io indicator != none                  -> pages
 *  C  wf errors      error-notification/count rise (Firebase JWT)     -> pages
 *  C+ standing errs  count > 0 unacknowledged (re-pages daily)        -> pages
 *  D  wf err detail  error-notification/list rows (enriches C)        -> rides C
 *     (NOTE 2026-09-22: D's list route returns 0 rows even when count>0;
 *      GHL exposes NO per-workflow error detail via API — C/C+ alerts
 *      therefore carry the Needs Review deep link, which does name them.)
 *  E  executions     /workflow/executions rows appear (canary)        -> pages
 *  G  capture        booking_attribution_records stale in biz hours   -> pages
 *  I  estate flip    published workflow count changes                 -> pages
 *
 * REMOVED 2026-09-21 (user correction): F dispatch + H sendfail — Curve
 * owns conversion/attribution now; the old conversion_queue/conversion_sends
 * path is decommissioned BY DESIGN and must never be reported as an outage.
 *
 * Statelessness: serverless invocations share warm containers, so runtime
 * state (findings, DRY) is reset at the top of every invocation and ALL
 * durable state lives in Supabase — ops_alert_log rows are the dedupe lock
 * AND the run ledger:
 *   ghl:state:run:<epoch-5min-bucket> — one per non-dry invocation (deadman)
 *   ghl:state:<key>                   — observed baselines (err_count, estate, legs)
 *   ghl:alert:<check>:<fp>            — insert-first lock per condition instance
 *
 * Auth: FAIL-CLOSED. CRON_SECRET must be configured and presented as
 * "Authorization: Bearer <secret>" — header only (no query-param form, it
 * would leak into access logs). Missing secret -> 500, wrong/absent header
 * -> 401.
 *
 * dry mode: ?dry=1 evaluates and reports WITHOUT sending email or writing
 * ANYTHING — no alert locks, no state mutation, no run marker.
 *
 * Delivery hardening: a finding whose email fails to send is surfaced in
 * the response as delivery_failed[] and its dedupe lock is RELEASED, so
 * the next run retries instead of silently muting the condition for 6h.
 */

const LOC = process.env.GHL_LOCATION_ID || "Ghstz8eIsHWLeXek47dk";
const BACKEND = "https://backend.leadconnectorhq.com";
const PUBLIC = "https://services.leadconnectorhq.com";
const STATUSPAGE = "https://gohighlevel.statuspage.io/api/v2/status.json";
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36";
const ALERT_TO = (process.env.ALERT_TO ||
  "techops@menswellnesscenters.com,v-ihetta@menswellnesscenters.com,v-islam.hetta@mwcforme.com")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const ALERT_FROM = process.env.ALERT_FROM || "v-islam.hetta@mwcforme.com";
/** The ONLY surface that names failing workflows (verified 2026-09-22: the
 *  error-notification/list route returns 0 rows whenever count > 0; 16 route
 *  shapes probed — REST, Firestore, frontend bundles — none expose per-
 *  workflow error detail. GHL's own digest email links here too.) */
const REVIEW_URL = `https://app.gohighlevel.com/v2/location/${LOC}/automation/workflows?listTab=review`;

// thresholds (mirror the locally-tested worker ghl_tripwire_watch.py)
const T = {
  CAPTURE_STALE_H: 24,
  LEG_FAIL_ALERT_MIN: 60, // max one blindness email per leg per hour
  REPEAT_CAP_H: 6, // same condition instance re-pages at most 6h
  BIZ: { startHour: 8, endHour: 18 }, // America/New_York Mon-Fri
};

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const GHL_PIT = process.env.GHL_API_KEY || "";
const FIREBASE_REFRESH = process.env.GHL_FIREBASE_REFRESH_TOKEN || "";
const FIREBASE_API_KEY = process.env.GHL_FIREBASE_API_KEY || "";

/** OAuth quartet read at CALL time, never at module scope — a battery or
 *  local run that deletes the env BEFORE import must be able to disable the
 *  email leg (module-scope capture + ESM import hoisting defeated that in
 *  the pre-2026-09-22 battery: it sent real mail while "disabled"). */
function googleOAuth() {
  return process.env.GOOGLE_OAUTH_REFRESH_TOKEN
    ? {
        refresh: process.env.GOOGLE_OAUTH_REFRESH_TOKEN,
        clientId: process.env.GOOGLE_OAUTH_CLIENT_ID,
        clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
        tokenUri: process.env.GOOGLE_OAUTH_TOKEN_URI,
      }
    : null;
}

/* ------------------------------------------------------------------ utils */

function log(obj) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...obj }));
}

async function jfetch(url, opts = {}, timeoutMs = 15000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: ctl.signal });
    const text = await res.text();
    let body = null;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return { status: res.status, ok: res.status >= 200 && res.status < 300, body, text };
  } finally {
    clearTimeout(t);
  }
}

/** Tolerant timestamp parse — never NaN-silent. Returns ms epoch or null. */
function tsMs(v) {
  if (!v) return null;
  if (typeof v === "number") return v < 1e12 ? v * 1000 : v;
  const t = Date.parse(String(v));
  return Number.isNaN(t) ? null : t;
}

function ageH(ms) {
  return ms == null ? null : (Date.now() - ms) / 3.6e6;
}

/** Business-hours gate: America/New_York Mon-Fri, 08:00 <= hour < 18:00.
 *  Saturday (dow 6) is NOT a business day — a quiet weekend must not page. */
function bizHoursNow(now = new Date()) {
  const fmt = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/New_York",
    hour12: false,
    weekday: "short",
    hour: "2-digit",
  });
  const parts = Object.fromEntries(fmt.formatToParts(now).map((p) => [p.type, p.value]));
  const dow = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 }[parts.weekday] ?? 0;
  const hour = Number(parts.hour);
  return dow >= 1 && dow <= 5 && hour >= T.BIZ.startHour && hour < T.BIZ.endHour;
}

/* -------------------------------------------------------------- supabase */

function sb() {
  const headers = {
    apikey: SUPABASE_KEY,
    Authorization: "Bearer " + SUPABASE_KEY,
    Accept: "application/json",
    "Content-Type": "application/json",
    "User-Agent": UA,
  };
  return {
    get: async (path) =>
      jfetch(`${SUPABASE_URL}/rest/v1/${path}`, { headers }),
    post: async (path, body) =>
      jfetch(`${SUPABASE_URL}/rest/v1/${path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      }),
  };
}

/** DRY is invocation-scoped: set at the top of every handler run so warm
 *  containers never leak a previous tick's mode into this one. */
let DRY = false;

/**
 * Insert-first dedupe lock against ops_alert_log (unique alert_key).
 *
 * Returns true when THIS invocation may send the email:
 *   - insert succeeds  -> fresh condition instance, send
 *   - insert fails     -> already alerted. BUT if the existing row is older
 *                         than repeatCapH, delete it and re-insert so a
 *                         persisting condition re-pages at most every cap
 *                         window (6h standard, 1h for blind legs).
 * In dry mode: reports "claimed" WITHOUT writing anything.
 */
async function claimAlert(check, fp, severity, repeatCapH = T.REPEAT_CAP_H) {
  if (DRY) return true;
  const key = `ghl:alert:${check}:${fp}`;
  const ins = await sb().post("ops_alert_log", {
    alert_key: key,
    check_id: `ghl_${check}`,
    severity,
  });
  if (ins.status === 201 || ins.ok) return true;
  // duplicate key -> check age of the existing row
  const st = await sb().get(
    `ops_alert_log?select=created_at&alert_key=eq.${encodeURIComponent(key)}&limit=1`
  );
  const at = st.ok && Array.isArray(st.body) && st.body[0]?.created_at ? tsMs(st.body[0].created_at) : null;
  if (at != null && Date.now() - at > repeatCapH * 3.6e6) {
    // re-arm: delete the stale row, re-insert, send
    await jfetch(
      `${SUPABASE_URL}/rest/v1/ops_alert_log?alert_key=eq.${encodeURIComponent(key)}`,
      {
        method: "DELETE",
        headers: {
          apikey: SUPABASE_KEY,
          Authorization: "Bearer " + SUPABASE_KEY,
        },
      }
    );
    const retry = await sb().post("ops_alert_log", {
      alert_key: key,
      check_id: `ghl_${check}`,
      severity,
    });
    return retry.status === 201 || retry.ok;
  }
  return false;
}

/** Release a claimed lock after a FAILED delivery, so the next run retries
 *  instead of muting the condition for the repeat-cap window. */
async function releaseAlert(check, fp) {
  const key = `ghl:alert:${check}:${fp}`;
  const res = await jfetch(
    `${SUPABASE_URL}/rest/v1/ops_alert_log?alert_key=eq.${encodeURIComponent(key)}`,
    {
      method: "DELETE",
      headers: {
        apikey: SUPABASE_KEY,
        Authorization: "Bearer " + SUPABASE_KEY,
      },
    }
  );
  log({ event: "alert_lock_released", check, status: res.status });
}

/** Generic state upsert via ops_alert_log rows (value stored in severity).
 *  Insert-first; on duplicate key, PATCH the value in place. No-op in dry. */
async function setState(key, value) {
  if (DRY) return true;
  const ins = await sb().post("ops_alert_log", {
    alert_key: key,
    check_id: "ghl_state",
    severity: String(value),
  });
  if (ins.status === 201 || ins.ok) return true;
  const patch = await jfetch(
    `${SUPABASE_URL}/rest/v1/ops_alert_log?alert_key=eq.${encodeURIComponent(key)}`,
    {
      method: "PATCH",
      headers: {
        apikey: SUPABASE_KEY,
        Authorization: "Bearer " + SUPABASE_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ severity: String(value) }),
    }
  );
  return patch.ok;
}

async function getState(key) {
  const res = await sb().get(
    `ops_alert_log?select=severity,created_at&alert_key=eq.${encodeURIComponent(key)}&order=created_at.desc&limit=1`
  );
  if (!res.ok || !Array.isArray(res.body) || res.body.length === 0) return null;
  return { value: res.body[0].severity, at: res.body[0].created_at };
}

/* ------------------------------------------------------------------- ghl */

let jwtCache = { tok: null, exp: 0 };

async function ghlJwt() {
  if (jwtCache.tok && Date.now() < jwtCache.exp - 60_000) return jwtCache.tok;
  if (!FIREBASE_REFRESH || !FIREBASE_API_KEY) return null;
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: FIREBASE_REFRESH,
  }).toString();
  const res = await jfetch(
    `https://securetoken.googleapis.com/v1/token?key=${FIREBASE_API_KEY}`,
    { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body }
  );
  if (!res.ok || !res.body?.id_token) return null;
  jwtCache = { tok: res.body.id_token, exp: Date.now() + (res.body.expires_in ?? 3000) * 1000 };
  return jwtCache.tok;
}

async function ghlInternal(path) {
  const tok = await ghlJwt();
  if (!tok) return { status: 0, ok: false, body: null, text: "no-firebase-creds" };
  return jfetch(`${BACKEND}${path}`, {
    headers: { "token-id": tok, channel: "APP", Accept: "application/json", "User-Agent": UA },
  });
}

async function ghlPublic(path) {
  if (!GHL_PIT) return { status: 0, ok: false, body: null, text: "no-pit" };
  return jfetch(`${PUBLIC}${path}`, {
    headers: {
      Authorization: "Bearer " + GHL_PIT,
      Version: "2021-07-28",
      Accept: "application/json",
      "User-Agent": UA,
    },
  });
}

/* ----------------------------------------------------------------- email */

async function gmailAccessToken(OA) {
  const body = new URLSearchParams({
    refresh_token: OA.refresh,
    client_id: OA.clientId,
    client_secret: OA.clientSecret,
    grant_type: "refresh_token",
  }).toString();
  const res = await jfetch(OA.tokenUri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  return res.ok ? res.body.access_token : null;
}

async function sendFindingEmail(f) {
  const OA = googleOAuth();
  if (!OA) {
    log({ event: "email_skip_no_oauth", subject: f.subject });
    return false;
  }
  const token = await gmailAccessToken(OA);
  if (!token) {
    log({ event: "gmail_token_failed", subject: f.subject });
    return false;
  }
  const raw = [
    `To: ${ALERT_TO.join(", ")}`,
    `From: ${ALERT_FROM}`,
    'Content-Type: multipart/alternative; boundary="mwcg"',
    `Subject: ${f.subject}`,
    "",
    "--mwcg",
    'Content-Type: text/html; charset=UTF-8',
    "",
    buildHtml(f),
    "",
    "--mwcg",
    'Content-Type: text/plain; charset=UTF-8',
    "",
    f.lines.join("\n"),
    "",
    "--mwcg--",
    "",
  ].join("\r\n");
  const res = await jfetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify({ raw: Buffer.from(raw).toString("base64url") }),
  });
  log({ event: res.ok ? "alert_email_sent" : "alert_email_failed", subject: f.subject, status: res.status, to: ALERT_TO.join(",") });
  return res.ok;
}

/* ----------------------------------------------------------------- checks */

let findings = []; // RESET at the start of every invocation — warm containers
// reuse module state between cron ticks, and an unreset array would
// re-page every past finding forever (caught by battery.mjs run-2).

function page(check, fp, subject, lines) {
  findings.push({ check, fp, subject, lines });
}

async function checkPlatform() {
  const r = await jfetch(STATUSPAGE, { headers: { Accept: "application/json" } });
  if (!r.ok) return { ok: false };
  const ind = r.body?.status?.indicator ?? "unknown";
  if (ind !== "none") {
    const fp = ind;
    if (await claimAlert("platform", fp, "alert")) {
      page(
        "platform",
        fp,
        `[GHL] Platform status: ${ind.toUpperCase()}`,
        [
          `GHL's own status page reports: ${ind} — ${r.body?.status?.description ?? "?"}.`,
          "Impact: workflows / messages may fail platform-wide.",
          "Evidence: " + STATUSPAGE,
          "Check: https://gohighlevel.statuspage.io",
        ]
      );
    }
  }
  return { ok: true, indicator: ind };
}

/** The error-notification LIST route returns 0 rows even while count > 0
 *  (probed exhaustively 2026-09-22: 16 param shapes, Firestore, frontend
 *  bundles — GHL exposes no per-workflow error detail to any API we can
 *  auth to). So this alert cannot name the failing workflow itself; it
 *  names the ONE surface that can — the Needs Review tab — via a direct
 *  deep link. GHL's own 24h digest email links to the same page. */
async function checkErrCount() {
  const r = await ghlInternal(`/workflow/${LOC}/error-notification/count`);
  if (!r.ok || !/^"?[0-9]+"?$/.test(String(r.body ?? ""))) return { ok: false };
  const count = parseInt(String(r.body), 10);
  const st = await getState("ghl:state:err_count");
  if (st) {
    const prev = parseInt(st.value, 10);
    if (!Number.isNaN(prev) && count > prev) {
      let detail = "";
      const lr = await ghlInternal(
        `/workflow/error-notification/list?location_id=${LOC}&limit=10`
      );
      // the list returns rows ONLY in the rare case GHL exposes them; today it is 0
      if (lr.ok && Array.isArray(lr.body?.rows) && lr.body.rows.length) {
        detail =
          " Rows (if GHL exposes them): " +
          lr.body.rows
            .slice(0, 3)
            .map((row) => JSON.stringify(row).slice(0, 200))
            .join(" | ");
      }
      const fp = `${prev}-${count}`;
      if (await claimAlert("wferrors", fp, "alert")) {
        page("wferrors", fp, `[GHL] Workflow errors +${count - prev} (${prev} -> ${count})`, [
          `Workflow error notifications rose from ${prev} to ${count} in the last 5 minutes.`,
          "Impact: workflows failing execution — SMS/email/steps not running.",
          "Evidence: internal error-notification/count" + detail,
          `Which workflow: GHL exposes no per-workflow error detail via API (verified 2026-09-22). Open the Needs Review tab — it lists every failing workflow by name: ${REVIEW_URL}`,
        ]);
      }
    }
  }
  // STANDING errors: count > 0 nobody has acknowledged. Without this, errors
  // that appear between deploys (or after a state reset) sit silent forever —
  // the rise-detector only pages on a delta. Re-pages daily (24h cap) so a
  // persisting error is not forgotten; recovers silently when acknowledged.
  if (count > 0) {
    const fpStanding = `standing:${count}`;
    if (await claimAlert("wferrors", fpStanding, "alert", 24)) {
      page("wferrors", fpStanding, `[GHL] ${count} workflow error${count === 1 ? "" : "s"} pending review (standing)`, [
        `${count} workflow error notification${count === 1 ? " is" : "s are"} pending in GHL right now.`,
        "Impact: a workflow is failing execution — SMS/email/steps not running for affected contacts.",
        `Evidence: internal error-notification/count = ${count} (verified live).`,
        `Which workflow: GHL exposes no per-workflow error detail via API (verified 2026-09-22). Open Needs Review — it lists every failing workflow by name: ${REVIEW_URL}`,
      ]);
    }
  }
  await setState("ghl:state:err_count", count);
  return { ok: true, count };
}

async function checkExecutions() {
  const r = await ghlInternal(`/workflow/executions?location_id=${LOC}&limit=10`);
  if (!r.ok || !Array.isArray(r.body)) return { ok: false };
  const n = r.body.length;
  const st = await getState("ghl:state:executions");
  const fp = `rows:${n}`;
  if (n > 0 && st?.value !== fp) {
    if (await claimAlert("executions", fp, "warn")) {
      page("executions", fp, `[GHL] Executions surface returned ${n} rows (was always empty)`, [
        "The internal executions route started returning rows — new failure-signal surface.",
        `Evidence: /workflow/executions limit=10 -> ${n} rows.`,
        `Check: if these rows are execution errors, the failing workflows are listed by name in Needs Review: ${REVIEW_URL}`,
      ]);
    }
  }
  await setState("ghl:state:executions", fp);
  return { ok: true, rows: n };
}

/** Estate flip with NAMING: stores the published ID->name map in state so the
 *  alert says WHICH workflow appeared/vanished — the question this signal
 *  exists to answer. Values live in the severity column (type: text, no
 *  length cap — verified against the OpenAPI spec 2026-09-22). */
async function checkEstate() {
  const r = await ghlPublic(`/workflows/?locationId=${LOC}`); // BARE params — limit 422s
  if (!r.ok || !Array.isArray(r.body?.workflows)) return { ok: false };
  const wfs = r.body.workflows;
  const pub = wfs.filter((w) => w.status === "published");
  const published = pub.length;
  const idMap = Object.fromEntries(pub.map((w) => [w.id, w.name]));
  const st = await getState("ghl:state:estate_published");
  const stMap = await getState("ghl:state:estate_map");
  if (st) {
    const prev = parseInt(st.value, 10);
    if (!Number.isNaN(prev) && published !== prev) {
      // diff the ID sets to NAME the flipped workflows
      let names = "";
      try {
        const prevMap = JSON.parse(stMap?.value ?? "{}");
        const prevIds = new Set(Object.keys(prevMap));
        const nowIds = new Set(Object.keys(idMap));
        const added = [...nowIds].filter((id) => !prevIds.has(id)).map((id) => idMap[id]);
        const removed = [...prevIds].filter((id) => !nowIds.has(id)).map((id) => prevMap[id] ?? id);
        const parts = [];
        if (removed.length) parts.push("UNPUBLISHED/DELETED: " + removed.join(", "));
        if (added.length) parts.push("NEWLY PUBLISHED: " + added.join(", "));
        if (parts.length) names = " " + parts.join(" | ");
      } catch {
        // state unreadable -> fall back to count-only alert (names stay empty)
      }
      const fp = `${prev}-${published}`;
      if (await claimAlert("estate", fp, "alert")) {
        page("estate", fp, `[GHL] Published workflows ${prev} -> ${published}${names ? " — " + names.slice(1) : ""}`, [
          `The live published-workflow count changed (${prev} -> ${published}; total ${wfs.length}).${names}`,
          "Impact: a production automation was published, unpublished, or deleted.",
          "Evidence: public /workflows list, status split, ID-set diff vs stored baseline.",
          "Check: GHL Automation -> Workflows; verify the change was intentional.",
        ]);
      }
    }
  }
  await setState("ghl:state:estate_published", published);
  await setState("ghl:state:estate_map", JSON.stringify(idMap));
  return { ok: true, published, total: wfs.length };
}

async function checkCapture() {
  const r = await sb().get(
    `booking_attribution_records?select=event,created_at&order=created_at.desc&limit=100`
  );
  if (!r.ok || !Array.isArray(r.body) || !r.body.length) return { ok: false };
  const watch = ["portal_booking", "track_generate_lead", "track_booking_complete"];
  const byEvent = {};
  for (const row of r.body) byEvent[row.event] ??= row.created_at;
  let worst = 0;
  for (const ev of watch) {
    if (byEvent[ev]) worst = Math.max(worst, ageH(tsMs(byEvent[ev])) ?? 0);
  }
  if (worst > T.CAPTURE_STALE_H && bizHoursNow()) {
    if (await claimAlert("capture", "stale", "alert")) {
      page("capture", "stale", "[MWC] Booking capture pipeline DOWN — no attribution events", [
        `No booking attribution events (portal_booking / track_*) for ${worst.toFixed(1)}h during US business hours.`,
        "Impact: bookings/forms are not being captured at all — leads lost.",
        "Evidence: Supabase booking_attribution_records newest per event.",
        "Check: booking app + GHL capture path (mwc-admin conversion ops).",
      ]);
    }
  }
  return { ok: true, worstAgeH: worst };
}

/* --------------------------------------------------------------- blindness */

const LEGS = ["platform", "wferrors", "executions", "estate", "capture"];

async function checkBlindness(results) {
  for (const leg of LEGS) {
    const ok = results[leg]?.ok;
    const key = `ghl:state:leg_${leg}`;
    if (ok) {
      await setState(key, "0");
      continue;
    }
    const st = await getState(key);
    const fails = st ? parseInt(st.value, 10) || 0 : 0;
    const next = fails + 1;
    await setState(key, String(next));
    if (next >= 2) {
      // blind legs re-page at most once per hour (LEG_FAIL_ALERT_MIN)
      if (await claimAlert("blind", leg, "warn", T.LEG_FAIL_ALERT_MIN / 60)) {
        page("blind", leg, `[GHL tripwire] Signal BLIND: '${leg}' failing ${next} runs`, [
          `The '${leg}' detection leg has failed ${next} consecutive runs — this signal is unwatched until it recovers.`,
          "Impact: errors of this class go undetected while blind (the eyes themselves need checking).",
          "Evidence: probe status recorded per run in ops_alert_log state keys.",
          "Check: GHL tokens (PAT / Firebase refresh) and Supabase access for this function.",
        ]);
      }
    }
  }
}

/* --------------------------------------------------------------- handler */

function esc(s) {
  return String(s).replace(/[<>&]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" })[c]);
}

function buildHtml(f) {
  const rows = f.lines
    .map(
      (l, i) =>
        `<tr><td style="padding:6px 14px;color:#6B7089;font-size:11px;white-space:nowrap;">${
          i === 0 ? "What" : i === 1 ? "Impact" : i === 2 ? "Evidence" : "Check"
        }</td><td style="padding:6px 14px;color:#0B1029;font-size:13px;">${esc(l)}</td></tr>`
    )
    .join("");
  return `<div style="font-family:Arial,Helvetica,sans-serif;max-width:620px;margin:0 auto;background:#fff;border:1px solid #E6E3DC;border-radius:10px;overflow:hidden;">
  <div style="background:#0B1029;color:#fff;padding:14px 18px;font-size:15px;font-weight:700;">&#9888; ${esc(f.subject)}</div>
  <div style="padding:16px 18px;">
    <table style="border-collapse:collapse;width:100%;background:#FAF9F6;border-radius:8px;">${rows}</table>
    <p style="margin:14px 0 0;font-size:11px;color:#6B7089;">MWC GHL tripwire · every 5 min · ${new Date().toISOString()}</p>
  </div>
</div>`;
}

/** Guard a single check so one leg's crash (timeout, bad payload) reads as a
 *  BLIND leg instead of killing the whole run — a 500 here would skip the
 *  run marker and make the deadman false-page "cron not firing". */
async function guard(name, fn) {
  try {
    return await fn();
  } catch (e) {
    const err = String(e?.message ?? e).slice(0, 160);
    log({ event: "check_exception", check: name, err });
    return { ok: false, error: err };
  }
}

export default async function handler(req, res) {
  // Auth: fail-closed, header-only bearer. No query-param secret form.
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    log({ event: "config_missing", need: "CRON_SECRET" });
    res.statusCode = 500;
    return res.json({ error: "cron secret not configured" });
  }
  if ((req.headers.authorization || "") !== `Bearer ${secret}`) {
    res.statusCode = 401;
    return res.json({ error: "unauthorized" });
  }

  if (!SUPABASE_URL || !SUPABASE_KEY) {
    log({ event: "config_missing", need: "SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY" });
    res.statusCode = 500;
    return res.json({ error: "supabase env missing" });
  }

  const dry = new URL(req.url, "http://x").searchParams.get("dry") === "1";

  const t0 = Date.now();
  findings = []; // invocation-scoped: never carry findings across warm ticks
  DRY = dry; // invocation-scoped: never carry mode across warm ticks
  const results = {};
  results.platform = await guard("platform", checkPlatform);
  results.wferrors = await guard("wferrors", checkErrCount);
  results.executions = await guard("executions", checkExecutions);
  results.estate = await guard("estate", checkEstate);
  results.capture = await guard("capture", checkCapture);
  try {
    await checkBlindness(results);
  } catch (e) {
    log({ event: "blindness_exception", err: String(e?.message ?? e).slice(0, 160) });
  }

  let sent = [];
  let deliveryFailed = [];
  if (!dry) {
    for (const f of findings) {
      let ok = false;
      try {
        ok = await sendFindingEmail(f);
      } catch (e) {
        log({ event: "email_exception", check: f.check, err: String(e?.message ?? e).slice(0, 160) });
      }
      if (ok) {
        sent.push(f.check);
      } else {
        // Delivery failed: surface it AND release the lock so the next run
        // retries — a lost page must never mute the condition for 6h.
        deliveryFailed.push(f.check);
        try {
          await releaseAlert(f.check, f.fp);
        } catch (e) {
          log({ event: "release_failed", check: f.check, err: String(e?.message ?? e).slice(0, 160) });
        }
      }
    }
  }

  log({
    event: "run",
    legs: Object.fromEntries(LEGS.map((l) => [l, results[l]?.ok ? "ok" : "FAIL"])),
    findings: findings.map((f) => f.check),
    sent,
    delivery_failed: deliveryFailed,
    dry,
    ms: Date.now() - t0,
  });

  // Run marker for the dead-man's switch (api/deadman.js): one row per 5-min
  // bucket; insert-first dedupes retries. dry mode writes nothing. A marker
  // write failure is LOUD (logged) — the deadman will catch it within 20 min.
  if (!dry) {
    try {
      await setState(`ghl:state:run:${Math.floor(Date.now() / 300000)}`, "run");
    } catch (e) {
      log({ event: "marker_write_failed", err: String(e?.message ?? e).slice(0, 160) });
    }
  }

  res.statusCode = 200;
  res.json({
    ok: findings.length === 0,
    legs: Object.fromEntries(LEGS.map((l) => [l, results[l]?.ok ? "ok" : "FAIL"])),
    observed: {
      err_count: results.wferrors?.count,
      estate_published: results.estate?.published,
      estate_total: results.estate?.total,
      capture_worst_age_h: results.capture?.worstAgeH,
    },
    findings: findings.map((f) => f.check),
    alerts_sent: sent,
    delivery_failed: deliveryFailed,
    dry,
    ms: Date.now() - t0,
  });
}

/** Test seams for battery.mjs (named exports — ignored by Vercel's handler
 *  resolution, which only consumes the default export). */
export const _internals = {
  claimAlert,
  releaseAlert,
  setState,
  getState,
  bizHoursNow,
  setDry: (v) => (DRY = v),
};
