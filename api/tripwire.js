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
 *  A  blindness      per-leg probe failures (2+ consecutive)          -> pages
 *  B  platform       statuspage.io indicator != none                  -> pages
 *  C  wf errors      error-notification/count rise (Firebase JWT)     -> pages
 *  D  wf err detail  error-notification/list rows (enriches C)        -> rides C
 *  E  executions     /workflow/executions rows appear (canary)        -> pages
 *  F  dispatch       conversion_queue all-skipped + arrivals fresh    -> pages
 *  G  capture        booking_attribution_records stale in biz hours   -> pages
 *  H  send failures  conversion_sends response_status != 200          -> pages
 *  I  estate flip    published workflow count changes                 -> pages
 *
 * Statelessness: serverless invocations share nothing, so ALL state lives in
 * Supabase — ops_alert_log rows are the dedupe lock AND the run ledger:
 *   ghl:run:<ISO-minutes>  — one per invocation (liveness/eyes check)
 *   ghl:state:<key>        — observed baselines (err_count, estate, legs)
 *   ghl:alert:<check>:<fp> — insert-first lock per condition instance
 *
 * Auth: CRON_SECRET bearer (Vercel cron sends it). ?dry=1 evaluates and
 * reports without sending email or writing anything.
 */

const LOC = process.env.GHL_LOCATION_ID || "Ghstz8eIsHWLeXek47dk";
const BACKEND = "https://backend.leadconnectorhq.com";
const PUBLIC = "https://services.leadconnectorhq.com";
const STATUSPAGE = "https://gohighlevel.statuspage.io/api/v2/status.json";
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36";
const ALERT_TO = process.env.ALERT_TO || "techops@menswellnesscenters.com";
const ALERT_FROM = process.env.ALERT_FROM || "v-islam.hetta@mwcforme.com";

// thresholds (mirror the locally-tested worker ghl_tripwire_watch.py)
const T = {
  DISPATCH_STALL_H: 6,
  DISPATCH_ARRIVAL_H: 2,
  SEND_STALE_H: 36,
  CAPTURE_STALE_H: 24,
  LEG_FAIL_ALERT_MIN: 60, // max one blindness email per leg per hour
  REPEAT_CAP_H: 6, // same condition instance re-pages at most 6h
  QUEUE_WINDOW: 60,
  SEND_WINDOW: 100,
  BIZ: { startHour: 8, endHour: 18 }, // America/New_York Mon-Fri
};

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const GHL_PIT = process.env.GHL_API_KEY || "";
const FIREBASE_REFRESH = process.env.GHL_FIREBASE_REFRESH_TOKEN || "";
const FIREBASE_API_KEY = process.env.GHL_FIREBASE_API_KEY || "";
const GOOGLE_OAUTH = process.env.GOOGLE_OAUTH_REFRESH_TOKEN
  ? {
      refresh: process.env.GOOGLE_OAUTH_REFRESH_TOKEN,
      clientId: process.env.GOOGLE_OAUTH_CLIENT_ID,
      clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
      tokenUri: process.env.GOOGLE_OAUTH_TOKEN_URI,
    }
  : null;

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

function bizHoursNow() {
  const fmt = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/New_York",
    hour12: false,
    weekday: "short",
    hour: "2-digit",
  });
  const parts = Object.fromEntries(fmt.formatToParts(new Date()).map((p) => [p.type, p.value]));
  const dow = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 }[parts.weekday] ?? 1;
  const hour = Number(parts.hour);
  return dow > 0 && hour >= T.BIZ.startHour && hour < T.BIZ.endHour;
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

/**
 * Insert-first dedupe lock against ops_alert_log (unique alert_key).
 *
 * Returns true when THIS invocation may send the email:
 *   - insert succeeds  -> fresh condition instance, send
 *   - insert fails     -> already alerted. BUT if the existing row is older
 *                         than REPEAT_CAP_H, delete it and re-insert so a
 *                         persisting condition re-pages at most every 6h.
 */
async function claimAlert(check, fp, severity) {
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
  if (at != null && Date.now() - at > T.REPEAT_CAP_H * 3.6e6) {
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

/** Generic state upsert via ops_alert_log rows (value stored in severity).
 *  Insert-first; on duplicate key, PATCH the value in place. */
async function setState(key, value) {
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

async function sendAlertEmail(subject, lines) {
  if (GOOGLE_OAUTH) return sendViaGmail(subject, lines);
  log({ event: "email_skip_no_oauth" });
  return false;
}

async function gmailAccessToken() {
  const body = new URLSearchParams({
    refresh_token: GOOGLE_OAUTH.refresh,
    client_id: GOOGLE_OAUTH.clientId,
    client_secret: GOOGLE_OAUTH.clientSecret,
    grant_type: "refresh_token",
  }).toString();
  const res = await jfetch(GOOGLE_OAUTH.tokenUri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  return res.ok ? res.body.access_token : null;
}

async function sendViaGmail(subject, lines) {
  const token = await gmailAccessToken();
  if (!token) {
    log({ event: "gmail_token_failed" });
    return false;
  }
  const boundary = "mwcb" + Date.now();
  const text = lines.join("\n");
  const raw = [
    `To: ${ALERT_TO}`,
    `From: ${ALERT_FROM}`,
    "Content-Type: multipart/alternative; boundary=" + boundary,
    `Subject: ${subject}`,
    "",
    "--" + boundary,
    "Content-Type: text/plain; charset=UTF-8",
    "",
    text,
    "",
    "--" + boundary + "--",
    "",
  ].join("\r\n");
  const res = await jfetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify({ raw: Buffer.from(raw).toString("base64url") }),
  });
  if (res.ok) log({ event: "email_sent", subject, id: res.body?.id });
  else log({ event: "email_failed", status: res.status, text: String(res.text).slice(0, 120) });
  return res.ok;
}

/* ----------------------------------------------------------------- checks */

let findings = []; // RESET at the start of every invocation — warm containers
// reuse module state between cron ticks, and an unreset array would
// re-page every past finding forever (caught by battery.mjs run-2).

function page(check, subject, lines) {
  findings.push({ check, subject, lines });
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
      if (lr.ok && Array.isArray(lr.body?.rows) && lr.body.rows.length) {
        detail =
          " Recent rows: " +
          lr.body.rows
            .slice(0, 3)
            .map((row) => JSON.stringify(row).slice(0, 200))
            .join(" | ");
      }
      if (await claimAlert("wferrors", `${prev}-${count}`, "alert")) {
        page("wferrors", `[GHL] Workflow errors +${count - prev} (${prev} -> ${count})`, [
          `Workflow error notifications rose from ${prev} to ${count} in the last 5 minutes.`,
          "Impact: workflows failing execution — SMS/email/steps not running.",
          "Evidence: internal error-notification/count" + detail,
          "Check: GHL Automation -> Workflows -> Needs Review tab.",
        ]);
      }
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
  if (n > 0 && st?.value !== `rows:${n}`) {
    if (await claimAlert("executions", `rows:${n}`, "warn")) {
      page("executions", `[GHL] Executions surface returned ${n} rows (was always empty)`, [
        "The internal executions route started returning rows — new failure-signal surface.",
        `Evidence: /workflow/executions limit=10 -> ${n} rows.`,
        "Check: review what GHL exposed; this is informational for tech ops.",
      ]);
    }
  }
  await setState("ghl:state:executions", `rows:${n}`);
  return { ok: true, rows: n };
}

async function checkEstate() {
  const r = await ghlPublic(`/workflows/?locationId=${LOC}`); // BARE params — limit 422s
  if (!r.ok || !Array.isArray(r.body?.workflows)) return { ok: false };
  const wfs = r.body.workflows;
  const published = wfs.filter((w) => w.status === "published").length;
  const st = await getState("ghl:state:estate_published");
  if (st) {
    const prev = parseInt(st.value, 10);
    if (!Number.isNaN(prev) && published !== prev) {
      if (await claimAlert("estate", `${prev}-${published}`, "alert")) {
        page("estate", `[GHL] Published workflows ${prev} -> ${published}`, [
          `The live published-workflow count changed (${prev} -> ${published}; total ${wfs.length}).`,
          "Impact: a production automation was published, unpublished, or deleted.",
          "Evidence: public /workflows list, status split.",
          "Check: GHL Automation -> Workflows; verify the change was intentional.",
        ]);
      }
    }
  }
  await setState("ghl:state:estate_published", published);
  return { ok: true, published, total: wfs.length };
}

async function checkDispatch() {
  const r = await sb().get(
    `conversion_queue?select=status,destination,created_at&order=created_at.desc&limit=${T.QUEUE_WINDOW}`
  );
  if (!r.ok || !Array.isArray(r.body) || !r.body.length) return { ok: false };
  const newestAge = ageH(tsMs(r.body[0].created_at));
  const nonskip = r.body.find((row) => row.status !== "skipped");
  const lastOkAge = nonskip ? ageH(tsMs(nonskip.created_at)) : null;
  if ((lastOkAge == null || lastOkAge > T.DISPATCH_STALL_H) && newestAge != null && newestAge < T.DISPATCH_ARRIVAL_H) {
    // corroborate with sends staleness
    const s = await sb().get(
      `conversion_sends?select=destination,created_at&order=created_at.desc&limit=200`
    );
    let stale = "";
    if (s.ok && Array.isArray(s.body)) {
      const byDest = {};
      for (const row of s.body) byDest[row.destination] ??= row.created_at;
      const parts = [];
      for (const [d, t] of Object.entries(byDest)) {
        const a = ageH(tsMs(t));
        if (a != null && a > T.SEND_STALE_H) parts.push(`${d} ${a.toFixed(0)}h`);
      }
      if (parts.length) stale = " Stale ad-platform sends: " + parts.join(", ") + ".";
    }
    if (await claimAlert("dispatch", "down", "alert")) {
      page("dispatch", "[MWC] GHL conversion dispatch DOWN — all queue rows skipped", [
        `Every conversion_queue row in the last ${T.QUEUE_WINDOW} has status='skipped' (last successful send: ${
          nonskip ? nonskip.created_at : "none in window"
        }) while new rows keep arriving (${newestAge.toFixed(1)}h old).${stale}`,
        "Impact: Google/Meta/Microsoft/TikTok conversion APIs receive NOTHING — ad bidding runs blind.",
        "Evidence: Supabase conversion_queue newest 60 rows, all skipped.",
        "Check: the dispatcher skip gate — queue rows are created but never sent (mwc-admin conversion ops).",
      ]);
    }
  }
  return { ok: true, lastOkAge, newestAge };
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
      page("capture", "[MWC] Booking capture pipeline DOWN — no attribution events", [
        `No booking attribution events (portal_booking / track_*) for ${worst.toFixed(1)}h during US business hours.`,
        "Impact: bookings/forms are not being captured at all — leads lost.",
        "Evidence: Supabase booking_attribution_records newest per event.",
        "Check: booking app + GHL capture path (mwc-admin conversion ops).",
      ]);
    }
  }
  return { ok: true, worstAgeH: worst };
}

async function checkSendFailures() {
  const r = await sb().get(
    `conversion_sends?select=destination,response_status,created_at&order=created_at.desc&limit=${T.SEND_WINDOW}`
  );
  if (!r.ok || !Array.isArray(r.body)) return { ok: false };
  const bad = r.body.filter((row) => row.response_status != null && String(row.response_status) !== "200");
  if (bad.length) {
    const fp = `${bad.length}|${bad[0].created_at}|${bad[0].destination}`;
    if (await claimAlert("sendfail", fp, "alert")) {
      page("sendfail", `[MWC] Conversion send failures — ${bad.length} of last ${r.body.length} non-200`, [
        `${bad.length} of the last ${r.body.length} sends to ad platforms returned non-200 (newest: ${bad[0].created_at} dest=${bad[0].destination} status=${bad[0].response_status}).`,
        "Impact: rejected/failed CAPI events — conversions not counted by ad platforms.",
        "Evidence: Supabase conversion_sends response_status distribution.",
        "Check: dispatcher error handling + platform API status (conversion ops).",
      ]);
    }
  }
  return { ok: true, bad: bad.length };
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
      if (await claimAlert("blind", leg, "warn")) {
        page("blind", `[GHL tripwire] Signal BLIND: '${leg}' failing ${next} runs`, [
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

async function sendFindingEmail(f) {
  if (!GOOGLE_OAUTH) return false;
  const token = await gmailAccessToken();
  if (!token) return false;
  const raw = [
    `To: ${ALERT_TO}`,
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
  log({ event: res.ok ? "alert_email_sent" : "alert_email_failed", subject: f.subject, status: res.status });
  return res.ok;
}

export default async function handler(req, res) {
  const secret = process.env.CRON_SECRET;
  if (secret) {
    const auth = req.headers.authorization || "";
    const provided = new URL(req.url, "http://x").searchParams.get("secret") || auth;
    if (provided !== `Bearer ${secret}` && provided !== secret) {
      res.statusCode = 401;
      return res.json({ error: "unauthorized" });
    }
  }
  const dry = new URL(req.url, "http://x").searchParams.get("dry") === "1";

  if (!SUPABASE_URL || !SUPABASE_KEY) {
    log({ event: "config_missing", need: "SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY" });
    res.statusCode = 500;
    return res.json({ error: "supabase env missing" });
  }

  const t0 = Date.now();
  findings = []; // invocation-scoped: never carry findings across warm ticks
  const results = {};
  // NOTE (2026-09-21, user correction): conversion + attribution are handled
  // by Curve now. The old conversion_queue/conversion_sends signals
  // (dispatch, sendfail) watched a DECOMMISSIONED path and paged falsely —
  // removed. Capture (booking_attribution_records freshness) is kept: it
  // watches the booking-app capture leg, not ad dispatch.
  results.platform = await checkPlatform();
  results.wferrors = await checkErrCount();
  results.executions = await checkExecutions();
  results.estate = await checkEstate();
  results.capture = await checkCapture();
  await checkBlindness(results);

  let sent = [];
  if (!dry) {
    for (const f of findings) {
      const ok = await sendFindingEmail(f);
      if (ok) sent.push(f.check);
    }
  }

  log({
    event: "run",
    legs: Object.fromEntries(LEGS.map((l) => [l, results[l]?.ok ? "ok" : "FAIL"])),
    findings: findings.map((f) => f.check),
    sent,
    dry,
    ms: Date.now() - t0,
  });

  // Run marker for the dead-man's switch (api/deadman.js): one row per 5-min
  // bucket; insert-first dedupes retries. dry mode writes nothing.
  if (!dry) {
    await setState(`ghl:state:run:${Math.floor(Date.now() / 300000)}`, "run");
  }

  res.statusCode = 200;
  res.json({
    ok: findings.length === 0,
    legs: Object.fromEntries(LEGS.map((l) => [l, results[l]?.ok ? "ok" : "FAIL"])),
    observed: {
      err_count: results.wferrors?.count,
      estate_published: results.estate?.published,
      estate_total: results.estate?.total,
      dispatch_last_ok_age_h: results.dispatch?.lastOkAgeH,
      dispatch_newest_age_h: results.dispatch?.newestAgeH,
      capture_worst_age_h: results.capture?.worstAgeH,
      sendfail_bad: results.sendfail?.bad,
    },
    findings: findings.map((f) => f.check),
    alerts_sent: sent,
    dry,
    ms: Date.now() - t0,
  });
}
