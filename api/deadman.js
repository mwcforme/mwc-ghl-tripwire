/**
 * Dead-man's switch for the GHL tripwire.
 *
 * The 5-min tripwire writes one ops_alert_log row per run (ghl:state:run:<epoch-bucket>).
 * This hourly cron checks: if the newest run-marker is older than 20 minutes,
 * the 5-min cron is NOT FIRING (missed >=4 ticks) — page techops.
 *
 * This closes the "unwitnessed silence" failure class: a dead tripwire looks
 * exactly like a healthy estate unless something watches the watcher.
 */
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ALERT_TO = process.env.ALERT_TO || "techops@menswellnesscenters.com";
const ALERT_FROM = process.env.ALERT_FROM || "v-islam.hetta@mwcforme.com";
const STALE_MIN = 20;

const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36";

async function jfetch(url, opts = {}, timeoutMs = 15000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: ctl.signal });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch { body = text; }
    return { status: res.status, ok: res.status >= 200 && res.status < 300, body, text };
  } finally { clearTimeout(t); }
}

async function gmailToken() {
  const body = new URLSearchParams({
    refresh_token: process.env.GOOGLE_OAUTH_REFRESH_TOKEN,
    client_id: process.env.GOOGLE_OAUTH_CLIENT_ID,
    client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
    grant_type: "refresh_token",
  }).toString();
  const r = await jfetch(process.env.GOOGLE_OAUTH_TOKEN_URI, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  return r.ok ? r.body.access_token : null;
}

async function email(subject, text) {
  const token = await gmailToken();
  if (!token) { console.error(JSON.stringify({ event: "gmail_token_failed" })); return false; }
  const boundary = "mwc" + Date.now();
  const raw = [
    `To: ${ALERT_TO}`,
    `From: ${ALERT_FROM}`,
    `Content-Type: multipart/alternative; boundary=${boundary}`,
    `Subject: ${subject}`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=UTF-8",
    "",
    text,
    "",
    `--${boundary}--`,
    "",
  ].join("\r\n");
  const r = await jfetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify({ raw: Buffer.from(raw).toString("base64url") }),
  });
  console.log(JSON.stringify({ event: r.ok ? "dms_email_sent" : "dms_email_failed", status: r.status }));
  return r.ok;
}

export default async function handler(req, res) {
  const secret = process.env.CRON_SECRET;
  if (secret) {
    const provided =
      new URL(req.url, "http://x").searchParams.get("secret") ||
      req.headers.authorization;
    if (provided !== `Bearer ${secret}` && provided !== secret) {
      res.statusCode = 401;
      return res.json({ error: "unauthorized" });
    }
  }
  const headers = {
    apikey: SUPABASE_KEY,
    Authorization: "Bearer " + SUPABASE_KEY,
    "User-Agent": UA,
  };
  // newest tripwire run marker
  const r = await jfetch(
    `${SUPABASE_URL}/rest/v1/ops_alert_log?select=alert_key,created_at&alert_key=like.ghl:state:run:*&order=created_at.desc&limit=1`,
    { headers }
  );
  const newest = Array.isArray(r.body) && r.body[0];
  const staleMin = newest ? (Date.now() - Date.parse(newest.created_at)) / 60000 : null;
  const isStale = !newest || staleMin > STALE_MIN;
  let emailOk = null;
  if (isStale) {
    emailOk = await email(
      "[MWC] GHL tripwire DEAD-MAN alarm — 5-min cron not firing",
      [
        `The GHL tripwire's 5-minute cron has not written a run marker in ${
          newest ? staleMin.toFixed(0) + " minutes" : "EVER"
        } (threshold ${STALE_MIN} min).`,
        "",
        "What this means: GHL error monitoring is OFF right now — errors will not be detected until the cron resumes.",
        newest ? `Last run marker: ${newest.created_at} (${newest.alert_key})` : "No run markers exist at all.",
        "",
        "Check: Vercel project mwc-ghl-tripwire -> crons (/api/tripwire */5) and its function logs. This hourly dead-man check will keep paging every hour until the tripwire resumes.",
      ].join("\n")
    );
  }
  res.statusCode = 200;
  res.json({
    ok: !isStale,
    newest_run_marker: newest?.created_at ?? null,
    stale_min: staleMin == null ? null : Number(staleMin.toFixed(1)),
    stale: isStale,
    paged: isStale, // condition detected (email attempt made); email_ok separate
    email_ok: emailOk,
  });
}
