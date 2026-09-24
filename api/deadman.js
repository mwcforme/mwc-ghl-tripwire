/**
 * Dead-man's switch for the GHL tripwire.
 *
 * The 5-min tripwire writes one ops_alert_log row per run
 * (ghl:state:run:<epoch-bucket>). This hourly cron checks: if the newest
 * run-marker is older than 20 minutes, the 5-min cron is NOT FIRING
 * (missed >=4 ticks) — page techops.
 *
 * This closes the "unwitnessed silence" failure class: a dead tripwire looks
 * exactly like a healthy estate unless something watches the watcher.
 *
 * Auth: FAIL-CLOSED, header-only bearer (same contract as api/tripwire.js).
 * A probe crash is LOUD: logged, emailed if possible, and a 500 so the
 * failure is visible in Vercel cron logs — the deadman must never die
 * silently, because nothing watches it.
 */
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ALERT_TO = (process.env.ALERT_TO ||
  "techops@menswellnesscenters.com,v-ihetta@menswellnesscenters.com,v-islam.hetta@mwcforme.com")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const ALERT_FROM = process.env.ALERT_FROM || "v-islam.hetta@mwcforme.com";
const STALE_MIN = 20;

/** Dead-man scope: each entry is a 5-min cron whose run markers
 *  (ops_alert_log ghl[:meta]:state:run:*) must stay fresh. The 2026-09-24
 *  extension adds the META workflow guard to the original tripwire watch.
 *  DEADMAN_WATCHES (JSON [{name,prefix,route}]) is a battery seam: it lets
 *  the local battery point the dead-man at battery-owned marker prefixes
 *  so partial-stale cases are deterministic (the deployed 5-min crons
 *  otherwise keep writing fresh markers mid-test). */
function parseWatches() {
  if (process.env.DEADMAN_WATCHES) {
    try {
      const v = JSON.parse(process.env.DEADMAN_WATCHES);
      if (Array.isArray(v) && v.every((x) => x && x.name && x.prefix)) return v;
    } catch {
      /* fall through to defaults */
    }
  }
  return [
    { name: "GHL tripwire", prefix: "ghl:state:run:", route: "/api/tripwire" },
    { name: "META workflow guard", prefix: "ghl:meta:state:run:", route: "/api/meta-workflows" },
  ];
}
const WATCHES = parseWatches();

const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36";

async function jfetch(url, opts = {}, timeoutMs = 15000) {
  const attempt = async () => {
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
    } catch (e) {
      return { status: 0, ok: false, body: null, text: String(e?.message ?? e).slice(0, 160) };
    } finally {
      clearTimeout(t);
    }
  };
  const first = await attempt();
  const method = (opts.method || "GET").toUpperCase();
  const retryable =
    method === "GET" && !first.ok && (first.status === 0 || first.status === 429 || first.status >= 500);
  let out = first;
  if (retryable) {
    await new Promise((r) => setTimeout(r, 500));
    out = await attempt();
    if (out.status !== 0) out = { ...out, retried: true };
  }
  // Transport-dead after retry must THROW, never return ok:false — the
  // caller's guard() turns a throw into a FAIL leg (blindness counter);
  // swallowing it here would read a dead dependency as a healthy leg
  // (soft-blind: probes "ok" while nothing can be persisted or paged).
  if (out.status === 0) throw new Error(`jfetch transport: ${out.text}`);
  return out;
}

/** Pure staleness decision (exported for the battery). newestMs == null
 *  (no markers at all) counts as STALE: a tripwire that has never written
 *  a marker is indistinguishable from one that stopped. */
export function computeStale(newestMs, nowMs = Date.now()) {
  if (newestMs == null) return { stale: true, staleMin: null };
  const staleMin = (nowMs - newestMs) / 60000;
  return { stale: staleMin > STALE_MIN, staleMin };
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

/** RFC 2047-encode a header value containing non-ASCII (Gmail mangles bare
 *  UTF-8 header bytes — same trap as the tripwire's sendFindingEmail). */
function mimeHeader(v) {
  const s = String(v);
  return /^[\x20-\x7e]*$/.test(s)
    ? s
    : "=?UTF-8?B?" + Buffer.from(s, "utf8").toString("base64") + "?=";
}

async function email(subject, text) {
  const token = await gmailToken();
  if (!token) { console.error(JSON.stringify({ event: "gmail_token_failed", subject })); return false; }
  const boundary = "mwc" + Date.now();
  const raw = [
    `To: ${ALERT_TO.join(", ")}`,
    `From: ${ALERT_FROM}`,
    `Content-Type: multipart/alternative; boundary=${boundary}`,
    `Subject: ${mimeHeader(subject)}`,
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
  console.log(JSON.stringify({ event: r.ok ? "dms_email_sent" : "dms_email_failed", subject, status: r.status }));
  return r.ok;
}

export default async function handler(req, res) {
  // Auth: fail-closed, header-only bearer. No query-param secret form.
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    console.error(JSON.stringify({ event: "config_missing", need: "CRON_SECRET" }));
    res.statusCode = 500;
    return res.json({ error: "cron secret not configured" });
  }
  if ((req.headers.authorization || "") !== `Bearer ${secret}`) {
    res.statusCode = 401;
    return res.json({ error: "unauthorized" });
  }
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.error(JSON.stringify({ event: "config_missing", need: "SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY" }));
    res.statusCode = 500;
    return res.json({ error: "supabase env missing" });
  }

  const headers = {
    apikey: SUPABASE_KEY,
    Authorization: "Bearer " + SUPABASE_KEY,
    "User-Agent": UA,
  };

  // newest run marker per watched 5-min cron — a probe crash must be LOUD,
  // not a silent 200
  const watches = [];
  try {
    for (const w of WATCHES) {
      const r = await jfetch(
        `${SUPABASE_URL}/rest/v1/ops_alert_log?select=alert_key,created_at&alert_key=like.${encodeURIComponent(w.prefix)}*&order=created_at.desc&limit=1`,
        { headers }
      );
      if (!r.ok || !Array.isArray(r.body)) throw new Error(`marker probe HTTP ${r.status} (${w.name})`);
      watches.push({ ...w, newest: r.body[0] ?? null });
    }
  } catch (e) {
    const err = String(e?.message ?? e).slice(0, 160);
    console.error(JSON.stringify({ event: "deadman_probe_failed", err }));
    let emailOk = null;
    try {
      emailOk = await email(
        "[MWC] GHL deadman PROBE ERROR — cannot read run markers",
        [
          "The dead-man's switch itself failed to read the watched run markers.",
          `Error: ${err}`,
          "",
          "What this means: liveness verification is degraded — check Vercel project mwc-ghl-tripwire (Supabase access, env) now.",
        ].join("\n")
      );
    } catch (e2) {
      console.error(JSON.stringify({ event: "deadman_probe_email_failed", err: String(e2?.message ?? e2).slice(0, 160) }));
    }
    res.statusCode = 500;
    return res.json({ error: "marker probe failed", err, email_ok: emailOk });
  }

  const staleWatches = [];
  const perWatch = [];
  for (const w of watches) {
    const { stale, staleMin } = computeStale(w.newest ? Date.parse(w.newest.created_at) : null);
    perWatch.push({
      name: w.name,
      route: w.route,
      newest_run_marker: w.newest?.created_at ?? null,
      stale_min: staleMin == null ? null : Number(staleMin.toFixed(1)),
      stale,
    });
    if (stale) staleWatches.push({ ...w, staleMin, newest: w.newest });
  }

  let emailOk = null;
  if (staleWatches.length) {
    const lines = [
      staleWatches.length === WATCHES.length
        ? `ALL ${WATCHES.length} watched 5-min crons have stopped writing run markers`
        : `${staleWatches.length} of ${WATCHES.length} watched 5-min crons stopped writing run markers: ${staleWatches.map((w) => w.name).join(", ")}`,
    ];
    for (const w of staleWatches) {
      lines.push(
        `— ${w.name} (${w.route}): last marker ${
          w.newest ? w.newest.created_at + " (" + w.staleMin.toFixed(0) + " min ago)" : "NEVER"
        } (threshold ${STALE_MIN} min)`
      );
    }
    lines.push(
      "",
      "What this means: GHL monitoring is OFF for the stale watcher(s) right now — errors / workflow changes will not be detected until the cron resumes.",
      "",
      "Check: Vercel project mwc-ghl-tripwire -> crons (Settings -> Cron Jobs) and the function logs for the stale route(s). This hourly dead-man check keeps paging every hour until each resumes."
    );
    try {
      emailOk = await email(
        `[MWC] GHL DEAD-MAN alarm — ${staleWatches.map((w) => w.name).join(" + ")} not firing`,
        lines.join("\n")
      );
    } catch (e) {
      console.error(JSON.stringify({ event: "dms_email_exception", err: String(e?.message ?? e).slice(0, 160) }));
      emailOk = false;
    }
  }
  res.statusCode = 200;
  res.json({
    ok: staleWatches.length === 0,
    watches: perWatch,
    stale: staleWatches.map((w) => w.name),
    paged: staleWatches.length > 0, // condition detected (email attempt made); email_ok separate
    email_ok: emailOk,
  });
}
