/**
 * META workflow guard — dedicated watch on the 3 new Meta lead-handling
 * workflows (shipped 2026-09-23/24, all published):
 *   Speed to Lead – Meta Sheet Leads       5158c291-8842-4763-9992-399015f93d2d
 *   Speed to Lead – SLA Escalation (Meta)  29587aae-54fd-47d2-bfe7-ffc33e16839a
 *   02. NON BOOKED META                    ce21e5c0-b893-4573-909b-1d9e8b73937a
 *
 * Why a dedicated route: the main tripwire's estate signal pages on
 * published-COUNT deltas for the whole location; this route ASSERTS these
 * three business-critical workflows are present + published at a known
 * version — independent of estate baselines — and adds edit awareness.
 * Overlap with the estate signal is deliberate (delta detector + assert).
 *
 * Signals (live-verified 2026-09-24: per-workflow detail/stats routes 404,
 * the executions surface returns [] — the public workflows LIST is the only
 * per-workflow signal surface GHL exposes; do not re-hunt):
 *   M1 missing      watched ID absent from the live list     -> pages (deleted)
 *   M2 unpublished  status != published                      -> pages (6h re-page while it persists)
 *   M3 version      version != stored baseline               -> pages once per 6h (edit awareness)
 *   A  blindness    list probe fails 2+ consecutive runs     -> pages (1/h cap)
 *
 * Statelessness: same contract as api/tripwire.js — runtime state reset at
 * the top of every invocation, ALL durable state in ops_alert_log:
 *   ghl:meta:state:run:<bucket>   one marker per non-dry run (deadman watches)
 *   ghl:meta:state:ver:<wf-id>    baseline {"version":N,"status":"published"}
 *   ghl:meta:state:leg_metalist   consecutive probe-failure counter
 *   ghl:meta:alert:<check>:<fp>   insert-first dedupe locks
 *
 * Auth: FAIL-CLOSED, header-only bearer (no query-param form).
 * dry=1 evaluates and reports WITHOUT sending email or writing ANYTHING.
 * Delivery: same Gmail OAuth leg as the tripwire; a failed send surfaces in
 * delivery_failed[] and releases the dedupe lock so the next run retries.
 */

const LOC = process.env.GHL_LOCATION_ID || "Ghstz8eIsHWLeXek47dk";
const PUBLIC = "https://services.leadconnectorhq.com";
const UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36";
/** Route-scoped recipients: META_ALERT_TO (this guard only) overrides the
 *  project-wide ALERT_TO — techops stays on tripwire/deadman pages, OFF the
 *  Meta lead-SLA pages (user request 2026-09-25; deployed META_ALERT_TO =
 *  v-ihetta + v-islam). */
const ALERT_TO = (process.env.META_ALERT_TO || process.env.ALERT_TO ||
  "techops@menswellnesscenters.com,v-ihetta@menswellnesscenters.com,v-islam.hetta@mwcforme.com")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const ALERT_FROM = process.env.ALERT_FROM || "v-islam.hetta@mwcforme.com";

/** The watched set — THE config of this guard. IDs are stable GHL identifiers
 *  (names can be renamed by admins; alerts use the live name, falling back
 *  to this label when the workflow is absent). */
const WATCH = [
  { id: "5158c291-8842-4763-9992-399015f93d2d", label: "Speed to Lead – Meta Sheet Leads" },
  { id: "29587aae-54fd-47d2-bfe7-ffc33e16839a", label: "Speed to Lead – SLA Escalation (Meta)" },
  { id: "ce21e5c0-b893-4573-909b-1d9e8b73937a", label: "02. NON BOOKED META" },
];

// thresholds (same conventions as api/tripwire.js)
const T = {
  LEG_FAIL_ALERT_MIN: 60, // max one blindness email per hour
  REPEAT_CAP_H: 6, // persisting condition re-pages at most every 6h
};

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const GHL_PIT = process.env.GHL_API_KEY || "";

/** OAuth quartet read at CALL time, never at module scope — so a battery or
 *  local run that deletes the env BEFORE import disables the email leg. */
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

/** DRY is invocation-scoped: reset at the top of every handler run so warm
 *  containers never leak a previous tick's mode into this one. */
let DRY = false;

/** Insert-first dedupe lock (unique alert_key) — same contract as the
 *  tripwire: fresh insert -> send; duplicate older than repeatCapH ->
 *  delete + re-insert (re-arm); anything else -> stay quiet. No-op in dry. */
async function claimAlert(check, fp, severity, repeatCapH = T.REPEAT_CAP_H) {
  if (DRY) return true;
  const key = `ghl:meta:alert:${check}:${fp}`;
  const ins = await sb().post("ops_alert_log", {
    alert_key: key,
    check_id: `ghl_meta_${check}`,
    severity,
  });
  if (ins.status === 201 || ins.ok) return true;
  const st = await sb().get(
    `ops_alert_log?select=created_at&alert_key=eq.${encodeURIComponent(key)}&limit=1`
  );
  const at = st.ok && Array.isArray(st.body) && st.body[0]?.created_at ? Date.parse(st.body[0].created_at) : null;
  if (at != null && Date.now() - at > repeatCapH * 3.6e6) {
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
      check_id: `ghl_meta_${check}`,
      severity,
    });
    return retry.status === 201 || retry.ok;
  }
  return false;
}

/** Release a claimed lock after a FAILED delivery so the next run retries. */
async function releaseAlert(check, fp) {
  const key = `ghl:meta:alert:${check}:${fp}`;
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

/** State upsert via ops_alert_log rows (value in severity). No-op in dry. */
async function setState(key, value) {
  if (DRY) return true;
  const ins = await sb().post("ops_alert_log", {
    alert_key: key,
    check_id: "ghl_meta_state",
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

/** RFC 2047-encode a header value containing non-ASCII. Gmail's raw-send
 *  layer mangles bare UTF-8 header bytes (verified live 2026-09-24: the
 *  metaver alert's en-dash/arrow subject arrived double-encoded while the
 *  charset-declared body stayed clean). ASCII-only values pass through. */
function mimeHeader(v) {
  const s = String(v);
  return /^[\x20-\x7e]*$/.test(s)
    ? s
    : "=?UTF-8?B?" + Buffer.from(s, "utf8").toString("base64") + "?=";
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
    'Content-Type: multipart/alternative; boundary="mwcmeta"',
    `Subject: ${mimeHeader(f.subject)}`,
    "",
    "--mwcmeta",
    'Content-Type: text/html; charset=UTF-8',
    "",
    buildHtml(f),
    "",
    "--mwcmeta",
    'Content-Type: text/plain; charset=UTF-8',
    "",
    f.lines.join("\n"),
    "",
    "--mwcmeta--",
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

/** M/D/YYYY from an ISO timestamp (UTC) — the "when" field of who/when
 *  attribution in alert lines (user request 2026-09-30). */
function fmtWhen(iso) {
  const d = iso ? new Date(iso) : null;
  if (!d || Number.isNaN(d.getTime())) return "unknown";
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()}`;
}

let findings = []; // RESET at the start of every invocation (warm containers)

function page(check, fp, subject, lines) {
  findings.push({ check, fp, subject, lines });
}

/** Pure decision core (exported for the battery — no I/O): given the watched
 *  defs, the live workflow list, and stored baselines, return per-workflow
 *  verdicts + the page-worthy findings.
 *  Baseline semantics: no baseline (first run) = BOOTSTRAP — record, don't
 *  page. A version change against an existing baseline = M3 edit alert. */
export function evaluateWatch(watch, liveWfs, baselines = {}) {
  const byId = new Map((liveWfs ?? []).map((w) => [w.id, w]));
  return (watch ?? []).map((def) => {
    const live = byId.get(def.id) ?? null;
    // Baseline must be an object with a finite numeric version — anything
    // else (null, string, array, object without version, NaN) is corrupt
    // state and degrades to BOOTSTRAP (record, don't page). The battery
    // caught the pre-fix behavior: a string baseline produced a version
    // finding with from=undefined.
    let base = baselines[def.id] ?? null;
    {
      const bv = Number(base?.version);
      base =
        base && typeof base === "object" && !Array.isArray(base) && Number.isFinite(bv)
          ? { ...base, version: bv }
          : null;
    }
    const fs = [];
    if (!live) {
      fs.push({ kind: "missing", fp: `missing:${def.id}`, severity: "alert" });
    } else {
      if (live.status !== "published") {
        fs.push({
          kind: "unpublished",
          fp: `unpub:${def.id}:${live.status}`,
          severity: "alert",
          status: live.status,
        });
      }
      if (base && Number(live.version) !== Number(base.version)) {
        fs.push({
          kind: "version",
          fp: `ver:${def.id}`,
          severity: "warn",
          from: base.version,
          to: live.version,
        });
      }
    }
    return {
      id: def.id,
      name: live?.name ?? def.label,
      label: def.label,
      present: !!live,
      status: live?.status ?? "absent",
      version: live?.version ?? null,
      updatedAt: live?.updatedAt ?? null,
      findings: fs,
    };
  });
}

/** Subject + 4-part lines (what / impact / evidence / check) per finding kind. */
function describe(v, f, ctx) {
  switch (f.kind) {
    case "missing":
      return {
        check: "metamissing",
        subject: `[GHL] META workflow DELETED: ${v.name}`,
        lines: [
          `Workflow "${v.name}" (${v.id}) is absent from the location's workflow list — deleted (or its ID changed).`,
          "Impact: Meta lead handling on this path is OFF — leads entering this funnel get no automated follow-up.",
          `Evidence: public /workflows list for location ${LOC} has no workflow with this ID (${ctx.published} published of ${ctx.total} total).`,
          `Check: GHL Automation → Workflows → restore "${v.label}" from version history or rebuild (owner: @mwc-ghl-qa).`,
        ],
      };
    case "unpublished":
      return {
        check: "metaunpub",
        subject: `[GHL] META workflow NOT PUBLISHED: ${v.name} — status "${f.status}"`,
        lines: [
          `Workflow "${v.name}" is in status "${f.status}" — it is NOT running (paused or reverted to draft). Last touched ${fmtWhen(v.updatedAt)} (by unknown — audit-log-scoped token not configured).`,
          "Impact: Meta leads on this path receive no automated speed-to-lead / non-booked follow-up until re-published.",
          `Evidence: live status from the public /workflows list (id ${v.id}); expected "published". Re-pages every 6h while it persists.`,
          `Check: GHL Automation → Workflows → "${v.name}" → re-publish if unintentional (owner: @mwc-ghl-qa).`,
        ],
      };
    case "version":
      return {
        check: "metaver",
        subject: `[GHL] META workflow edited: ${v.name} v${f.from} → v${f.to}`,
        lines: [
          `Workflow "${v.name}" was saved to version ${f.to} (baseline was v${f.from}) — edited by unknown on ${fmtWhen(v.updatedAt)} (who is unavailable until the audit-log-scoped GHL token is configured).`,
          "Impact: someone changed the automation — verify the edit didn't break the Meta lead path (execution errors also trip the main tripwire within 5 min).",
          `Evidence: version + updatedAt fields on the public /workflows list (id ${v.id}); further edits within 6h are absorbed into this notice.`,
          `Check: GHL Automation → Workflows → "${v.name}" → version history (owner: @mwc-ghl-qa).`,
        ],
      };
    default:
      return null;
  }
}

async function checkMetaWorkflows() {
  // Supabase health probe FIRST: a Supabase that answers with HTTP errors
  // (auth rotated, 500s) must read as a BLIND leg, not a silent ok — without
  // this, getState() returns null both for "key absent" and "request failed",
  // and the guard would report ok while persisting nothing (no baselines,
  // no dedupe locks, no run markers — soft-blind).
  const health = await sb().get("ops_alert_log?select=alert_key&limit=1");
  if (!health.ok) return { ok: false, error: "supabase_unreachable:" + health.status };

  // BARE params — the public /workflows route rejects limit (422)
  const r = await ghlPublic(`/workflows/?locationId=${LOC}`);
  if (!r.ok || !Array.isArray(r.body?.workflows)) return { ok: false };
  const wfs = r.body.workflows;
  const ctx = {
    published: wfs.filter((w) => w.status === "published").length,
    total: wfs.length,
  };

  const baselines = {};
  for (const def of WATCH) {
    const st = await getState(`ghl:meta:state:ver:${def.id}`);
    if (st) {
      try {
        const b = JSON.parse(st.value);
        if (b && typeof b.version !== "undefined") baselines[def.id] = b;
      } catch {
        /* unreadable baseline -> treat as bootstrap */
      }
    }
  }

  const verdicts = evaluateWatch(WATCH, wfs, baselines);
  for (const v of verdicts) {
    for (const f of v.findings) {
      const d = describe(v, f, ctx);
      if (d && (await claimAlert(d.check, f.fp, f.severity))) {
        page(d.check, f.fp, d.subject, d.lines);
      }
    }
    // persist baseline AFTER the alert decision so a version drift fires once
    if (v.present) {
      await setState(
        `ghl:meta:state:ver:${v.id}`,
        JSON.stringify({ version: v.version, status: v.status })
      );
    }
  }
  return { ok: true, verdicts, published: ctx.published, total: ctx.total };
}

/* --------------------------------------------------------------- blindness */

const LEGS = ["metalist"];

async function checkBlindness(results) {
  for (const leg of LEGS) {
    const ok = results[leg]?.ok;
    const key = `ghl:meta:state:leg_${leg}`;
    if (ok) {
      await setState(key, "0");
      continue;
    }
    const st = await getState(key);
    const fails = st ? parseInt(st.value, 10) || 0 : 0;
    const next = fails + 1;
    await setState(key, String(next));
    if (next >= 2) {
      // blind legs re-page at most once per hour
      if (await claimAlert("blind", leg, "warn", T.LEG_FAIL_ALERT_MIN / 60)) {
        page("blind", leg, `[GHL meta guard] Signal BLIND: '${leg}' probe failing ${next} runs`, [
          `The '${leg}' probe has failed ${next} consecutive runs — the META workflow guard is unwatched until it recovers.`,
          "Impact: unpublish/delete/edit on the 3 Meta lead workflows goes undetected while blind.",
          "Evidence: probe status recorded per run in ops_alert_log (ghl:meta:state:leg_metalist).",
          "Check: GHL API key (PIT) validity + services.leadconnectorhq.com reachability (owner: @mwc-ghl-qa).",
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
    <p style="margin:14px 0 0;font-size:11px;color:#6B7089;">MWC META workflow guard · every 5 min · ${new Date().toISOString()}</p>
  </div>
</div>`;
}

/** Guard the single check so a crash reads as a BLIND leg, not a dead run. */
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
  results.metalist = await guard("metalist", checkMetaWorkflows);
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
        // Delivery failed: surface it AND release the lock so the next run retries.
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

  // Run marker for the dead-man's switch (ghl:meta:state:run:*): one row per
  // 5-min bucket; insert-first dedupes retries. dry mode writes nothing.
  if (!dry) {
    try {
      await setState(`ghl:meta:state:run:${Math.floor(Date.now() / 300000)}`, "run");
    } catch (e) {
      log({ event: "marker_write_failed", err: String(e?.message ?? e).slice(0, 160) });
    }
  }

  const verdicts = results.metalist?.verdicts ?? [];
  res.statusCode = 200;
  res.json({
    ok: findings.length === 0,
    legs: Object.fromEntries(LEGS.map((l) => [l, results[l]?.ok ? "ok" : "FAIL"])),
    observed: {
      workflows: verdicts.map((v) => ({
        id: v.id,
        name: v.name,
        present: v.present,
        status: v.status,
        version: v.version,
        updatedAt: v.updatedAt,
      })),
      published_total: results.metalist?.published,
      total: results.metalist?.total,
    },
    findings: findings.map((f) => f.check),
    alerts_sent: sent,
    delivery_failed: deliveryFailed,
    dry,
    ms: Date.now() - t0,
  });
}

/** Test seams for meta-battery.mjs (named exports — ignored by Vercel's
 *  handler resolution, which only consumes the default export). */
export const _internals = {
  claimAlert,
  releaseAlert,
  setState,
  getState,
  setDry: (v) => (DRY = v),
};
