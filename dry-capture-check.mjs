/**
 * In-process dry run of the DEPLOYED api/tripwire.js against prod Supabase.
 * dry=1 => no email, no alert locks, no state mutation, no run marker.
 * Prints only the capture leg's observations.
 */
import { readFileSync } from "node:fs";
import os from "node:os";

const envPath = os.homedir() + "/.config/mwc-admin/.env.local";
for (const line of readFileSync(envPath, "utf8").split("\n")) {
  const m = line.match(/^([A-Za-z0-9_]+)=(.*)$/);
  if (m) process.env[m[1]] = m[2].replace(/^"|"$/g, "");
}
delete process.env.GOOGLE_OAUTH_REFRESH_TOKEN; // keep the email leg off
process.env.CRON_SECRET = process.env.CRON_SECRET || "local-dry-run";

const { default: handler } = await import("./api/tripwire.js");
const res = { statusCode: 0, body: null, json(x) { this.body = x; } };
await handler(
  { method: "GET", url: "/api/tripwire?dry=1", headers: { authorization: "Bearer " + process.env.CRON_SECRET } },
  res
);
const b = res.body || {};
console.log("status", res.statusCode, "dry", b.dry);
console.log("legs", JSON.stringify(b.legs));
console.log("capture:", JSON.stringify(b.observed?.capture_stale));
console.log("coverage:", JSON.stringify(b.observed?.capture_coverage));
console.log("worstAgeH:", b.observed?.capture_worst_age_h, "findings:", JSON.stringify(b.findings));
