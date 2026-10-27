/**
 * Offline battery for the capture-liveness rule (no env, no network, no email).
 *
 * Guards the 2026-10-27 false alarm: the check paged "Booking capture pipeline
 * DOWN — leads lost" at 37.9h while portal_booking + track_generate_lead were
 * both <2h fresh and 21 bookings landed. Root cause was the rule, not the data:
 * a single max() across three events, on wall-clock hours, where one of the
 * three is a sparse per-booking label another writer can absorb.
 *
 * Run: node battery-capture.mjs
 */
const { _internals } = await import("./api/tripwire.js");
const { captureVerdict, bizMinutesBetween, bizHoursNow, THRESHOLDS } = _internals;

let pass = 0;
let fail = 0;
function check(name, cond, detail = "") {
  if (cond) { pass++; console.log("PASS " + name); }
  else { fail++; console.log("FAIL " + name + " :: " + detail); }
}
const ET = (iso) => new Date(iso).getTime();
const names = (rows) => rows.map((r) => r.event).sort().join(",");
const obs = (event, newest, n7d) => ({ event, newest, n7d });

// ---------------------------------------------------------------- thresholds
check("threshold: one business day of silence (10 bh)", THRESHOLDS.CAPTURE_STALE_BH === 10);
check("threshold: liveness set excludes the sparse label",
  _internals.CAPTURE_LIVENESS.join(",") === "portal_booking,track_generate_lead",
  _internals.CAPTURE_LIVENESS.join(","));

// ------------------------------------------------------- the real incident
// Tue 2026-10-27 12:27Z (08:27 ET), the shape that paged at 08:00 ET.
{
  const now = ET("2026-10-27T12:27:00Z");
  const v = captureVerdict([
    obs("portal_booking", "2026-10-27T11:19:14Z", 5),          // 1.1h
    obs("track_generate_lead", "2026-10-27T12:00:25Z", 5),     // 0.4h
    obs("track_booking_complete", "2026-10-25T22:05:46Z", 1),  // 37.9h  <-- the trigger
  ], now);
  check("incident fixture: 37.9h on the sparse label does NOT page", v.stale.length === 0, names(v.stale));
  check("incident fixture: sparse label still reported as coverage",
    v.coverage.length === 1 && v.coverage[0].event === "track_booking_complete",
    JSON.stringify(v.coverage));
}

// ------------------------------------------------- genuine outage still pages
// Tue 12:27 ET (16:27Z) and the last portal_booking row Mon 10:00 ET -> ~12.5 bh.
{
  const now = ET("2026-10-27T16:27:00Z");
  const v = captureVerdict([
    obs("portal_booking", "2026-10-26T14:00:00Z", 5),
    obs("track_generate_lead", "2026-10-27T16:00:25Z", 5),
    obs("track_booking_complete", "2026-10-25T22:05:46Z", 1),
  ], now);
  check("outage fixture: stale portal_booking pages", v.stale.length === 1 && v.stale[0].event === "portal_booking", names(v.stale));
  check("outage fixture: business-hours age is 10-14 (not wall-clock 22)",
    v.stale[0].bh > 10 && v.stale[0].bh < 14, String(v.stale[0]?.bh));
  check("outage fixture: wall-clock age reported separately",
    v.stale[0].wallH > 20, String(v.stale[0]?.wallH));
}

// Both liveness events dark = one alert naming both, stable fingerprint order.
{
  const now = ET("2026-10-27T12:27:00Z");
  const v = captureVerdict([
    obs("portal_booking", "2026-10-25T14:00:00Z", 5),
    obs("track_generate_lead", "2026-10-25T14:00:00Z", 5),
    obs("track_booking_complete", "2026-10-27T11:00:00Z", 1),
  ], now);
  check("total outage: both liveness events named", names(v.stale) === "portal_booking,track_generate_lead", names(v.stale));
}

// ------------------------------------------------------ weekend cannot page
// Mon 08:30 ET, last capture Fri 17:00 ET: 1.5 business hours, 63.5 wall hours.
{
  const now = ET("2026-10-26T12:30:00Z");
  const v = captureVerdict([
    obs("portal_booking", "2026-10-23T21:00:00Z", 5),
    obs("track_generate_lead", "2026-10-23T21:00:00Z", 5),
    obs("track_booking_complete", "2026-10-23T21:00:00Z", 1),
  ], now);
  check("weekend gap: 63.5h wall but 1.5 bh does NOT page", v.stale.length === 0, names(v.stale));
  check("weekend gap: wall age > 60h (sanity)", v.coverage[0] && v.coverage[0].wallH > 60, JSON.stringify(v.coverage[0]));
}

// ------------------------------------------------- quiet-by-volume can't page
{
  const now = ET("2026-10-27T12:27:00Z");
  const v = captureVerdict([
    obs("portal_booking", "2026-10-27T11:19:14Z", 5),
    obs("track_generate_lead", "2026-10-17T11:00:00Z", 0), // retired event, no volume
  ], now);
  check("volume guard: non-live event cannot page", v.stale.length === 0, names(v.stale));
}

// ---------------------------------------------------------------- unit math
check("bh math: Fri 17:00 -> Mon 08:30 ET = 1.5 bh",
  Math.abs(bizMinutesBetween(ET("2026-10-23T21:00:00Z"), ET("2026-10-26T12:30:00Z")) / 60 - 1.5) < 0.3,
  String(bizMinutesBetween(ET("2026-10-23T21:00:00Z"), ET("2026-10-26T12:30:00Z")) / 60));
check("bh math: one full ET business day = 10 bh",
  Math.abs(bizMinutesBetween(ET("2026-10-26T12:00:00Z"), ET("2026-10-27T12:00:00Z")) / 60 - 10) < 0.3,
  String(bizMinutesBetween(ET("2026-10-26T12:00:00Z"), ET("2026-10-27T12:00:00Z")) / 60));
check("bh math: null newest -> Infinity", bizMinutesBetween(null, Date.now()) === Infinity);
check("gate: Saturday is not a business day", bizHoursNow(new Date("2026-10-24T15:00:00Z")) === false);
check("gate: Tuesday 08:30 ET is a business day", bizHoursNow(new Date("2026-10-27T12:30:00Z")) === true);

console.log(`\n${fail === 0 ? "ALL PASS" : "FAILURES"} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
