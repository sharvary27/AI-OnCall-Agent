import { describe, expect, it } from "vitest";
import {
  computeBaseline,
  detectAnomalies,
  diffAnomalies,
  isFailure,
  spikeThreshold,
  type CheckSample
} from "../src/detect";
import type { CheckDetails } from "../src/checks";

// ---------- helpers to build fake checks (newest first, like the Probe) ----------

let clock = 1_000_000;
function check(overrides: Partial<CheckSample> = {}): CheckSample {
  clock += 60_000;
  return { ts: clock, status: 200, latencyMs: 100, ok: true, error: null, details: null, ...overrides };
}
const ok = (latencyMs = 100) => check({ latencyMs });
const fail = (status = 503) => check({ status, ok: false, latencyMs: 50 });
const timeout = () => check({ status: null, ok: false, latencyMs: null, error: "timeout after 10000ms" });
const withDetails = (d: Partial<CheckDetails>, o: Partial<CheckSample> = {}) =>
  check({
    details: {
      dns: null,
      redirects: [],
      finalUrl: null,
      rateLimit: null,
      security: null,
      edge: null,
      blockedHint: null,
      ...d
    },
    ...o
  });
const types = (recent: CheckSample[]) => detectAnomalies(recent).map((a) => a.type);
const healthyHistory = (n: number, latency = 100) => Array.from({ length: n }, () => ok(latency));

describe("baseline", () => {
  it("uses only healthy checks for latency", () => {
    const b = computeBaseline([ok(100), ok(200), fail(), ok(300)]);
    expect(b.samples).toBe(3);
    expect(b.medianLatencyMs).toBe(200);
    expect(b.errorRatePct).toBe(25);
  });

  it("has no spike threshold until it has enough samples", () => {
    expect(spikeThreshold(computeBaseline(healthyHistory(4)))).toBeNull();
    expect(spikeThreshold(computeBaseline(healthyHistory(5)))).toBe(400); // max(3x100, 100+300)
  });

  it("uses 3x median when that is larger than median + 300ms", () => {
    expect(spikeThreshold(computeBaseline(healthyHistory(10, 500)))).toBe(1500);
  });
});

describe("down", () => {
  it("does not fire on a single failure (blip)", () => {
    expect(types([fail(), ...healthyHistory(5)])).not.toContain("down");
  });

  it("fires after 2 failures in a row", () => {
    const a = detectAnomalies([fail(), timeout(), ...healthyHistory(5)]);
    expect(a.map((x) => x.type)).toContain("down");
    expect(a.find((x) => x.type === "down")?.severity).toBe("critical");
  });

  it("does not count bot blocking or rate limiting as down", () => {
    const blocked = withDetails({ blockedHint: "HTTP 999" }, { status: 999, ok: false });
    const limited = check({ status: 429, ok: false });
    expect(isFailure(blocked)).toBe(false);
    expect(isFailure(limited)).toBe(false);
    expect(types([blocked, blocked])).not.toContain("down");
  });
});

describe("error_burst", () => {
  it("fires when 3 of the last 6 checks failed, without being down", () => {
    const recent = [ok(), fail(), ok(), fail(), ok(), fail()];
    expect(types(recent)).toEqual(["error_burst"]);
  });

  it("is replaced by down when the service is fully down", () => {
    expect(types([fail(), fail(), fail(), ok(), ok(), ok()])).toEqual(["down"]);
  });
});

describe("latency_spike", () => {
  it("fires when the 2 newest checks are both far above normal", () => {
    expect(types([ok(900), ok(800), ...healthyHistory(10)])).toContain("latency_spike");
  });

  it("ignores a single slow check", () => {
    expect(types([ok(900), ok(100), ...healthyHistory(10)])).not.toContain("latency_spike");
  });

  it("does not judge latency without enough history", () => {
    expect(types([ok(900), ok(900), ...healthyHistory(3)])).not.toContain("latency_spike");
  });

  it("does not let the spike itself raise the baseline", () => {
    // the two slow checks are excluded from the baseline they are compared to
    const a = detectAnomalies([ok(2000), ok(2000), ...healthyHistory(5)]);
    expect(a.find((x) => x.type === "latency_spike")?.message).toContain("normal ~100ms");
  });
});

describe("dns, rate limits, blocking", () => {
  it("flags NXDOMAIN as a critical DNS failure", () => {
    const c = withDetails(
      { dns: { resolver: "1.1.1.1", status: "NXDOMAIN", ms: 12, a: [], aaaa: [], cname: [], error: null } },
      { status: null, ok: false, error: "domain does not exist (NXDOMAIN)" }
    );
    const a = detectAnomalies([c]);
    expect(a.find((x) => x.type === "dns_failure")?.severity).toBe("critical");
  });

  it("flags 429 as rate_limited with the retry time", () => {
    const c = withDetails(
      { rateLimit: { limit: null, remaining: null, resetSec: null, retryAfterSec: 30, rateLimited: true, headerStyle: null } },
      { status: 429, ok: false }
    );
    const a = detectAnomalies([c]);
    expect(a.map((x) => x.type)).toEqual(["rate_limited"]);
    expect(a[0].message).toContain("30s");
  });

  it("warns about low quota before the 429 happens", () => {
    const c = withDetails({
      rateLimit: { limit: 60, remaining: 5, resetSec: 600, retryAfterSec: null, rateLimited: false, headerStyle: "x-ratelimit-*" }
    });
    const a = detectAnomalies([c]);
    expect(a.map((x) => x.type)).toEqual(["quota_low"]);
    expect(a[0].message).toContain("5/60");
  });

  it("does not warn when plenty of quota is left", () => {
    const c = withDetails({
      rateLimit: { limit: 60, remaining: 50, resetSec: 600, retryAfterSec: null, rateLimited: false, headerStyle: "x-ratelimit-*" }
    });
    expect(types([c])).toEqual([]);
  });

  it("reports bot blocking as blocked, not down", () => {
    const c = withDetails({ blockedHint: "HTTP 999: blocked" }, { status: 999, ok: false });
    expect(types([c, c])).toEqual(["blocked"]);
  });
});

describe("open / resolve lifecycle", () => {
  it("opens once, stays open without new events, then resolves", () => {
    const down = detectAnomalies([fail(), fail()]);

    const first = diffAnomalies([], down, 1_000);
    expect(first.events.map((e) => `${e.kind}:${e.type}`)).toEqual(["opened:down"]);

    const second = diffAnomalies(first.open, down, 61_000);
    expect(second.events).toEqual([]); // still down: no duplicate alert
    expect(second.open[0].since).toBe(1_000); // keeps the original start time

    const third = diffAnomalies(second.open, [], 121_000);
    expect(third.events.map((e) => `${e.kind}:${e.type}`)).toEqual(["resolved:down"]);
    expect(third.events[0].message).toContain("resolved after 120s");
    expect(third.open).toEqual([]);
  });

  it("a healthy endpoint produces no alerts", () => {
    expect(detectAnomalies(healthyHistory(20))).toEqual([]);
    expect(detectAnomalies([])).toEqual([]);
  });
});