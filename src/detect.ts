// Anomaly detection for one endpoint. Pure functions with no Cloudflare APIs,
// so they can be unit-tested directly (see test/detect.test.ts).
//
// Input is the endpoint's recent checks, newest first. Output is the set of
// anomalies currently active. diffAnomalies() turns that into "opened" and
// "resolved" events, so one incident = one alert, not one alert per check.

import type { CheckDetails } from "../src/checks";

export type CheckSample = {
  ts: number;
  status: number | null;
  latencyMs: number | null;
  ok: boolean;
  error: string | null;
  details?: CheckDetails | null;
};

export type Baseline = {
  samples: number; // healthy checks the baseline is built from
  medianLatencyMs: number | null;
  p90LatencyMs: number | null;
  errorRatePct: number | null; // across all checks in the window
};

export type AnomalyType =
  | "down"
  | "error_burst"
  | "latency_spike"
  | "dns_failure"
  | "rate_limited"
  | "quota_low"
  | "blocked";

export type Severity = "critical" | "warning";

export type Anomaly = {
  type: AnomalyType;
  severity: Severity;
  message: string;
};

export type OpenAnomaly = Anomaly & { since: number };

export type AnomalyEvent = Anomaly & { kind: "opened" | "resolved"; ts: number };

// Tunables, in one place.
export const RULES = {
  downConsecutive: 2, // failures in a row before "down"
  burstWindow: 6, // look at the last N checks...
  burstFailures: 3, // ...and alert if at least this many failed
  spikeConsecutive: 2, // slow checks in a row before "latency_spike"
  spikeMultiplier: 3, // slow = more than 3x the median...
  spikeMinExtraMs: 300, // ...and at least 300ms above it
  minBaselineSamples: 5, // don't judge latency before we know "normal"
  quotaLowRatio: 0.1 // warn at 10% of quota left
};

// ---------- classification helpers ----------

function isRateLimited(c: CheckSample): boolean {
  return c.status === 429 || c.details?.rateLimit?.rateLimited === true;
}

function isBlocked(c: CheckSample): boolean {
  return Boolean(c.details?.blockedHint) && c.status !== 429;
}

// A real failure: the service itself is broken. Blocking and rate limiting
// are reported separately, so they don't count as the site being down.
export function isFailure(c: CheckSample): boolean {
  return !c.ok && !isBlocked(c) && !isRateLimited(c);
}

function describeFailure(c: CheckSample): string {
  if (c.error) return c.error;
  if (c.status !== null) return `HTTP ${c.status}`;
  return "unknown error";
}

// ---------- baseline ----------

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

export function computeBaseline(history: CheckSample[]): Baseline {
  const latencies = history
    .filter((c) => c.ok && c.latencyMs !== null)
    .map((c) => c.latencyMs as number)
    .sort((a, b) => a - b);

  const failures = history.filter(isFailure).length;

  return {
    samples: latencies.length,
    medianLatencyMs: latencies.length ? percentile(latencies, 50) : null,
    p90LatencyMs: latencies.length ? percentile(latencies, 90) : null,
    errorRatePct: history.length
      ? Math.round((failures / history.length) * 1000) / 10
      : null
  };
}

// ---------- detection ----------

export function spikeThreshold(baseline: Baseline): number | null {
  if (baseline.samples < RULES.minBaselineSamples || baseline.medianLatencyMs === null) {
    return null;
  }
  const m = baseline.medianLatencyMs;
  return Math.max(m * RULES.spikeMultiplier, m + RULES.spikeMinExtraMs);
}

// recent: newest first, recent[0] is the check that just ran.
export function detectAnomalies(recent: CheckSample[]): Anomaly[] {
  const anomalies: Anomaly[] = [];
  const latest = recent[0];
  if (!latest) return anomalies;

  // down: N failures in a row
  const head = recent.slice(0, RULES.downConsecutive);
  const isDown = head.length === RULES.downConsecutive && head.every(isFailure);
  if (isDown) {
    anomalies.push({
      type: "down",
      severity: "critical",
      message: `${RULES.downConsecutive} failed checks in a row (latest: ${describeFailure(latest)})`
    });
  }

  // error_burst: flaky but not fully down
  const window = recent.slice(0, RULES.burstWindow);
  const failuresInWindow = window.filter(isFailure).length;
  if (!isDown && failuresInWindow >= RULES.burstFailures) {
    anomalies.push({
      type: "error_burst",
      severity: "warning",
      message: `${failuresInWindow} of the last ${window.length} checks failed`
    });
  }

  // latency_spike: compare the newest checks against a baseline built from
  // older checks, so the spike itself doesn't drag the baseline up.
  const baseline = computeBaseline(recent.slice(RULES.spikeConsecutive));
  const threshold = spikeThreshold(baseline);
  const newest = recent.slice(0, RULES.spikeConsecutive);
  if (
    threshold !== null &&
    newest.length === RULES.spikeConsecutive &&
    newest.every((c) => c.ok && c.latencyMs !== null && c.latencyMs > threshold)
  ) {
    anomalies.push({
      type: "latency_spike",
      severity: "warning",
      message: `latency ${latest.latencyMs}ms vs normal ~${baseline.medianLatencyMs}ms (threshold ${Math.round(threshold)}ms)`
    });
  }

  // dns_failure: the domain doesn't resolve
  const dnsStatus = latest.details?.dns?.status;
  if (dnsStatus === "NXDOMAIN" || dnsStatus === "SERVFAIL") {
    anomalies.push({
      type: "dns_failure",
      severity: "critical",
      message: `DNS ${dnsStatus} from 1.1.1.1`
    });
  }

  // rate_limited / quota_low
  const rl = latest.details?.rateLimit;
  if (isRateLimited(latest)) {
    const wait = rl?.retryAfterSec ?? rl?.resetSec;
    anomalies.push({
      type: "rate_limited",
      severity: "warning",
      message: wait != null ? `rate limited, retry in ~${wait}s` : "rate limited (HTTP 429)"
    });
  } else if (
    rl &&
    rl.limit !== null &&
    rl.remaining !== null &&
    rl.limit > 0 &&
    rl.remaining / rl.limit <= RULES.quotaLowRatio
  ) {
    anomalies.push({
      type: "quota_low",
      severity: "warning",
      message: `only ${rl.remaining}/${rl.limit} requests left${rl.resetSec != null ? `, resets in ~${rl.resetSec}s` : ""}`
    });
  }

  // blocked: the site is refusing automated traffic
  if (isBlocked(latest)) {
    anomalies.push({
      type: "blocked",
      severity: "warning",
      message: latest.details?.blockedHint ?? "blocked"
    });
  }

  return anomalies;
}

// ---------- open / resolve ----------

export function diffAnomalies(
  previouslyOpen: OpenAnomaly[],
  current: Anomaly[],
  now: number
): { open: OpenAnomaly[]; events: AnomalyEvent[] } {
  const prevByType = new Map(previouslyOpen.map((a) => [a.type, a]));
  const currentTypes = new Set(current.map((a) => a.type));
  const events: AnomalyEvent[] = [];
  const open: OpenAnomaly[] = [];

  for (const a of current) {
    const prev = prevByType.get(a.type);
    if (prev) {
      // still ongoing: keep the original start time, refresh the message
      open.push({ ...a, since: prev.since });
    } else {
      open.push({ ...a, since: now });
      events.push({ ...a, kind: "opened", ts: now });
    }
  }

  for (const prev of previouslyOpen) {
    if (!currentTypes.has(prev.type)) {
      const durationSec = Math.round((now - prev.since) / 1000);
      events.push({
        type: prev.type,
        severity: prev.severity,
        kind: "resolved",
        ts: now,
        message: `resolved after ${durationSec}s (was: ${prev.message})`
      });
    }
  }

  return { open, events };
}