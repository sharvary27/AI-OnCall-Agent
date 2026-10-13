import { describe, expect, it } from "vitest";
import { buildPostmortemData, findImpactStart, type HistoryCheck, type HistoryEvent } from "../src/postmortem";
import type { Incident } from "../src/incident";

const T0 = Date.parse("2026-10-13T16:00:00Z");
const min = (n: number) => T0 + n * 60_000;

const ok = (m: number, latencyMs = 100): HistoryCheck => ({ ts: min(m), status: 200, latencyMs, ok: true, error: null });
const fail = (m: number, status: number | null = 503): HistoryCheck => ({
  ts: min(m),
  status,
  latencyMs: status === null ? null : 150,
  ok: false,
  error: status === null ? "timeout after 10000ms" : null
});

// Healthy until minute 3, failing minutes 3-7, healthy again from minute 8.
const checks = [ok(0), ok(1), ok(2), fail(3), fail(4), fail(5), fail(6, null), fail(7), ok(8), ok(9)];

const incident: Incident = {
  id: "wf-1",
  url: "https://api.example.com/health",
  type: "down",
  severity: "critical",
  alertMessage: "2 failed checks in a row (latest: HTTP 503)",
  openedAt: min(4), // alert needs 2 failures, so it opens at the 2nd one
  createdAt: min(5),
  stillOpen: true,
  recheck: { status: 503, latencyMs: 150, ok: false, error: null },
  diagnosis: "Origin returns 503; DNS fine. Likely the app server.",
  proposal: { action: "backoff", intervalSec: 300, summary: "Check every 5 minutes." },
  status: "approved",
  decidedAt: min(5) + 30_000
};

const events: HistoryEvent[] = [
  { ts: min(4), kind: "opened", type: "down", severity: "critical", message: incident.alertMessage },
  { ts: min(8), kind: "resolved", type: "down", severity: "critical", message: "resolved after 240s" }
];

describe("findImpactStart", () => {
  it("walks back to the first failure before the alert", () => {
    expect(findImpactStart(checks, min(4))).toBe(min(3));
  });

  it("does not walk back past the end of a previous alert (earlier session)", () => {
    // failing since minute 3, but a previous "down" alert was closed at minute 4.5
    expect(findImpactStart(checks, min(6), min(4.5))).toBe(min(5));
  });

  it("falls back to the alert time when there's no earlier failure", () => {
    expect(findImpactStart([ok(0), ok(1)], min(1))).toBe(min(1));
    expect(findImpactStart([], min(1))).toBe(min(1));
  });
});

describe("buildPostmortemData", () => {
  const data = buildPostmortemData(incident, events, checks, min(20));

  it("measures impact from the first failure to resolution", () => {
    expect(data.state).toBe("resolved");
    expect(data.impactStartedAt).toBe(new Date(min(3)).toISOString());
    expect(data.resolvedAt).toBe(new Date(min(8)).toISOString());
    expect(data.durationMinutes).toBe(5);
    expect(data.detectionDelayMinutes).toBe(1);
  });

  it("counts failed checks by status code", () => {
    expect(data.checksDuringIncident).toBe(6); // minutes 3-8
    expect(data.failedChecks).toBe(5);
    expect(data.failuresByStatus).toEqual({ "503": 4, "timeout after 10000ms": 1 });
  });

  it("builds an ordered timeline including the approval", () => {
    expect(data.timeline.map((t) => t.event)).toEqual([
      "First failed check (HTTP 503)",
      "Alert opened: 2 failed checks in a row (latest: HTTP 503)",
      "Automatic investigation finished (diagnosis posted)",
      "Approved: checks slowed to every 5 min",
      "Resolved: resolved after 240s"
    ]);
  });

  it("reports ongoing incidents up to now", () => {
    const ongoing = buildPostmortemData(incident, events.slice(0, 1), checks.slice(0, 8), min(10));
    expect(ongoing.state).toBe("ongoing");
    expect(ongoing.resolvedAt).toBeNull();
    expect(ongoing.durationMinutes).toBe(7); // minute 3 to "now" (minute 10)
  });

  it("starts the impact after a previous session's alert ended", () => {
    // Earlier session: alert opened at minute 4, closed by "monitoring stopped" at 5.5.
    // Re-added: new alert opens at minute 7. Failures from minute 3 belong to the old one.
    const reopened = { ...incident, openedAt: min(7), createdAt: min(7) };
    const history: HistoryEvent[] = [
      events[0],
      { ts: min(5.5), kind: "resolved", type: "down", severity: "critical", message: "resolved; monitoring stopped" },
      { ts: min(7), kind: "opened", type: "down", severity: "critical", message: incident.alertMessage }
    ];
    const data = buildPostmortemData(reopened, history, checks, min(20));
    expect(data.impactStartedAt).toBe(new Date(min(6)).toISOString());
    expect(data.detectionDelayMinutes).toBe(1);
  });

  it("ignores a resolution of a different alert type", () => {
    const other: HistoryEvent[] = [{ ...events[1], type: "latency_spike" }];
    expect(buildPostmortemData(incident, other, checks, min(20)).state).toBe("ongoing");
  });
});