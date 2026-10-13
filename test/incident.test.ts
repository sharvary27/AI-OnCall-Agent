import { describe, expect, it } from "vitest";
import {
  buildEvidence,
  fallbackDiagnosis,
  formatDecisionMessage,
  formatIncidentMessage,
  formatRecoveredMessage,
  proposeAction,
  shouldInvestigate,
  tidyDiagnosis,
  type EndpointContext,
  type Incident,
  type InvestigationParams
} from "../src/incident";
import type { FullCheck } from "../src/checks";

const OPENED = Date.parse("2026-10-12T00:37:15Z");

const params: InvestigationParams = {
  url: "https://httpbin.org/status/503",
  agentName: "default",
  anomaly: { type: "down", severity: "critical", message: "2 failed checks in a row (latest: HTTP 503)" },
  openedAt: OPENED
};

const recheck: FullCheck = {
  ts: OPENED + 30_000,
  status: 503,
  latencyMs: 210,
  ok: false,
  error: null,
  details: {
    dns: { resolver: "1.1.1.1", status: "NOERROR", ms: 20, a: ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"], aaaa: ["::1"], cname: [], error: null },
    redirects: [],
    finalUrl: "https://httpbin.org/status/503",
    rateLimit: null,
    security: { hsts: false, csp: false, xFrameOptions: false, xContentTypeOptions: false, referrerPolicy: false, missing: ["csp"] },
    edge: { server: "gunicorn", cfRay: null, cacheStatus: null, via: null, ageSec: null },
    blockedHint: null
  }
};

const context: EndpointContext = {
  intervalSec: 60,
  baseline: { samples: 0, medianLatencyMs: null, p90LatencyMs: null, errorRatePct: 100 },
  uptimePct: 0,
  openAnomalies: [{ ...params.anomaly, since: OPENED }],
  checks: Array.from({ length: 10 }, (_, i) => ({
    time: new Date(OPENED - i * 60_000).toISOString(),
    status: 503,
    latencyMs: 200,
    ok: false,
    error: null
  }))
};

describe("shouldInvestigate", () => {
  it("investigates real problems", () => {
    for (const t of ["down", "error_burst", "latency_spike", "dns_failure", "rate_limited", "quota_low"] as const) {
      expect(shouldInvestigate(t)).toBe(true);
    }
  });
  it("skips bot blocking, which isn't an outage", () => expect(shouldInvestigate("blocked")).toBe(false));
});

describe("buildEvidence", () => {
  const evidence = buildEvidence(params, recheck, context, OPENED + 5 * 60_000);

  it("describes the alert and how long ago it opened", () => {
    expect(evidence.alert).toEqual({
      type: "down",
      severity: "critical",
      message: "2 failed checks in a row (latest: HTTP 503)",
      openedMinutesAgo: 5
    });
  });

  it("knows whether the alert survived the recheck", () => {
    expect(evidence.stillOpenAfterRecheck).toBe(true);
    const resolved = buildEvidence(params, recheck, { ...context, openAnomalies: [] }, OPENED);
    expect(resolved.stillOpenAfterRecheck).toBe(false);
  });

  it("keeps the prompt small: trims IPs, drops security headers, caps history", () => {
    expect(evidence.recheck.dns?.ipv4).toHaveLength(3);
    expect(JSON.stringify(evidence)).not.toContain("xFrameOptions");
    expect(evidence.recentChecks).toHaveLength(8);
  });

  it("includes the facts the diagnosis needs", () => {
    expect(evidence.recheck).toMatchObject({ status: 503, ok: false, latencyMs: 210, server: "gunicorn" });
    expect(evidence.recheck.dns?.status).toBe("NOERROR");
  });
});

describe("chat message", () => {
  const incident: Incident = {
    id: "wf-1",
    url: params.url,
    type: "latency_spike",
    severity: "warning",
    alertMessage: "latency 900ms vs normal ~100ms",
    openedAt: OPENED,
    createdAt: OPENED + 60_000,
    stillOpen: false,
    recheck: { status: 200, latencyMs: 120, ok: true, error: null },
    diagnosis: "  Latency spiked briefly.\n- recheck 120ms  ",
    proposal: null,
    status: "no_action"
  };

  it("leads with an icon, the readable type and the URL", () => {
    const text = formatIncidentMessage(incident);
    expect(text.split("\n")[0]).toBe(`🟠 **latency spike: ${params.url}** (may have recovered)`);
    expect(text).toContain("Alert: latency 900ms vs normal ~100ms");
    expect(text.endsWith("- recheck 120ms")).toBe(true);
  });

  it("uses a red icon for critical, ongoing incidents", () => {
    const text = formatIncidentMessage({ ...incident, type: "down", severity: "critical", stillOpen: true });
    expect(text.startsWith("🔴 **down:")).toBe(true);
    expect(text).toContain("(still happening)");
  });

  it("still reports raw facts if the LLM is unavailable", () => {
    const text = fallbackDiagnosis(buildEvidence(params, recheck, context, OPENED));
    expect(text).toContain("HTTP 503 in 210ms");
    expect(text).toContain("DNS: NOERROR");
  });
});

describe("proposeAction", () => {
  it("suggests slowing checks while an endpoint is down", () => {
    const p = proposeAction("down", 60, true, null);
    expect(p).toEqual({
      action: "backoff",
      intervalSec: 300,
      summary:
        "Reduce noise: check every 5 minutes instead of every 1 minute while it's failing. Normal checks resume automatically when it recovers."
    });
  });

  it("caps the back-off at 30 minutes for outages", () => {
    expect(proposeAction("down", 600, true, null)?.intervalSec).toBe(1800);
  });

  it("backs off at least until the rate limit resets", () => {
    expect(proposeAction("rate_limited", 60, true, { retryAfterSec: 900, resetSec: null })?.intervalSec).toBe(900);
    expect(proposeAction("quota_low", 60, true, { retryAfterSec: null, resetSec: 30 })?.intervalSec).toBe(300);
  });

  it("proposes nothing if it already recovered, or for latency spikes", () => {
    expect(proposeAction("down", 60, false, null)).toBeNull();
    expect(proposeAction("latency_spike", 60, true, null)).toBeNull();
  });

  it("proposes nothing if checks are already slow enough", () => {
    expect(proposeAction("down", 1800, true, null)).toBeNull();
  });
});

describe("tidyDiagnosis", () => {
  it("turns * bullets into - and separates text that follows a list", () => {
    const raw = "Service unavailable.\n* Status: 503\n* DNS: NOERROR\nLikely cause: the app.";
    expect(tidyDiagnosis(raw)).toBe("Service unavailable.\n- Status: 503\n- DNS: NOERROR\n\nLikely cause: the app.");
  });

  it("leaves already-clean text alone", () => {
    const clean = "Down.\n\n- a\n- b\n\nNext step: x";
    expect(tidyDiagnosis(clean)).toBe(clean);
  });
});

describe("approval messages", () => {
  const base: Incident = {
    id: "wf-2",
    url: "https://httpbin.org/status/503",
    type: "down",
    severity: "critical",
    alertMessage: "2 failed checks in a row (latest: HTTP 503)",
    openedAt: OPENED,
    createdAt: OPENED,
    stillOpen: true,
    recheck: { status: 503, latencyMs: 200, ok: false, error: null },
    diagnosis: "Server error.",
    proposal: { action: "backoff", intervalSec: 300, summary: "Check every 5 minutes." },
    status: "awaiting_approval"
  };

  it("asks for approval while waiting", () => {
    const text = formatIncidentMessage(base);
    expect(text).toContain("**Suggested action:** Check every 5 minutes.");
    expect(text).toContain("Reply **approve** or **dismiss** (expires in 30 minutes).");
  });

  it("stops asking once answered", () => {
    expect(formatIncidentMessage({ ...base, status: "approved" })).not.toContain("Reply **approve**");
  });

  it("confirms each outcome", () => {
    expect(formatDecisionMessage({ ...base, status: "approved" })).toContain("now checking https://httpbin.org/status/503 every 5 minutes");
    expect(formatDecisionMessage({ ...base, status: "dismissed" })).toContain("stays as it was");
    expect(formatDecisionMessage({ ...base, status: "expired" })).toContain("No answer in 30 minutes");
    expect(formatDecisionMessage({ ...base, status: "no_action" })).toBe("");
  });

  it("announces recovery and the restored interval", () => {
    expect(formatRecoveredMessage(base.url, "down", "resolved after 300s (was: ...)", 60)).toBe(
      "✅ **down resolved: https://httpbin.org/status/503**: resolved after 300s (was: ...). Back to checking every 1 minute."
    );
    expect(formatRecoveredMessage(base.url, "error_burst", "resolved after 60s", null)).toBe(
      "✅ **error burst resolved: https://httpbin.org/status/503**: resolved after 60s."
    );
  });
});