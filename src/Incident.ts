// Pure helpers for investigations: which alerts to investigate, what evidence
// to give the LLM, and how to show the result in chat. No Cloudflare APIs here,
// so it's unit-tested in test/incident.test.ts.

import type { FullCheck } from "./checks";
import type { Anomaly, AnomalyType, Baseline, OpenAnomaly } from "./detect";

export type InvestigationParams = {
  url: string;
  agentName: string; // which chat agent to report back to
  anomaly: Anomaly;
  openedAt: number;
};

export type Incident = {
  id: string;
  url: string;
  type: AnomalyType;
  severity: Anomaly["severity"];
  alertMessage: string;
  openedAt: number;
  createdAt: number;
  stillOpen: boolean; // was the alert still open after the recheck?
  recheck: { status: number | null; latencyMs: number | null; ok: boolean; error: string | null };
  diagnosis: string;
};

// What the Workflow learns about the endpoint (subset of Probe.getSummary()).
export type EndpointContext = {
  baseline: Baseline;
  uptimePct: number | null;
  openAnomalies: OpenAnomaly[];
  checks: { time: string; status: number | null; latencyMs: number | null; ok: boolean; error: string | null }[];
};

// Bot blocking isn't an outage, so it isn't worth an investigation.
const INVESTIGATE: Record<AnomalyType, boolean> = {
  down: true,
  error_burst: true,
  latency_spike: true,
  dns_failure: true,
  rate_limited: true,
  quota_low: true,
  blocked: false
};

export function shouldInvestigate(type: AnomalyType): boolean {
  return INVESTIGATE[type];
}

// Compact, LLM-friendly evidence. Leaves out noise (security headers,
// IPv6 lists, ...) to keep the prompt small and focused.
export function buildEvidence(
  params: InvestigationParams,
  recheck: FullCheck,
  context: EndpointContext,
  now: number
) {
  const d = recheck.details;
  return {
    endpoint: params.url,
    alert: {
      type: params.anomaly.type,
      severity: params.anomaly.severity,
      message: params.anomaly.message,
      openedMinutesAgo: Math.round((now - params.openedAt) / 60_000)
    },
    stillOpenAfterRecheck: context.openAnomalies.some((a) => a.type === params.anomaly.type),
    recheck: {
      status: recheck.status,
      ok: recheck.ok,
      latencyMs: recheck.latencyMs,
      error: recheck.error,
      dns: d.dns ? { status: d.dns.status, ipv4: d.dns.a.slice(0, 3), cname: d.dns.cname, ms: d.dns.ms } : null,
      redirects: d.redirects.map((h) => `${h.status} ${h.url} -> ${h.location}`),
      finalUrl: d.finalUrl,
      rateLimit: d.rateLimit,
      server: d.edge?.server ?? null,
      blockedHint: d.blockedHint
    },
    normal: {
      medianLatencyMs: context.baseline.medianLatencyMs,
      p90LatencyMs: context.baseline.p90LatencyMs,
      errorRatePct: context.baseline.errorRatePct,
      uptimePctRecent: context.uptimePct
    },
    recentChecks: context.checks.slice(0, 8).map((c) => ({
      time: c.time,
      status: c.status,
      latencyMs: c.latencyMs,
      error: c.error
    })),
    otherOpenAlerts: context.openAnomalies
      .filter((a) => a.type !== params.anomaly.type)
      .map((a) => `${a.severity}: ${a.type} (${a.message})`)
  };
}

export const DIAGNOSIS_SYSTEM_PROMPT = `You are an experienced site reliability engineer on call.
You get evidence about one alert on one HTTP endpoint, as JSON.
Write a short diagnosis for the developer who owns it:
1. What is wrong, in one sentence.
2. Key evidence: 2 to 4 short bullet points, citing actual numbers (status codes, ms, DNS status).
3. Most likely cause, and how confident you are (low/medium/high).
4. One concrete next step.
Rules: use only facts from the evidence; never invent numbers. If stillOpenAfterRecheck is
false, say the problem may have been transient. DNS NOERROR with HTTP 5xx points to the
server/app, not the network. NXDOMAIN means the domain itself doesn't resolve.
Keep it under 130 words. Plain text with "-" bullets, no headings.`;

const ICON: Record<Anomaly["severity"], string> = { critical: "🔴", warning: "🟠" };

// The message that appears in chat without the user asking.
export function formatIncidentMessage(incident: Incident): string {
  const status = incident.stillOpen ? "still happening" : "may have recovered";
  return [
    `${ICON[incident.severity]} **${incident.type.replaceAll("_", " ")}: ${incident.url}** (${status})`,
    `Alert: ${incident.alertMessage}`,
    "",
    incident.diagnosis.trim()
  ].join("\n");
}

// Fallback when the LLM call fails for good: still report the facts.
export function fallbackDiagnosis(evidence: ReturnType<typeof buildEvidence>): string {
  const r = evidence.recheck;
  const lines = [
    `Automatic diagnosis unavailable; raw findings:`,
    `- Recheck: ${r.status !== null ? `HTTP ${r.status}` : r.error ?? "no response"}${r.latencyMs !== null ? ` in ${r.latencyMs}ms` : ""}`,
    `- DNS: ${r.dns?.status ?? "not checked"}`,
    `- Normal latency: ${evidence.normal.medianLatencyMs ?? "unknown"}ms`
  ];
  return lines.join("\n");
}