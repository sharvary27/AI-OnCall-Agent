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
  proposal: Proposal | null; // what the agent suggests doing, if anything
  status: IncidentStatus;
  decidedAt?: number; // when the approval step finished
};

// Lifecycle of the human-approval step.
export type IncidentStatus =
  | "awaiting_approval" // proposal posted, waiting for the user
  | "approved" // user said yes, action applied
  | "dismissed" // user said no
  | "expired" // nobody answered in time
  | "no_action"; // nothing to propose (e.g. a latency spike, or it already recovered)

// The only action the agent can take: slow down checks ("back off") until the
// alert resolves, then automatically return to the normal interval.
export type Proposal = {
  action: "backoff";
  intervalSec: number;
  summary: string; // one sentence shown to the user
};

export const DECISION_EVENT = "incident-decision"; // Workflow event type
export const APPROVAL_TIMEOUT = "30 minutes";

function minutes(sec: number): string {
  const m = Math.round(sec / 60);
  return m === 1 ? "1 minute" : `${m} minutes`;
}

function clamp(n: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, n));
}

// Decide what (if anything) to suggest for an incident.
export function proposeAction(
  type: AnomalyType,
  currentIntervalSec: number,
  stillOpen: boolean,
  rateLimit: { retryAfterSec: number | null; resetSec: number | null } | null
): Proposal | null {
  if (!stillOpen) return null; // already recovered: nothing to do

  if (type === "rate_limited" || type === "quota_low") {
    // Respect the server: don't poll faster than the quota comes back.
    const wait = rateLimit?.retryAfterSec ?? rateLimit?.resetSec ?? 0;
    const intervalSec = clamp(Math.max(wait, currentIntervalSec * 4), 300, 3600);
    if (intervalSec <= currentIntervalSec) return null;
    return {
      action: "backoff",
      intervalSec,
      summary: `Back off: check every ${minutes(intervalSec)} instead of every ${minutes(currentIntervalSec)} until the limit clears, so monitoring doesn't burn your quota.`
    };
  }

  if (type === "down" || type === "error_burst" || type === "dns_failure") {
    const intervalSec = clamp(currentIntervalSec * 5, 300, 1800);
    if (intervalSec <= currentIntervalSec) return null;
    return {
      action: "backoff",
      intervalSec,
      summary: `Reduce noise: check every ${minutes(intervalSec)} instead of every ${minutes(currentIntervalSec)} while it's failing. Normal checks resume automatically when it recovers.`
    };
  }

  return null; // latency spikes: informational only
}

// Llama sometimes uses "*" bullets and starts the next paragraph right under the
// last bullet, which markdown then merges into that bullet. Normalise both.
export function tidyDiagnosis(text: string): string {
  const isBullet = (l: string) => /^\s*[-*•]\s+/.test(l);
  const lines = text.trim().split("\n").map((l) => l.replace(/^\s*[*•]\s+/, "- "));
  const out: string[] = [];
  for (const line of lines) {
    const prev = out[out.length - 1];
    if (prev !== undefined && isBullet(prev) && line.trim() !== "" && !isBullet(line)) {
      out.push(""); // blank line ends the list
    }
    out.push(line);
  }
  return out.join("\n");
}

// What the Workflow learns about the endpoint (subset of Probe.getSummary()).
export type EndpointContext = {
  intervalSec: number; // how often the endpoint is currently checked
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
  const lines = [
    `${ICON[incident.severity]} **${incident.type.replaceAll("_", " ")}: ${incident.url}** (${status})`,
    "",
    `Alert: ${incident.alertMessage}`,
    "",
    tidyDiagnosis(incident.diagnosis)
  ];
  if (incident.proposal && incident.status === "awaiting_approval") {
    lines.push(
      "",
      `**Suggested action:** ${incident.proposal.summary}`,
      `Reply **approve** or **dismiss** (expires in ${APPROVAL_TIMEOUT}).`
    );
  }
  return lines.join("\n");
}

// Posted after the approval step finishes.
export function formatDecisionMessage(incident: Incident): string {
  const where = incident.url;
  switch (incident.status) {
    case "approved":
      return `✅ Approved: now checking ${where} every ${minutes(incident.proposal?.intervalSec ?? 300)}. I'll switch back to the normal interval and let you know when it recovers.`;
    case "dismissed":
      return `👍 Dismissed: monitoring of ${where} stays as it was.`;
    case "expired":
      return `⌛ No answer in ${APPROVAL_TIMEOUT}, so I left monitoring of ${where} unchanged.`;
    default:
      return "";
  }
}

// Posted by the Probe when an alert resolves.
export function formatRecoveredMessage(
  url: string,
  type: AnomalyType,
  resolvedMessage: string,
  restoredIntervalSec: number | null
): string {
  const restored =
    restoredIntervalSec !== null ? ` Back to checking every ${minutes(restoredIntervalSec)}.` : "";
  return `✅ **${type.replaceAll("_", " ")} resolved: ${url}**: ${resolvedMessage}.${restored}`;
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