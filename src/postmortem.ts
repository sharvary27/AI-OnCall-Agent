// Builds the facts for an incident postmortem from an incident plus the
// endpoint's raw history. Pure functions, tested in test/postmortem.test.ts.
// The LLM writes the prose; this decides the numbers, so they can't be invented.

import type { Incident } from "./incident";

export type HistoryEvent = {
  ts: number;
  kind: "opened" | "resolved";
  type: string;
  severity: string;
  message: string;
};

export type HistoryCheck = {
  ts: number;
  status: number | null;
  latencyMs: number | null;
  ok: boolean;
  error: string | null;
};

const iso = (ts: number) => new Date(ts).toISOString();

// The problem usually starts before the alert: "down" needs 2 failures, so the
// first failure is earlier than the alert. Walk back from the alert to the
// start of the unbroken run of failed checks, but never past notBefore (the
// end of the previous alert of the same type, e.g. an earlier monitoring session).
export function findImpactStart(
  checks: HistoryCheck[],
  openedAt: number,
  notBefore = -Infinity
): number {
  const sorted = checks.filter((c) => c.ts > notBefore).sort((a, b) => a.ts - b.ts);
  let i = -1;
  for (let j = 0; j < sorted.length; j++) if (sorted[j].ts <= openedAt) i = j;
  if (i < 0 || sorted[i].ok) return openedAt;
  while (i > 0 && !sorted[i - 1].ok) i--;
  return sorted[i].ts;
}

export function buildPostmortemData(
  incident: Incident,
  events: HistoryEvent[],
  checks: HistoryCheck[],
  now: number
) {
  const resolved = events
    .filter((e) => e.kind === "resolved" && e.type === incident.type && e.ts >= incident.openedAt)
    .sort((a, b) => a.ts - b.ts)[0];
  const endTs = resolved?.ts ?? null;
  // Where did the previous alert of this type end? Don't attribute earlier
  // failures to this incident.
  const previousEnd = events
    .filter((e) => e.kind === "resolved" && e.type === incident.type && e.ts < incident.openedAt)
    .reduce((max, e) => Math.max(max, e.ts), -Infinity);
  const startTs = findImpactStart(checks, incident.openedAt, previousEnd);
  const windowEnd = endTs ?? now;

  const during = checks.filter((c) => c.ts >= startTs && c.ts <= windowEnd);
  const failed = during.filter((c) => !c.ok);
  const statusCodes: Record<string, number> = {};
  for (const c of failed) {
    const key = c.status !== null ? String(c.status) : c.error ?? "no response";
    statusCodes[key] = (statusCodes[key] ?? 0) + 1;
  }
  const latencies = during.map((c) => c.latencyMs).filter((x): x is number => x !== null);

  const timeline: { time: string; event: string }[] = [];
  if (startTs < incident.openedAt) {
    const first = during.find((c) => c.ts === startTs);
    timeline.push({
      time: iso(startTs),
      event: `First failed check (${first?.status !== null && first?.status !== undefined ? `HTTP ${first.status}` : first?.error ?? "no response"})`
    });
  }
  timeline.push({ time: iso(incident.openedAt), event: `Alert opened: ${incident.alertMessage}` });
  timeline.push({ time: iso(incident.createdAt), event: "Automatic investigation finished (diagnosis posted)" });
  if (incident.proposal) {
    const outcome =
      incident.status === "approved"
        ? `Approved: checks slowed to every ${Math.round(incident.proposal.intervalSec / 60)} min`
        : incident.status === "dismissed"
          ? "Suggested back-off dismissed by the user"
          : incident.status === "expired"
            ? "Suggested back-off expired without an answer"
            : "Suggested back-off awaiting an answer";
    timeline.push({ time: incident.decidedAt ? iso(incident.decidedAt) : "unknown", event: outcome });
  }
  if (resolved) timeline.push({ time: iso(resolved.ts), event: `Resolved: ${resolved.message}` });

  return {
    endpoint: incident.url,
    alertType: incident.type,
    severity: incident.severity,
    state: endTs ? "resolved" : "ongoing",
    impactStartedAt: iso(startTs),
    detectedAt: iso(incident.openedAt),
    resolvedAt: endTs ? iso(endTs) : null,
    durationMinutes: Math.round((windowEnd - startTs) / 60_000),
    detectionDelayMinutes: Math.round((incident.openedAt - startTs) / 60_000),
    checksDuringIncident: during.length,
    failedChecks: failed.length,
    failuresByStatus: statusCodes,
    maxLatencyMs: latencies.length ? Math.max(...latencies) : null,
    diagnosis: incident.diagnosis,
    actionTaken: incident.proposal ? `${incident.proposal.summary} (${incident.status})` : "none",
    timeline: timeline.sort((a, b) => a.time.localeCompare(b.time))
  };
}

export const POSTMORTEM_INSTRUCTIONS = `Write a blameless postmortem from the data, in markdown, with these sections:
## Summary (2 sentences)
## Impact (duration, failed checks, status codes)
## Timeline (bullet list, times in UTC)
## Root cause (from the diagnosis; say if it's uncertain)
## Resolution (what changed, or "ongoing")
## Follow-ups (2-3 concrete action items)
Use only numbers from the data. Keep it under 250 words.`;