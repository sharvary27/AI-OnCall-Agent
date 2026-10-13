import { createWorkersAI } from "workers-ai-provider";
import { callable, routeAgentRequest } from "agents";
import { AIChatAgent, type OnChatMessageOptions } from "@cloudflare/ai-chat";
import {
  convertToModelMessages,
  pruneMessages,
  stepCountIs,
  streamText,
  tool,
  wrapLanguageModel,
  type LanguageModelMiddleware
} from "ai";
import { z } from "zod";

import { runFullCheck } from "./checks";
import {
  DECISION_EVENT,
  formatDecisionMessage,
  formatIncidentMessage,
  type Incident
} from "./incident";

// The Worker entry must export every Durable Object and Workflow class.
export { Probe } from "./probe";
export { InvestigationWorkflow } from "./investigate";

const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";

const SYSTEM_PROMPT = `You are an on-call engineer assistant for the user's deployed services.
You help them monitor endpoints, investigate outages, latency spikes and rate limiting,
and explain what happened in plain language.

Tools:
- addEndpoint: start monitoring a URL.
- listEndpoints: see everything being monitored and its latest check.
- getEndpointStatus: recent checks, uptime, average latency and full network
  details of the latest check for one monitored URL.
- inspectEndpoint: one-off deep check of any URL, without monitoring it.
- getAlerts: open alerts and recent alert history across all endpoints.
- getIncidents: past incidents with their automatic diagnosis.
- respondToIncident: approve or dismiss the action suggested in an incident.
- removeEndpoint: stop monitoring a URL.

Alerts: each endpoint learns its normal latency (baseline) and raises alerts
(down, error_burst, latency_spike, dns_failure, rate_limited, quota_low, blocked).
"opened" means a problem started, "resolved" means it cleared. Lead with
critical alerts, say when they started, and compare latency to the baseline.

Incidents: when an alert opens, an automatic investigation rechecks the endpoint,
compares it with its history and writes a diagnosis. These appear in this chat
on their own, as messages starting with a colored icon. Use getIncidents to look
them up (e.g. "what broke last night?", "why was it down?").
Some incidents end with a "Suggested action" and wait for the user. When the user
replies approve / yes / do it, call respondToIncident with decision "approve";
for dismiss / no / leave it, use "dismiss". Never approve on the user's behalf.

Reading check details:
- dns: status NXDOMAIN means the domain does not exist; empty a/aaaa means it
  resolves to nothing; ms is the lookup time through 1.1.1.1.
- redirects: each hop before the final page. A redirect to a login page usually
  means the site requires sign-in or blocks bots.
- rateLimit: rateLimited true means HTTP 429 or no quota left. Mention remaining
  and resetSec / retryAfterSec when present (in seconds).
- blockedHint: the site is blocking automated requests; explain it, don't call
  the site "down".
- security.missing: security headers the site doesn't send. Only mention these
  if the user asks about security.

Be direct and concise. Only state facts you got from a tool result; if you don't have
data yet, say so instead of guessing.
Call each tool at most once per request. After a tool returns, answer the user
using its result; do not call the same tool again with the same input.`;

// Workers AI + Llama 3.3 (workers-ai-provider 3.3.1) currently emits every
// streamed piece twice: reply text AND tool-call arguments. Doubled tool
// arguments become invalid JSON like {"url": "{"url": "httpshttps://://...
// so the tool never runs. This middleware:
//   1. drops the second copy of each duplicated text / reasoning / tool-input
//      delta (real repeats like "ha", "ha" still come through), and
//   2. repairs the final tool-call input if it still isn't valid JSON.

function parsesAsJson(s: string): boolean {
  try {
    JSON.parse(s);
    return true;
  } catch {
    return false;
  }
}

// Rebuild a string in which every chunk was emitted twice
// ("httpshttps://://" -> "https://"). Chunk boundaries are unknown, so try
// chunk sizes with backtracking and accept the first result that is valid JSON.
function undoubleJson(s: string): string | null {
  let budget = 20_000; // safety cap on search steps
  const walk = (i: number, acc: string): string | null => {
    if (--budget < 0) return null;
    if (i === s.length) return parsesAsJson(acc) ? acc : null;
    for (let k = 1; i + 2 * k <= s.length; k++) {
      const chunk = s.slice(i, i + k);
      if (chunk === s.slice(i + k, i + 2 * k)) {
        const found = walk(i + 2 * k, acc + chunk);
        if (found !== null) return found;
      }
    }
    return null;
  };
  return walk(0, "");
}

const dedupeDeltas: LanguageModelMiddleware = {
  specificationVersion: "v3",
  wrapStream: async ({ doStream }) => {
    const { stream, ...rest } = await doStream();
    let lastKey: string | null = null; // which stream + piece we saw last
    let skippedLast = false;
    const toolInputs = new Map<string, string>(); // deduped args per tool call

    const fixed = stream.pipeThrough(
      new TransformStream({
        transform(part, controller) {
          if (
            part.type === "text-delta" ||
            part.type === "reasoning-delta" ||
            part.type === "tool-input-delta"
          ) {
            const key = `${part.type}:${part.id}:${part.delta}`;
            if (key === lastKey && !skippedLast) {
              skippedLast = true; // duplicate, drop it
              return;
            }
            lastKey = key;
            skippedLast = false;
            if (part.type === "tool-input-delta") {
              toolInputs.set(part.id, (toolInputs.get(part.id) ?? "") + part.delta);
            }
            controller.enqueue(part);
            return;
          }

          lastKey = null;
          skippedLast = false;

          if (part.type === "tool-call" && !parsesAsJson(part.input)) {
            const fromDeltas = toolInputs.get(part.toolCallId);
            const repaired =
              fromDeltas && parsesAsJson(fromDeltas) ? fromDeltas : undoubleJson(part.input);
            if (repaired) {
              controller.enqueue({ ...part, input: repaired });
              return;
            }
            console.warn("[dedupe] could not repair tool input:", part.input);
          }

          controller.enqueue(part);
        }
      })
    );
    return { stream: fixed, ...rest };
  }
};

// Turn "example.com" or "https://Example.com/" into one canonical form,
// so the same endpoint always maps to the same Probe instance.
function normalizeUrl(input: string): string {
  const withScheme = /^https?:\/\//i.test(input.trim())
    ? input.trim()
    : `https://${input.trim()}`;
  const url = new URL(withScheme);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http and https URLs are supported");
  }
  return url.toString();
}

type EndpointRow = { url: string; interval_sec: number; added_at: number };
type IncidentRow = { id: string; created_at: number; data: string };

// Keep tool schemas simple: Workers AI rejects complex JSON schemas
// (unions / anyOf / null types) with an opaque "internal error".
// z.coerce accepts both 120 and "120"; toInt() then clamps it to a sane range.
const looseNumber = z.coerce.number().optional();

function toInt(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === "number" ? value : parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export class ChatAgent extends AIChatAgent<Env> {
  maxPersistedMessages = 100;
  chatRecovery = true;
  // Wait for MCP connections to be re-established after hibernation before
  // processing a message, so MCP tools aren't intermittently missing.
  waitForMcpConnections = true;

  onStart() {
    // Which endpoints this chat is monitoring.
    this.sql`CREATE TABLE IF NOT EXISTS endpoints (
      url          TEXT PRIMARY KEY,
      interval_sec INTEGER NOT NULL,
      added_at     INTEGER NOT NULL
    )`;
    // Incidents reported by investigation Workflows (full record as JSON).
    this.sql`CREATE TABLE IF NOT EXISTS incidents (
      id         TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL,
      data       TEXT NOT NULL
    )`;

    // Configure OAuth popup behavior for MCP servers that require authentication
    this.mcp.configureOAuthCallback({
      customHandler: (result) => {
        if (result.authSuccess) {
          return new Response("<script>window.close();</script>", {
            headers: { "content-type": "text/html" },
            status: 200
          });
        }
        return new Response(
          `Authentication Failed: ${result.authError || "Unknown error"}`,
          { headers: { "content-type": "text/plain" }, status: 400 }
        );
      }
    });
  }

  // Kept for the starter UI's MCP button.
  @callable()
  async addServer(name: string, url: string) {
    return await this.addMcpServer(name, url);
  }

  @callable()
  async removeServer(serverId: string) {
    await this.removeMcpServer(serverId);
  }

  // ---- Called by Workflows and Probes (Durable Object RPC), not by the user ----

  // Adds an assistant message to the chat without the user asking.
  // persistMessages saves it and pushes it to every open browser tab over the
  // WebSocket WITHOUT triggering an LLM reply (saveMessages would also make the
  // model respond to it).
  async postMessage(text: string, id: string = crypto.randomUUID()): Promise<void> {
    const message = {
      id,
      role: "assistant" as const,
      parts: [{ type: "text" as const, text }]
    };
    await this.persistMessages([...this.messages, message]);
  }

  // A new incident from an investigation: store it and post it.
  async reportIncident(incident: Incident): Promise<void> {
    this.saveIncident(incident);
    await this.postMessage(formatIncidentMessage(incident), `incident-${incident.id}`);
  }

  // The approval step finished (approved / dismissed / expired).
  async updateIncident(incident: Incident): Promise<void> {
    this.saveIncident(incident);
    const text = formatDecisionMessage(incident);
    if (text) await this.postMessage(text);
  }

  private saveIncident(incident: Incident): void {
    this.sql`INSERT OR REPLACE INTO incidents (id, created_at, data)
             VALUES (${incident.id}, ${incident.createdAt}, ${JSON.stringify(incident)})`;
  }

  private loadIncidents(): Incident[] {
    return this.sql<IncidentRow>`SELECT * FROM incidents ORDER BY created_at DESC LIMIT 100`.map(
      (r) => JSON.parse(r.data) as Incident
    );
  }

  private probeFor(url: string) {
    return this.env.Probe.get(this.env.Probe.idFromName(url));
  }

  private isMonitored(url: string): boolean {
    return this.sql<EndpointRow>`SELECT url FROM endpoints WHERE url = ${url}`.length > 0;
  }

  async onChatMessage(_onFinish: unknown, options?: OnChatMessageOptions) {
    const workersai = createWorkersAI({ binding: this.env.AI });

    const result = streamText({
      model: wrapLanguageModel({
        model: workersai(MODEL, { sessionAffinity: this.sessionAffinity }),
        middleware: dedupeDeltas
      }),
      system: SYSTEM_PROMPT,
      messages: pruneMessages({
        messages: await convertToModelMessages(this.messages),
        toolCalls: "before-last-2-messages",
        reasoning: "before-last-message"
      }),
      tools: {
        ...this.mcp.getAITools(),

        addEndpoint: tool({
          description:
            "Start monitoring an HTTP(S) endpoint. Runs a check right away, then repeats every intervalSeconds.",
          inputSchema: z.object({
            url: z.string().describe("The URL to monitor, e.g. https://example.com/health"),
            intervalSeconds: looseNumber.describe(
              "How often to check, in seconds (60 to 3600). Defaults to 300."
            )
          }),
          execute: async ({ url, intervalSeconds }) => {
            try {
              const normalized = normalizeUrl(url);
              const interval = toInt(intervalSeconds, 300, 60, 3600);
              // Pass this chat's name so the Probe knows where to report incidents.
              const firstCheck = await this.probeFor(normalized).configure(
                normalized,
                interval,
                this.name
              );
              this.sql`INSERT OR REPLACE INTO endpoints (url, interval_sec, added_at)
                       VALUES (${normalized}, ${interval}, ${Date.now()})`;
              return { monitoring: normalized, intervalSeconds: interval, firstCheck };
            } catch (err) {
              console.error("addEndpoint failed:", err);
              return { error: errorMessage(err) };
            }
          }
        }),

        listEndpoints: tool({
          description: "List every monitored endpoint with its most recent check.",
          inputSchema: z.object({}),
          execute: async () => {
            try {
              const rows = this.sql<EndpointRow>`SELECT * FROM endpoints ORDER BY added_at`;
              if (rows.length === 0) return "No endpoints are being monitored yet.";
              return await Promise.all(
                rows.map(async (r) => {
                  const summary = await this.probeFor(r.url).getSummary(1);
                  return {
                    url: r.url,
                    intervalSeconds: r.interval_sec,
                    latest: summary.checks[0] ?? null,
                    rateLimited: summary.latestDetails?.rateLimit?.rateLimited ?? false,
                    blockedHint: summary.latestDetails?.blockedHint ?? null,
                    openAlerts: summary.openAnomalies.map((a) => `${a.severity}: ${a.type}`)
                  };
                })
              );
            } catch (err) {
              console.error("listEndpoints failed:", err);
              return { error: errorMessage(err) };
            }
          }
        }),

        inspectEndpoint: tool({
          description:
            "Run one deep network check of any URL right now (DNS, redirects, rate-limit and security headers) without adding it to monitoring.",
          inputSchema: z.object({
            url: z.string().describe("The URL to inspect, e.g. https://example.com")
          }),
          execute: async ({ url }) => {
            try {
              return await runFullCheck(normalizeUrl(url));
            } catch (err) {
              console.error("inspectEndpoint failed:", err);
              return { error: errorMessage(err) };
            }
          }
        }),

        getEndpointStatus: tool({
          description:
            "Get recent checks, uptime percentage and average latency for one monitored endpoint.",
          inputSchema: z.object({
            url: z.string().describe("The monitored URL"),
            limit: looseNumber.describe("How many recent checks to include (1 to 100). Defaults to 20.")
          }),
          execute: async ({ url, limit }) => {
            try {
              const normalized = normalizeUrl(url);
              if (!this.isMonitored(normalized)) {
                return `${normalized} is not being monitored. Use addEndpoint first.`;
              }
              return await this.probeFor(normalized).getSummary(toInt(limit, 20, 1, 100));
            } catch (err) {
              console.error("getEndpointStatus failed:", err);
              return { error: errorMessage(err) };
            }
          }
        }),

        getAlerts: tool({
          description:
            "Show open alerts (down, latency spikes, rate limiting, DNS failures, ...) across all monitored endpoints, plus recent alert history. Use for questions like 'is anything wrong?' or 'what broke?'.",
          inputSchema: z.object({
            historyLimit: looseNumber.describe(
              "How many recent alert events per endpoint to include (1 to 50). Defaults to 10."
            )
          }),
          execute: async ({ historyLimit }) => {
            try {
              const rows = this.sql<EndpointRow>`SELECT * FROM endpoints ORDER BY added_at`;
              if (rows.length === 0) return "No endpoints are being monitored yet.";
              const limit = toInt(historyLimit, 10, 1, 50);
              const perEndpoint = await Promise.all(
                rows.map(async (r) => {
                  const probe = this.probeFor(r.url);
                  const [open, history] = await Promise.all([
                    probe.getOpenAnomalies(),
                    probe.getEvents(limit)
                  ]);
                  return { url: r.url, open, history };
                })
              );
              const openCount = perEndpoint.reduce((n, e) => n + e.open.length, 0);
              return { openAlertCount: openCount, endpoints: perEndpoint };
            } catch (err) {
              console.error("getAlerts failed:", err);
              return { error: errorMessage(err) };
            }
          }
        }),

        getIncidents: tool({
          description:
            "Look up past incidents (automatic investigations of alerts) with their diagnosis, newest first. Optionally filter by URL.",
          inputSchema: z.object({
            url: z.string().optional().describe("Only incidents for this URL"),
            limit: looseNumber.describe("How many incidents (1 to 20). Defaults to 5.")
          }),
          execute: async ({ url, limit }) => {
            try {
              const n = toInt(limit, 5, 1, 20);
              const filterUrl = url ? normalizeUrl(url) : null;
              const incidents = this.loadIncidents()
                .filter((i) => !filterUrl || i.url === filterUrl)
                .slice(0, n)
                .map((i) => ({
                  url: i.url,
                  type: i.type,
                  severity: i.severity,
                  openedAt: new Date(i.openedAt).toISOString(),
                  stillOpenAtInvestigation: i.stillOpen,
                  alert: i.alertMessage,
                  diagnosis: i.diagnosis,
                  suggestedAction: i.proposal?.summary ?? null,
                  status: i.status ?? "no_action"
                }));
              return incidents.length ? incidents : "No incidents recorded yet.";
            } catch (err) {
              console.error("getIncidents failed:", err);
              return { error: errorMessage(err) };
            }
          }
        }),

        respondToIncident: tool({
          description:
            "Approve or dismiss the suggested action of the most recent incident that is waiting for the user's answer. Only call this when the user explicitly answers.",
          inputSchema: z.object({
            decision: z.enum(["approve", "dismiss"]).describe("The user's answer"),
            url: z.string().optional().describe("Only needed if several incidents are waiting")
          }),
          execute: async ({ decision, url }) => {
            try {
              const filterUrl = url ? normalizeUrl(url) : null;
              const pending = this.loadIncidents().find(
                (i) => i.status === "awaiting_approval" && (!filterUrl || i.url === filterUrl)
              );
              if (!pending) return "There is no incident waiting for an answer.";

              // Wake the paused Workflow (its id is the incident id).
              const instance = await this.env.INVESTIGATION.get(pending.id);
              await instance.sendEvent({ type: DECISION_EVENT, payload: { decision } });

              // Mark it answered right away so it can't be answered twice;
              // the Workflow posts the final confirmation.
              this.saveIncident({
                ...pending,
                status: decision === "approve" ? "approved" : "dismissed"
              });
              return {
                sent: decision,
                url: pending.url,
                note: "The investigation will apply this and confirm in chat."
              };
            } catch (err) {
              console.error("respondToIncident failed:", err);
              return { error: errorMessage(err) };
            }
          }
        }),

        removeEndpoint: tool({
          description: "Stop monitoring an endpoint.",
          inputSchema: z.object({
            url: z.string().describe("The monitored URL")
          }),
          execute: async ({ url }) => {
            try {
              const normalized = normalizeUrl(url);
              if (!this.isMonitored(normalized)) {
                return `${normalized} was not being monitored.`;
              }
              await this.probeFor(normalized).stop();
              this.sql`DELETE FROM endpoints WHERE url = ${normalized}`;
              return `Stopped monitoring ${normalized}.`;
            } catch (err) {
              console.error("removeEndpoint failed:", err);
              return { error: errorMessage(err) };
            }
          }
        })
      },
      // Llama 3.3 on Workers AI tends to call the same tool over and over
      // instead of answering. Once a step has run tools, give the next step
      // no tools, so the model has to reply in text using the results.
      prepareStep: ({ steps }) => {
        const last = steps.at(-1);
        if (last && last.toolCalls.length > 0) {
          return { activeTools: [] };
        }
        return {};
      },
      stopWhen: stepCountIs(5),
      abortSignal: options?.abortSignal,
      onError: ({ error }) => {
        console.error("[agent] streamText error:", error);
      }
    });

    return result.toUIMessageStreamResponse();
  }
}

export default {
  async fetch(request: Request, env: Env) {
    return (
      (await routeAgentRequest(request, env)) ||
      new Response("Not found", { status: 404 })
    );
  }
} satisfies ExportedHandler<Env>;