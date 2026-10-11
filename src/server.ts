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

// The Worker entry must export every Durable Object class.
export { Probe } from "./probe";

const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";

const SYSTEM_PROMPT = `You are an on-call engineer assistant for the user's deployed services.
You help them monitor endpoints, investigate outages, latency spikes and rate limiting,
and explain what happened in plain language.

Tools:
- addEndpoint: start monitoring a URL.
- listEndpoints: see everything being monitored and its latest check.
- getEndpointStatus: recent checks, uptime and average latency for one URL.
- removeEndpoint: stop monitoring a URL.

Be direct and concise. Only state facts you got from a tool result; if you don't have
data yet, say so instead of guessing.`;

// Workers AI + Llama 3.3 (workers-ai-provider 3.3.1) currently emits every
// text delta twice. This middleware drops the second copy of each pair, so
// genuine repeats (e.g. "ha", "ha") still come through.
const dedupeDeltas: LanguageModelMiddleware = {
  specificationVersion: "v3",
  wrapStream: async ({ doStream }) => {
    const { stream, ...rest } = await doStream();
    let last: string | null = null;
    let skippedLast = false;
    const fixed = stream.pipeThrough(
      new TransformStream({
        transform(part, controller) {
          if (part.type === "text-delta") {
            if (part.delta === last && !skippedLast) {
              skippedLast = true; // duplicate, drop it
              return;
            }
            last = part.delta;
            skippedLast = false;
          } else {
            last = null;
            skippedLast = false;
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
            intervalSeconds: z.coerce
              .number()
              .int()
              .min(60)
              .max(3600)
              .optional()
              .describe("How often to check, 60 to 3600 seconds. Defaults to 300.")
          }),
          execute: async ({ url, intervalSeconds }) => {
            const normalized = normalizeUrl(url);
            const interval = intervalSeconds ?? 300;
            const firstCheck = await this.probeFor(normalized).configure(normalized, interval);
            this.sql`INSERT OR REPLACE INTO endpoints (url, interval_sec, added_at)
                     VALUES (${normalized}, ${interval}, ${Date.now()})`;
            return { monitoring: normalized, intervalSeconds: interval, firstCheck };
          }
        }),

        listEndpoints: tool({
          description: "List every monitored endpoint with its most recent check.",
          inputSchema: z.object({}),
          execute: async () => {
            const rows = this.sql<EndpointRow>`SELECT * FROM endpoints ORDER BY added_at`;
            if (rows.length === 0) return "No endpoints are being monitored yet.";
            return Promise.all(
              rows.map(async (r) => {
                const summary = await this.probeFor(r.url).getSummary(1);
                return {
                  url: r.url,
                  intervalSeconds: r.interval_sec,
                  latest: summary.checks[0] ?? null
                };
              })
            );
          }
        }),

        getEndpointStatus: tool({
          description:
            "Get recent checks, uptime percentage and average latency for one monitored endpoint.",
          inputSchema: z.object({
            url: z.string().describe("The monitored URL"),
            limit: z.coerce
              .number()
              .int()
              .min(1)
              .max(100)
              .optional()
              .describe("How many recent checks to include. Defaults to 20.")
          }),
          execute: async ({ url, limit }) => {
            const normalized = normalizeUrl(url);
            if (!this.isMonitored(normalized)) {
              return `${normalized} is not being monitored. Use addEndpoint first.`;
            }
            return this.probeFor(normalized).getSummary(limit ?? 20);
          }
        }),

        removeEndpoint: tool({
          description: "Stop monitoring an endpoint.",
          inputSchema: z.object({
            url: z.string().describe("The monitored URL")
          }),
          execute: async ({ url }) => {
            const normalized = normalizeUrl(url);
            if (!this.isMonitored(normalized)) {
              return `${normalized} was not being monitored.`;
            }
            await this.probeFor(normalized).stop();
            this.sql`DELETE FROM endpoints WHERE url = ${normalized}`;
            return `Stopped monitoring ${normalized}.`;
          }
        })
      },
      stopWhen: stepCountIs(10),
      abortSignal: options?.abortSignal
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