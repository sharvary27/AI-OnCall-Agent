import { createWorkersAI } from "workers-ai-provider";
import { callable, routeAgentRequest, type Schedule } from "agents";
import { getSchedulePrompt, scheduleSchema } from "agents/schedule";
import { AIChatAgent, type OnChatMessageOptions } from "@cloudflare/ai-chat";
import {
  convertToModelMessages,
  pruneMessages,
  stepCountIs,
  streamText,
  wrapLanguageModel,
  type LanguageModelMiddleware
} from "ai";
import { z } from "zod";
const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
 

const SYSTEM_PROMPT = `You are an on-call engineer assistant for the user's deployed services.
You help them monitor endpoints, investigate outages, latency spikes and rate limiting,
and explain what happened in plain language.
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

export class ChatAgent extends AIChatAgent<Env> {
  maxPersistedMessages = 100;
  chatRecovery = true;
  // Wait for MCP connections to be re-established after hibernation before
  // processing a message, so MCP tools aren't intermittently missing.
  waitForMcpConnections = true;

  onStart() {
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

  @callable()
  async addServer(name: string, url: string) {
    return await this.addMcpServer(name, url);
  }

  @callable()
  async removeServer(serverId: string) {
    await this.removeMcpServer(serverId);
  }

  async onChatMessage(_onFinish: unknown, options?: OnChatMessageOptions) {
    const mcpTools = this.mcp.getAITools();
    const workersai = createWorkersAI({ binding: this.env.AI });

    const result = streamText({
      model: wrapLanguageModel({
        model: workersai(MODEL, {
          sessionAffinity: this.sessionAffinity
        }),
        middleware: dedupeDeltas
      }),
      system: SYSTEM_PROMPT,
      messages: pruneMessages({
        messages: await convertToModelMessages(this.messages),
        toolCalls: "before-last-2-messages",
        reasoning: "before-last-message"
      }),
      tools :{
        ...this.mcp.getAITools()
      },
      stopWhen: stepCountIs(10),
      abortSignal: options?.abortSignal,
      // TEMP debug: confirm each text piece arrives once. Remove before committing.
      // onChunk: ({ chunk }) => { // debug: log each chunk as it arrives
      //   if (chunk.type === "text-delta") {
      //     console.log("DELTA:", JSON.stringify(chunk.text));
      //   }
      // }
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