import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { getAgentByName } from "agents";
import { runFullCheck } from "./checks";
import {
  DIAGNOSIS_SYSTEM_PROMPT,
  buildEvidence,
  fallbackDiagnosis,
  type EndpointContext,
  type Incident,
  type InvestigationParams
} from "./Incident";

const MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";

// Started by a Probe when an alert opens. Each step.do() is durable:
// its result is saved, and if a later step fails, Cloudflare retries
// from that step instead of re-running the whole investigation.
export class InvestigationWorkflow extends WorkflowEntrypoint<Env, InvestigationParams> {
  async run(event: WorkflowEvent<InvestigationParams>, step: WorkflowStep) {
    const params = event.payload;

    // 1. Give it a moment: many problems are blips that fix themselves.
    await step.sleep("wait to rule out a blip", "30 seconds");

    // 2. Fresh look at the endpoint right now.
    const recheck = await step.do(
      "recheck endpoint",
      { retries: { limit: 2, delay: "5 seconds", backoff: "constant" }, timeout: "30 seconds" },
      () => runFullCheck(params.url)
    );

    // 3. What does "normal" look like, and what happened recently?
    const context = await step.do("gather history", async (): Promise<EndpointContext> => {
      const probe = this.env.Probe.get(this.env.Probe.idFromName(params.url));
      const summary = await probe.getSummary(10);
      return {
        baseline: summary.baseline,
        uptimePct: summary.uptimePct,
        openAnomalies: summary.openAnomalies,
        checks: summary.checks
      };
    });

    const evidence = buildEvidence(params, recheck, context, Date.now());

    // 4. Ask Llama 3.3 for a diagnosis. Non-streaming, so the doubled-delta
    //    streaming bug doesn't apply here. Retried with backoff if the call fails.
    let diagnosis: string;
    try {
      diagnosis = await step.do(
        "diagnose with Llama 3.3",
        { retries: { limit: 3, delay: "10 seconds", backoff: "exponential" }, timeout: "2 minutes" },
        async () => {
          const out = (await this.env.AI.run(MODEL, {
            messages: [
              { role: "system", content: DIAGNOSIS_SYSTEM_PROMPT },
              { role: "user", content: JSON.stringify(evidence) }
            ],
            max_tokens: 400
          })) as { response?: string };
          if (!out.response?.trim()) throw new Error("empty diagnosis from model");
          return out.response.trim();
        }
      );
    } catch {
      // All retries failed: still report the raw facts rather than nothing.
      diagnosis = fallbackDiagnosis(evidence);
    }

    const incident: Incident = {
      id: event.instanceId,
      url: params.url,
      type: params.anomaly.type,
      severity: params.anomaly.severity,
      alertMessage: params.anomaly.message,
      openedAt: params.openedAt,
      createdAt: Date.now(),
      stillOpen: evidence.stillOpenAfterRecheck,
      recheck: {
        status: recheck.status,
        latencyMs: recheck.latencyMs,
        ok: recheck.ok,
        error: recheck.error
      },
      diagnosis
    };

    // 5. Hand the incident to the chat agent: it stores it and posts it in chat.
    await step.do(
      "report to chat",
      { retries: { limit: 3, delay: "5 seconds", backoff: "exponential" } },
      async () => {
        const agent = await getAgentByName(this.env.ChatAgent, params.agentName);
        await agent.reportIncident(incident);
        return incident.id;
      }
    );

    return incident;
  }
}