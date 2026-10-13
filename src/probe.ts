import { DurableObject } from "cloudflare:workers";
import { runFullCheck, type CheckDetails, type FullCheck } from "./checks";
import {
  computeBaseline,
  detectAnomalies,
  diffAnomalies,
  type AnomalyEvent,
  type CheckSample,
  type OpenAnomaly
} from "./detect";
import { shouldInvestigate } from "./Incident";

// One Probe instance per monitored endpoint (named by its URL).
// It runs a full network check, stores the result in its own SQLite table,
// and uses a Durable Object alarm to wake itself up for the next check.

export type ProbeConfig = {
  url: string;
  intervalSec: number;
  active: boolean;
  agentName?: string; // the chat agent to report incidents to
};

const MAX_ROWS = 500; // keep the last 500 checks per endpoint
const MAX_EVENTS = 200; // keep the last 200 alert events
const DETECTION_WINDOW = 30; // checks used for baseline + detection

type EventRow = {
  ts: number;
  kind: "opened" | "resolved";
  type: string;
  severity: string;
  message: string;
};

type CheckRow = {
  ts: number;
  status: number | null;
  latency_ms: number | null;
  ok: number;
  error: string | null;
  details: string | null;
};

export class Probe extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS checks (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         INTEGER NOT NULL,
        status     INTEGER,
        latency_ms INTEGER,
        ok         INTEGER NOT NULL,
        error      TEXT
      )
    `);
    // Schema migration for Probes created before milestone 3:
    // add the details column if it isn't there yet.
    try {
      this.ctx.storage.sql.exec(`ALTER TABLE checks ADD COLUMN details TEXT`);
    } catch {
      // "duplicate column name": already migrated, nothing to do.
    }
    // Alert history: one row when an anomaly opens, one when it resolves.
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS events (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        ts       INTEGER NOT NULL,
        kind     TEXT NOT NULL,
        type     TEXT NOT NULL,
        severity TEXT NOT NULL,
        message  TEXT NOT NULL
      )
    `);
  }

  // Start (or restart) monitoring. Runs one check immediately and
  // schedules the next one.
  async configure(url: string, intervalSec: number, agentName?: string): Promise<FullCheck> {
    const config: ProbeConfig = { url, intervalSec, active: true, agentName };
    await this.ctx.storage.put("config", config);
    const first = await this.runCheck(config);
    await this.ctx.storage.setAlarm(Date.now() + intervalSec * 1000);
    return first;
  }

  async stop(): Promise<void> {
    const config = await this.getConfig();
    if (config) await this.ctx.storage.put("config", { ...config, active: false });
    await this.ctx.storage.deleteAlarm();
    // Stopping monitoring closes any open alerts.
    await this.ctx.storage.put("openAnomalies", []);
  }

  async getOpenAnomalies(): Promise<OpenAnomaly[]> {
    return (await this.ctx.storage.get<OpenAnomaly[]>("openAnomalies")) ?? [];
  }

  // Alert history, newest first.
  async getEvents(limit = 20) {
    return this.ctx.storage.sql
      .exec<EventRow>(
        `SELECT ts, kind, type, severity, message FROM events ORDER BY id DESC LIMIT ?`,
        limit
      )
      .toArray()
      .map((e) => ({ ...e, time: new Date(e.ts).toISOString() }));
  }

  async getConfig(): Promise<ProbeConfig | null> {
    return (await this.ctx.storage.get<ProbeConfig>("config")) ?? null;
  }

  // Called by Cloudflare when the alarm fires.
  async alarm(): Promise<void> {
    const config = await this.getConfig();
    if (!config?.active) return;
    try {
      await this.runCheck(config);
    } finally {
      // Always schedule the next check, even if this one blew up.
      await this.ctx.storage.setAlarm(Date.now() + config.intervalSec * 1000);
    }
  }

  // Recent checks plus simple stats, newest first. Full network details are
  // only included for the latest check, to keep the LLM's input small.
  async getSummary(limit = 20) {
    const config = await this.getConfig();
    const rows = this.ctx.storage.sql
      .exec<CheckRow>(
        `SELECT ts, status, latency_ms, ok, error, details
         FROM checks ORDER BY id DESC LIMIT ?`,
        limit
      )
      .toArray();

    const checks = rows.map((r) => ({
      time: new Date(r.ts).toISOString(),
      status: r.status,
      latencyMs: r.latency_ms,
      ok: r.ok === 1,
      error: r.error
    }));

    const okCount = checks.filter((c) => c.ok).length;
    const latencies = checks
      .map((c) => c.latencyMs)
      .filter((x): x is number => x !== null);

    const latestDetails: CheckDetails | null = rows[0]?.details
      ? (JSON.parse(rows[0].details) as CheckDetails)
      : null;

    const rateLimitedCount = rows.filter((r) => {
      if (r.status === 429) return true;
      if (!r.details) return false;
      return (JSON.parse(r.details) as CheckDetails).rateLimit?.rateLimited === true;
    }).length;

    return {
      config,
      openAnomalies: await this.getOpenAnomalies(),
      baseline: computeBaseline(this.loadSamples(DETECTION_WINDOW)),
      checksShown: checks.length,
      uptimePct: checks.length
        ? Math.round((okCount / checks.length) * 1000) / 10
        : null,
      avgLatencyMs: latencies.length
        ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
        : null,
      rateLimitedCount,
      latestDetails,
      checks
    };
  }

  private async runCheck(config: ProbeConfig): Promise<FullCheck> {
    const result = await runFullCheck(config.url);

    this.ctx.storage.sql.exec(
      `INSERT INTO checks (ts, status, latency_ms, ok, error, details)
       VALUES (?, ?, ?, ?, ?, ?)`,
      result.ts,
      result.status,
      result.latencyMs,
      result.ok ? 1 : 0,
      result.error,
      JSON.stringify(result.details)
    );
    // Trim old rows so storage doesn't grow forever.
    this.ctx.storage.sql.exec(
      `DELETE FROM checks WHERE id <= (SELECT MAX(id) FROM checks) - ?`,
      MAX_ROWS
    );

    await this.runDetection(result.ts);
    return result;
  }

  // Compare the latest checks against this endpoint's normal behaviour,
  // record opened/resolved alerts, and remember what is currently open.
  private async runDetection(now: number): Promise<AnomalyEvent[]> {
    const current = detectAnomalies(this.loadSamples(DETECTION_WINDOW));
    const { open, events } = diffAnomalies(await this.getOpenAnomalies(), current, now);

    for (const e of events) {
      this.ctx.storage.sql.exec(
        `INSERT INTO events (ts, kind, type, severity, message) VALUES (?, ?, ?, ?, ?)`,
        e.ts,
        e.kind,
        e.type,
        e.severity,
        e.message
      );
    }
    if (events.length > 0) {
      this.ctx.storage.sql.exec(
        `DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?`,
        MAX_EVENTS
      );
    }
    await this.ctx.storage.put("openAnomalies", open);
    await this.startInvestigations(events);
    return events;
  }

  // Each newly opened alert gets its own investigation Workflow. A failure to
  // start one must never break monitoring, so errors are only logged.
  private async startInvestigations(events: AnomalyEvent[]): Promise<void> {
    const config = await this.getConfig();
    if (!config?.agentName) return; // nobody to report to

    for (const e of events) {
      if (e.kind !== "opened" || !shouldInvestigate(e.type)) continue;
      try {
        await this.env.INVESTIGATION.create({
          params: {
            url: config.url,
            agentName: config.agentName,
            anomaly: { type: e.type, severity: e.severity, message: e.message },
            openedAt: e.ts
          }
        });
      } catch (err) {
        console.error(`could not start investigation for ${config.url}:`, err);
      }
    }
  }

  // Recent checks as detection input, newest first.
  private loadSamples(limit: number): CheckSample[] {
    return this.ctx.storage.sql
      .exec<CheckRow>(
        `SELECT ts, status, latency_ms, ok, error, details
         FROM checks ORDER BY id DESC LIMIT ?`,
        limit
      )
      .toArray()
      .map((r) => ({
        ts: r.ts,
        status: r.status,
        latencyMs: r.latency_ms,
        ok: r.ok === 1,
        error: r.error,
        details: r.details ? (JSON.parse(r.details) as CheckDetails) : null
      }));
  }
}