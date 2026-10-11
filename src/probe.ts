import { DurableObject } from "cloudflare:workers";

// One Probe instance per monitored endpoint (named by its URL).
// It checks the endpoint, stores the result in its own SQLite table,
// and uses a Durable Object alarm to wake itself up for the next check.

export type CheckResult = {
  ts: number; // when the check started (ms since epoch)
  status: number | null; // HTTP status, null if the request failed
  latencyMs: number | null; // time until response headers arrived
  ok: boolean; // status < 400
  error: string | null; // timeout / network error message
};

export type ProbeConfig = {
  url: string;
  intervalSec: number;
  active: boolean;
};

const MAX_ROWS = 500; // keep the last 500 checks per endpoint
const TIMEOUT_MS = 10_000;

type CheckRow = {
  ts: number;
  status: number | null;
  latency_ms: number | null;
  ok: number;
  error: string | null;
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
  }

  // Start (or restart) monitoring. Runs one check immediately and
  // schedules the next one.
  async configure(url: string, intervalSec: number): Promise<CheckResult> {
    const config: ProbeConfig = { url, intervalSec, active: true };
    await this.ctx.storage.put("config", config);
    const first = await this.runCheck(config);
    await this.ctx.storage.setAlarm(Date.now() + intervalSec * 1000);
    return first;
  }

  async stop(): Promise<void> {
    const config = await this.getConfig();
    if (config) await this.ctx.storage.put("config", { ...config, active: false });
    await this.ctx.storage.deleteAlarm();
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

  // Recent checks plus simple stats, newest first.
  async getSummary(limit = 20) {
    const config = await this.getConfig();
    const rows = this.ctx.storage.sql
      .exec<CheckRow>(
        `SELECT ts, status, latency_ms, ok, error
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

    return {
      config,
      checksShown: checks.length,
      uptimePct: checks.length
        ? Math.round((okCount / checks.length) * 1000) / 10
        : null,
      avgLatencyMs: latencies.length
        ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
        : null,
      checks
    };
  }

  private async runCheck(config: ProbeConfig): Promise<CheckResult> {
    const start = Date.now();
    let result: CheckResult;

    try {
      const res = await fetch(config.url, {
        method: "GET",
        redirect: "follow",
        signal: AbortSignal.timeout(TIMEOUT_MS),
        headers: { "user-agent": "cf-ai-oncall-probe/0.1" }
      });
      // fetch resolves when headers arrive, so this is time-to-headers.
      const latencyMs = Date.now() - start;
      await res.body?.cancel(); // we don't need the body, free the connection
      result = {
        ts: start,
        status: res.status,
        latencyMs,
        ok: res.status < 400,
        error: null
      };
    } catch (err) {
      const message =
        err instanceof Error
          ? err.name === "TimeoutError"
            ? `timeout after ${TIMEOUT_MS}ms`
            : err.message
          : String(err);
      result = { ts: start, status: null, latencyMs: null, ok: false, error: message };
    }

    this.ctx.storage.sql.exec(
      `INSERT INTO checks (ts, status, latency_ms, ok, error) VALUES (?, ?, ?, ?, ?)`,
      result.ts,
      result.status,
      result.latencyMs,
      result.ok ? 1 : 0,
      result.error
    );
    // Trim old rows so storage doesn't grow forever.
    this.ctx.storage.sql.exec(
      `DELETE FROM checks WHERE id <= (SELECT MAX(id) FROM checks) - ?`,
      MAX_ROWS
    );

    return result;
  }
}