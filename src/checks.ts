// One full network check of a URL: DNS, HTTP (with redirect chain),
// rate-limit headers, security headers, edge/CDN info and block hints.
// Used by the Probe (scheduled checks) and by the inspectEndpoint tool.

export type DnsInfo = {
  resolver: "1.1.1.1";
  status: string; // NOERROR, NXDOMAIN, SERVFAIL, ...
  ms: number;
  a: string[]; // IPv4 addresses
  aaaa: string[]; // IPv6 addresses
  cname: string[]; // CNAME chain, if any
  error: string | null;
};

export type RedirectHop = { url: string; status: number; location: string };

export type RateLimitInfo = {
  limit: number | null;
  remaining: number | null;
  resetSec: number | null; // seconds until the quota resets
  retryAfterSec: number | null; // from Retry-After
  rateLimited: boolean; // 429, or no quota left
  headerStyle: string | null; // which header family we found
};

export type SecurityHeaders = {
  hsts: boolean;
  csp: boolean;
  xFrameOptions: boolean;
  xContentTypeOptions: boolean;
  referrerPolicy: boolean;
  missing: string[];
};

export type EdgeInfo = {
  server: string | null;
  cfRay: string | null;
  cacheStatus: string | null;
  via: string | null;
  ageSec: number | null;
};

export type CheckDetails = {
  dns: DnsInfo | null;
  redirects: RedirectHop[];
  finalUrl: string | null;
  rateLimit: RateLimitInfo | null;
  security: SecurityHeaders | null;
  edge: EdgeInfo | null;
  blockedHint: string | null;
};

export type FullCheck = {
  ts: number; // when the check started (ms since epoch)
  status: number | null; // final HTTP status, null if the request failed
  latencyMs: number | null; // until the final response's headers arrived
  ok: boolean;
  error: string | null;
  details: CheckDetails;
};

const TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 5;
const USER_AGENT = "cf-ai-oncall-probe/0.2";

// ---------- DNS (Cloudflare 1.1.1.1 DNS-over-HTTPS, JSON API) ----------

const DNS_STATUS: Record<number, string> = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED"
};

type DohAnswer = { name: string; type: number; TTL: number; data: string };
type DohResponse = { Status: number; Answer?: DohAnswer[] };

function isIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

async function dohQuery(host: string, type: "A" | "AAAA"): Promise<DohResponse> {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`;
  const res = await fetch(url, {
    headers: { accept: "application/dns-json" },
    signal: AbortSignal.timeout(5_000)
  });
  if (!res.ok) throw new Error(`DoH ${type} query returned HTTP ${res.status}`);
  return (await res.json()) as DohResponse;
}

export async function lookupDns(host: string): Promise<DnsInfo> {
  const start = Date.now();
  try {
    const [a, aaaa] = await Promise.all([dohQuery(host, "A"), dohQuery(host, "AAAA")]);
    const answers = [...(a.Answer ?? []), ...(aaaa.Answer ?? [])];
    const unique = (xs: string[]) => [...new Set(xs)];
    return {
      resolver: "1.1.1.1",
      status: DNS_STATUS[a.Status] ?? `code ${a.Status}`,
      ms: Date.now() - start,
      a: unique(answers.filter((x) => x.type === 1).map((x) => x.data)),
      aaaa: unique(answers.filter((x) => x.type === 28).map((x) => x.data)),
      cname: unique(answers.filter((x) => x.type === 5).map((x) => x.data)),
      error: null
    };
  } catch (err) {
    return {
      resolver: "1.1.1.1",
      status: "ERROR",
      ms: Date.now() - start,
      a: [],
      aaaa: [],
      cname: [],
      error: err instanceof Error ? err.message : String(err)
    };
  }
}

// ---------- Header parsing (pure functions, unit-tested) ----------

function toNumber(value: string | null | undefined): number | null {
  if (value == null || value.trim() === "") return null;
  const n = Number(value.trim());
  return Number.isFinite(n) ? n : null;
}

// Retry-After is either seconds ("120") or an HTTP date.
export function parseRetryAfter(value: string | null, nowMs: number): number | null {
  if (!value) return null;
  const secs = toNumber(value);
  if (secs !== null) return Math.max(0, Math.round(secs));
  const date = Date.parse(value);
  return Number.isNaN(date) ? null : Math.max(0, Math.round((date - nowMs) / 1000));
}

// Reset is usually "seconds until reset", but some APIs (e.g. GitHub) send a
// unix timestamp. Anything that looks like a timestamp gets converted.
function normalizeReset(value: number | null, nowMs: number): number | null {
  if (value === null) return null;
  if (value > 1_000_000_000) return Math.max(0, Math.round(value - nowMs / 1000));
  return Math.max(0, Math.round(value));
}

export function parseRateLimit(
  headers: Headers,
  status: number,
  nowMs: number
): RateLimitInfo | null {
  let limit: number | null = null;
  let remaining: number | null = null;
  let reset: number | null = null;
  let headerStyle: string | null = null;

  // Separate headers: X-RateLimit-*, RateLimit-*, X-Rate-Limit-*
  for (const prefix of ["x-ratelimit-", "ratelimit-", "x-rate-limit-"]) {
    const l = toNumber(headers.get(`${prefix}limit`));
    const r = toNumber(headers.get(`${prefix}remaining`));
    const s = toNumber(headers.get(`${prefix}reset`));
    if (l !== null || r !== null || s !== null) {
      limit = l;
      remaining = r;
      reset = s;
      headerStyle = `${prefix}*`;
      break;
    }
  }

  // Combined IETF-style header: "limit=100, remaining=40, reset=30"
  // or the newer draft: '"default";r=40;t=30'
  const combined = headers.get("ratelimit");
  if (!headerStyle && combined) {
    const pick = (re: RegExp) => toNumber(combined.match(re)?.[1]);
    limit = pick(/(?:^|[\s,;])limit=(\d+)/i);
    remaining = pick(/(?:^|[\s,;])(?:remaining|r)=(\d+)/i);
    reset = pick(/(?:^|[\s,;])(?:reset|t)=(\d+)/i);
    headerStyle = "ratelimit";
  }

  const retryAfterSec = parseRetryAfter(headers.get("retry-after"), nowMs);
  if (!headerStyle && retryAfterSec === null && status !== 429) return null;

  return {
    limit,
    remaining,
    resetSec: normalizeReset(reset, nowMs),
    retryAfterSec,
    rateLimited: status === 429 || remaining === 0,
    headerStyle
  };
}

export function parseSecurityHeaders(headers: Headers): SecurityHeaders {
  const checks: [keyof Omit<SecurityHeaders, "missing">, string][] = [
    ["hsts", "strict-transport-security"],
    ["csp", "content-security-policy"],
    ["xFrameOptions", "x-frame-options"],
    ["xContentTypeOptions", "x-content-type-options"],
    ["referrerPolicy", "referrer-policy"]
  ];
  const result = { missing: [] as string[] } as SecurityHeaders;
  for (const [key, header] of checks) {
    const present = headers.has(header);
    result[key] = present as never;
    if (!present) result.missing.push(header);
  }
  return result;
}

export function parseEdge(headers: Headers): EdgeInfo {
  return {
    server: headers.get("server"),
    cfRay: headers.get("cf-ray"),
    cacheStatus: headers.get("cf-cache-status") ?? headers.get("x-cache"),
    via: headers.get("via"),
    ageSec: toNumber(headers.get("age"))
  };
}

// Recognise the common ways sites block automated traffic.
export function detectBlock(
  status: number,
  headers: Headers,
  originalUrl: string,
  finalUrl: string
): string | null {
  if (status === 999) {
    return "HTTP 999: non-standard code (used by LinkedIn) to block automated requests";
  }
  if (headers.get("cf-mitigated") === "challenge") {
    return "Cloudflare bot challenge: the site wants a real browser";
  }
  if (status === 429) return "rate limited (HTTP 429)";
  const loginLike = /(authwall|login|signin|sign-in|captcha|challenge)/i;
  if (!loginLike.test(originalUrl) && loginLike.test(finalUrl)) {
    return `redirected to a login/challenge page: ${finalUrl}`;
  }
  return null;
}

// ---------- The full check ----------

export async function runFullCheck(url: string): Promise<FullCheck> {
  const ts = Date.now();
  const host = new URL(url).hostname;
  const details: CheckDetails = {
    dns: null,
    redirects: [],
    finalUrl: null,
    rateLimit: null,
    security: null,
    edge: null,
    blockedHint: null
  };

  // DNS runs alongside HTTP so it doesn't add to the check's latency.
  const dnsPromise = isIpLiteral(host) ? Promise.resolve(null) : lookupDns(host);

  let status: number | null = null;
  let latencyMs: number | null = null;
  let error: string | null = null;

  try {
    const signal = AbortSignal.timeout(TIMEOUT_MS);
    let current = url;
    let res: Response | null = null;

    // Follow redirects by hand so we can record every hop.
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      res = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal,
        headers: { "user-agent": USER_AGENT }
      });
      const location = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && location) {
        details.redirects.push({ url: current, status: res.status, location });
        await res.body?.cancel();
        current = new URL(location, current).toString();
        res = null;
        continue;
      }
      break;
    }

    if (!res) throw new Error(`too many redirects (more than ${MAX_REDIRECTS})`);

    latencyMs = Date.now() - ts;
    status = res.status;
    details.finalUrl = current;
    details.rateLimit = parseRateLimit(res.headers, res.status, Date.now());
    details.security = url.startsWith("https:") ? parseSecurityHeaders(res.headers) : null;
    details.edge = parseEdge(res.headers);
    details.blockedHint = detectBlock(res.status, res.headers, url, current);
    await res.body?.cancel(); // we only need headers
  } catch (err) {
    error =
      err instanceof Error
        ? err.name === "TimeoutError"
          ? `timeout after ${TIMEOUT_MS}ms`
          : err.message
        : String(err);
  }

  details.dns = await dnsPromise;
  if (details.dns?.status === "NXDOMAIN") {
    error = error ?? "domain does not exist (NXDOMAIN)";
  }

  return {
    ts,
    status,
    latencyMs,
    ok: status !== null && status < 400 && error === null,
    error,
    details
  };
}