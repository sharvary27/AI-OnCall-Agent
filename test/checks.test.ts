import { afterEach, describe, expect, it, vi } from "vitest";
import {
  detectBlock,
  parseEdge,
  parseRateLimit,
  parseRetryAfter,
  parseSecurityHeaders,
  runFullCheck
} from "../src/checks";

const NOW = Date.parse("2026-10-11T20:00:00Z");
const H = (o: Record<string, string>) => new Headers(o);

describe("Retry-After", () => {
  it("parses seconds", () => expect(parseRetryAfter("120", NOW)).toBe(120));
  it("parses an HTTP date", () =>
    expect(parseRetryAfter("Sun, 11 Oct 2026 20:01:00 GMT", NOW)).toBe(60));
  it("ignores junk", () => expect(parseRetryAfter("soon", NOW)).toBeNull());
});

describe("rate-limit headers", () => {
  it("reads X-RateLimit-* with a unix-timestamp reset (GitHub style)", () => {
    const h = H({
      "x-ratelimit-limit": "60",
      "x-ratelimit-remaining": "0",
      "x-ratelimit-reset": String(NOW / 1000 + 300)
    });
    expect(parseRateLimit(h, 200, NOW)).toEqual({
      limit: 60,
      remaining: 0,
      resetSec: 300,
      retryAfterSec: null,
      rateLimited: true,
      headerStyle: "x-ratelimit-*"
    });
  });

  it("reads RateLimit-* with a seconds reset (IETF style)", () => {
    const h = H({ "ratelimit-limit": "100", "ratelimit-remaining": "42", "ratelimit-reset": "30" });
    expect(parseRateLimit(h, 200, NOW)).toMatchObject({ limit: 100, remaining: 42, resetSec: 30, rateLimited: false });
  });

  it("reads a combined RateLimit header", () => {
    expect(parseRateLimit(H({ ratelimit: "limit=100, remaining=5, reset=12" }), 200, NOW)).toMatchObject({
      limit: 100,
      remaining: 5,
      resetSec: 12
    });
  });

  it("reads the newer r=/t= draft format", () => {
    expect(parseRateLimit(H({ ratelimit: '"default";r=0;t=45' }), 200, NOW)).toMatchObject({
      remaining: 0,
      resetSec: 45,
      rateLimited: true
    });
  });

  it("treats a 429 with only Retry-After as rate limited", () => {
    expect(parseRateLimit(H({ "retry-after": "90" }), 429, NOW)).toMatchObject({
      retryAfterSec: 90,
      rateLimited: true
    });
  });

  it("returns null when there is no rate-limit info", () => {
    expect(parseRateLimit(H({}), 200, NOW)).toBeNull();
  });
});

describe("security and edge headers", () => {
  it("lists missing security headers", () => {
    const s = parseSecurityHeaders(H({ "strict-transport-security": "max-age=1", "x-frame-options": "DENY" }));
    expect(s.hsts).toBe(true);
    expect(s.missing).toEqual(["content-security-policy", "x-content-type-options", "referrer-policy"]);
  });

  it("reads edge / CDN info", () => {
    expect(parseEdge(H({ server: "cloudflare", "cf-ray": "abc-EWR", "cf-cache-status": "HIT", age: "12" }))).toEqual({
      server: "cloudflare",
      cfRay: "abc-EWR",
      cacheStatus: "HIT",
      via: null,
      ageSec: 12
    });
  });
});

describe("block detection", () => {
  it("recognises LinkedIn's 999", () =>
    expect(detectBlock(999, H({}), "https://linkedin.com/in/x", "https://linkedin.com/in/x")).toMatch(/^HTTP 999/));
  it("recognises a Cloudflare challenge", () =>
    expect(detectBlock(403, H({ "cf-mitigated": "challenge" }), "https://a.com", "https://a.com")).toMatch(/^Cloudflare/));
  it("recognises a redirect to a login wall", () =>
    expect(detectBlock(200, H({}), "https://linkedin.com/jobs", "https://linkedin.com/authwall?x=1")).toMatch(/^redirected/));
  it("leaves normal pages alone", () =>
    expect(detectBlock(200, H({}), "https://example.com", "https://example.com/")).toBeNull());
});

// ---------- full check against a fake network ----------

type Route = { status: number; headers?: Record<string, string> };

function fakeNetwork(routes: Record<string, Route>) {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith("https://cloudflare-dns.com/")) {
      const params = new URL(url).searchParams;
      const host = params.get("name");
      if (host === "nope.invalid") return new Response(JSON.stringify({ Status: 3 }));
      const answers =
        params.get("type") === "A"
          ? [
              { name: host, type: 5, TTL: 60, data: "edge.cdn.net." },
              { name: "edge.cdn.net", type: 1, TTL: 60, data: "93.184.215.14" }
            ]
          : [];
      return new Response(JSON.stringify({ Status: 0, Answer: answers }));
    }
    const route = routes[url];
    if (!route) throw new TypeError("fetch failed: getaddrinfo ENOTFOUND");
    expect(init?.redirect).toBe("manual");
    return new Response("body", { status: route.status, headers: route.headers ?? {} });
  });
}

describe("runFullCheck", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("records the redirect chain, rate limit and DNS", async () => {
    fakeNetwork({
      "http://site.test/": { status: 301, headers: { location: "https://site.test/" } },
      "https://site.test/": { status: 302, headers: { location: "/home" } },
      "https://site.test/home": {
        status: 200,
        headers: { "x-ratelimit-limit": "100", "x-ratelimit-remaining": "7", "x-ratelimit-reset": "60" }
      }
    });
    const r = await runFullCheck("http://site.test/");
    expect(r.ok).toBe(true);
    expect(r.status).toBe(200);
    expect(r.details.redirects.map((h) => `${h.status} ${h.url}`)).toEqual([
      "301 http://site.test/",
      "302 https://site.test/"
    ]);
    expect(r.details.finalUrl).toBe("https://site.test/home");
    expect(r.details.rateLimit).toMatchObject({ remaining: 7, resetSec: 60 });
    expect(r.details.dns).toMatchObject({ status: "NOERROR", a: ["93.184.215.14"], cname: ["edge.cdn.net."] });
  });

  it("stops redirect loops", async () => {
    fakeNetwork({ "https://loop.test/": { status: 302, headers: { location: "https://loop.test/" } } });
    const r = await runFullCheck("https://loop.test/");
    expect(r.ok).toBe(false);
    expect(r.error).toBe("too many redirects (more than 5)");
  });

  it("reports 429s as rate limited", async () => {
    fakeNetwork({ "https://api.test/": { status: 429, headers: { "retry-after": "30" } } });
    const r = await runFullCheck("https://api.test/");
    expect(r.ok).toBe(false);
    expect(r.details.rateLimit).toMatchObject({ rateLimited: true, retryAfterSec: 30 });
  });

  it("reports domains that don't exist", async () => {
    fakeNetwork({});
    const r = await runFullCheck("https://nope.invalid/");
    expect(r.ok).toBe(false);
    expect(r.details.dns?.status).toBe("NXDOMAIN");
    expect(r.error).toContain("ENOTFOUND");
  });
});