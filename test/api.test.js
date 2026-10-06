import test from "node:test";
import assert from "node:assert/strict";

delete process.env.GEMINI_API_KEY;
for (const k of ["UPSTASH_REDIS_REST_URL", "UPSTASH_REDIS_REST_TOKEN", "KV_REST_API_URL", "KV_REST_API_TOKEN"]) delete process.env[k];
process.env.RATE_LIMIT_PER_HOUR = "3";
process.env.RATE_LIMIT_PER_DAY = "50";
process.env.RATE_LIMIT_BURST = "100";

const net = await import("../api/_lib/net.js");
const api = await import("../api/scan.js");

let requests = 0;
net._setLookup(async (h) => (h.includes("private") ? [{ address: "192.168.0.10", family: 4 }] : [{ address: "93.184.215.14", family: 4 }]));
net._setLegacyTls(async () => ({ tested: false }));
net._setDns({ txt: async () => { throw Object.assign(new Error(), { code: "ENODATA" }); }, mx: async () => { throw Object.assign(new Error(), { code: "ENODATA" }); } });
net._setRequest(async (url) => {
  requests++;
  const tls = url.startsWith("https") ? { authorized: true, protocol: "TLSv1.3", validFrom: new Date(Date.now() - 864e6).toUTCString(), validTo: new Date(Date.now() + 864e7).toUTCString() } : null;
  if (url.startsWith("http://")) return { url, status: 301, headers: { location: url.replace("http://", "https://") }, setCookies: [], body: "", tls };
  if (new URL(url).pathname === "/") return { url, status: 200, headers: { "content-type": "text/html" }, setCookies: [], body: "<html></html>", tls };
  return { url, status: 404, headers: {}, setCookies: [], body: "", tls };
});

const post = (body, { ip = "1.1.1.1", origin } = {}) => api.POST(new Request("https://sitesafecheck.com/api/scan", {
  method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": ip, host: "sitesafecheck.com", ...(origin ? { origin } : {}) }, body: typeof body === "string" ? body : JSON.stringify(body),
}));

test("GET reports status without secrets", async () => {
  process.env.GEMINI_API_KEY = "secret-key-123";
  const j = await (await api.GET()).json();
  assert.equal(j.ai, true); assert.equal(j.persistent, false);
  assert.ok(!JSON.stringify(j).includes("secret-key-123"));
  delete process.env.GEMINI_API_KEY;
});

test("requires the ownership/authorization checkbox", async () => {
  const r = await post({ url: "example.com" });
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "authorization_required");
});

test("rejects localhost, private IPs, metadata, internal names, private DNS answers", async () => {
  for (const url of ["localhost", "http://127.0.0.1", "169.254.169.254", "http://[::1]/", "metadata.google.internal", "http://10.0.0.1/", "0x7f000001", "example.com:8080"]) {
    const r = await post({ url, authorized: true }, { ip: "9.9.9.9" });
    assert.equal(r.status, 400, url);
    assert.equal((await r.json()).error, "blocked_target", url);
  }
  const r = await post({ url: "private-dns.com", authorized: true }, { ip: "9.9.9.8" });
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "blocked_target");
});

test("bad JSON, honeypot, oversize body, cross-site origin are refused", async () => {
  assert.equal((await post("{nope")).status, 400);
  assert.equal((await post({ url: "a.com", authorized: true, company_website: "spam" })).status, 400);
  assert.equal((await post(JSON.stringify({ url: "a.com", authorized: true, pad: "x".repeat(5000) }))).status, 413);
  assert.equal((await post({ url: "a.com", authorized: true }, { origin: "https://evil.example.net" })).status, 403);
});

test("scans, caches per domain, and rate limits fresh scans per IP", async () => {
  let r = await post({ url: "https://first.com/", authorized: true }, { ip: "2.2.2.2", origin: "https://sitesafecheck.com" });
  assert.equal(r.status, 200);
  let j = await r.json();
  assert.equal(j.cached, false);
  assert.equal(j.report.host, "first.com");
  assert.ok(j.report.score.grade);
  const before = requests;
  j = await (await post({ url: "first.com", authorized: true }, { ip: "2.2.2.2" })).json();
  assert.equal(j.cached, true);
  assert.equal(requests, before, "cache hit makes no outbound requests");
  for (const d of ["second.com", "third.com"]) assert.equal((await post({ url: d, authorized: true }, { ip: "2.2.2.2" })).status, 200);
  r = await post({ url: "fourth.com", authorized: true }, { ip: "2.2.2.2" });
  assert.equal(r.status, 429);
  assert.ok(r.headers.get("retry-after"));
  assert.equal((await post({ url: "fourth.com", authorized: true }, { ip: "3.3.3.3" })).status, 200, "other visitors unaffected");
  assert.equal((await post({ url: "first.com", authorized: true }, { ip: "2.2.2.2" })).status, 200, "cached domains still load for a limited IP");
});
