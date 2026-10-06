// End-to-end scan with every network call mocked (HTTP, DNS, TLS probe).
import test from "node:test";
import assert from "node:assert/strict";
import { _setLookup, _setRequest, _setLegacyTls, _setDns } from "../api/_lib/net.js";
import { collect, buildReport, orgDomain } from "../api/_lib/scan.js";

delete process.env.GEMINI_API_KEY;
const NOW = Date.parse("2026-10-05T12:00:00Z");
const tls = { authorized: true, error: "", protocol: "TLSv1.3", validFrom: new Date(NOW - 30 * 864e5).toUTCString(), validTo: new Date(NOW + 60 * 864e5).toUTCString(), issuer: "Let's Encrypt", altNames: ["shop.com", "www.shop.com"] };
const R = (url, status, headers = {}, body = "", extra = {}) => ({ url, status, headers, setCookies: [], body, bodyBytes: Buffer.from(body), tls: url.startsWith("https") ? tls : null, ms: 50, ...extra });

function mockSite(routes, dns = {}) {
  const calls = [];
  _setLookup(async () => [{ address: "93.184.215.14", family: 4 }]);
  _setLegacyTls(async () => ({ tested: true, accepted: false }));
  _setRequest(async (url) => {
    calls.push(url);
    const u = new URL(url);
    for (const [re, fn] of routes) if (re.test(url)) return fn(url);
    if (/sitesafecheck-not-a-real-page/.test(u.pathname)) return R(url, 404, { "content-type": "text/html" }, "<h1>Not found</h1>");
    return R(url, 404, { "content-type": "text/html" }, "<h1>Not found</h1>");
  });
  _setDns({
    txt: async (name) => { if (dns[name]) return dns[name]; const e = new Error("nodata"); e.code = "ENODATA"; throw e; },
    mx: async (name) => { if (dns["mx:" + name]) return dns["mx:" + name]; const e = new Error("nodata"); e.code = "ENODATA"; throw e; },
  });
  return calls;
}

test("well-configured site grades A with real evidence", async () => {
  const good = { "content-type": "text/html", "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "permissions-policy": "camera=()", server: "nginx" };
  mockSite([
    [/^https:\/\/shop\.com\/$/, (u) => R(u, 200, good, "<html><body>Hi</body></html>", { setCookies: ["sid=1; Secure; HttpOnly; SameSite=Lax"] })],
    [/^http:\/\/shop\.com\/$/, (u) => R(u, 301, { location: "https://shop.com/" })],
    [/security\.txt$/, (u) => R(u, 200, { "content-type": "text/plain" }, "Contact: mailto:sec@shop.com\n")],
  ], { "shop.com": ["v=spf1 include:_spf.google.com -all"], "_dmarc.shop.com": ["v=DMARC1; p=reject"], "google._domainkey.shop.com": ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"], "mx:shop.com": [{ exchange: "aspmx.l.google.com", priority: 1 }] });
  const raw = await collect("https://shop.com", { now: NOW });
  const rep = await buildReport(raw, { useAi: false, now: NOW });
  assert.equal(rep.score.grade, "A", JSON.stringify(rep.findings.filter((f) => f.status === "fail" || f.status === "warn")));
  assert.equal(rep.score.score, 100);
  assert.equal(rep.meta.emailProviders[0], "Google Workspace");
  assert.ok(rep.findings.every((f) => f.title && f.category && f.evidence));
  assert.match(rep.summary, /can't prove a site is secure/);
  assert.equal(rep.ai.used, false);
});

test("weak WordPress site: real failures, exposed .env referred out, version banner, dir listing", async () => {
  const calls = mockSite([
    [/^https:\/\/www\.weak\.com\/$/, (u) => R(u, 200, { "content-type": "text/html", server: "Apache/2.4.29 (Ubuntu)", "x-powered-by": "PHP/7.2.24" }, '<html><link rel="stylesheet" href="/wp-content/themes/a/style.css"><script src="http://cdn.old.com/jquery.js"></script></html>', { setCookies: ["PHPSESSID=abc; path=/"] })],
    [/^https:\/\/weak\.com\/$/, (u) => R(u, 301, { location: "https://www.weak.com/" })],
    [/^http:\/\/weak\.com\/$/, (u) => R(u, 200, { "content-type": "text/html" }, "<html>insecure</html>", { tls: null })],
    [/\/\.env$/, (u) => R(u, 200, { "content-type": "text/plain" }, "DB_PASSWORD=hunter2\nAPP_KEY=x\n")],
    [/\/wp-content\/uploads\/$/, (u) => R(u, 200, { "content-type": "text/html" }, "<title>Index of /wp-content/uploads</title>")],
  ], { "weak.com": ["v=spf1 +all"] });
  const raw = await collect("weak.com", { now: NOW });
  const rep = await buildReport(raw, { useAi: false, now: NOW });
  const get = (id) => rep.findings.find((f) => f.id === id);
  assert.equal(get("exposed_files").status, "fail");
  assert.equal(get("exposed_files").fixBy, "refer");
  assert.match(get("exposed_files").fix, /urgently/);
  assert.ok(!JSON.stringify(rep).includes("hunter2"), "secret contents must never appear in a report");
  assert.equal(get("directory_listing").status, "fail");
  assert.equal(get("server_banner").status, "fail");
  assert.equal(get("http_redirect").status, "fail");
  assert.equal(get("mixed_content").status, "fail");
  assert.equal(get("spf").severity, "high");
  assert.equal(get("dmarc").status, "fail");
  assert.equal(get("dkim").status, "info");
  assert.equal(get("cookie_httponly").status, "fail");
  assert.equal(rep.meta.cms, "WordPress");
  assert.ok(rep.score.score <= 69 && rep.score.capped !== undefined);
  assert.equal(rep.score.grade, "F");
  // probes went to the final origin, including the WordPress uploads folder
  assert.ok(calls.includes("https://www.weak.com/wp-content/uploads/"));
  assert.ok(calls.some((u) => /sitesafecheck-not-a-real-page-[0-9a-f]{12}\.txt$/.test(u)), "soft-404 baseline requested");
});

test("redirect to a different domain: no probes against the other domain", async () => {
  const calls = mockSite([
    [/^https:\/\/old\.com\/$/, (u) => R(u, 301, { location: "https://newbrand.com/" })],
    [/^https:\/\/newbrand\.com\/$/, (u) => R(u, 200, { "content-type": "text/html" }, "<html></html>")],
    [/^http:\/\/old\.com\/$/, (u) => R(u, 301, { location: "https://old.com/" })],
  ]);
  const raw = await collect("old.com", { now: NOW });
  assert.equal(raw.meta.offsite, true);
  assert.ok(!calls.some((u) => u.includes("newbrand.com/.env")));
  assert.equal(raw.findings.find((f) => f.id === "exposed_files").status, "info");
});

test("blocked and unreachable targets throw clear errors", async () => {
  _setLookup(async () => [{ address: "10.1.2.3", family: 4 }]);
  await assert.rejects(collect("intranet-ish.com"), (e) => e.code === "blocked_target");
  await assert.rejects(collect("http://localhost:8080"), (e) => e.code === "blocked_target");
  _setLookup(async () => { throw Object.assign(new Error("nf"), { code: "ENOTFOUND" }); });
  await assert.rejects(collect("doesnotexist-zzzz.com"), (e) => e.code === "dns_not_found");
  mockSite([[/./, () => { throw Object.assign(new Error("refused"), { code: "connect_failed" }); }]]);
  await assert.rejects(collect("down.com"), (e) => e.code === "unreachable");
});

test("DMARC falls back to the organizational domain for subdomains", async () => {
  mockSite([[/^https:\/\/shop\.brand\.com\/$/, (u) => R(u, 200, { "content-type": "text/html" }, "<html></html>")], [/^http:/, (u) => R(u, 301, { location: "https://shop.brand.com/" })]], { "_dmarc.brand.com": ["v=DMARC1; p=reject"] });
  const raw = await collect("shop.brand.com", { now: NOW });
  const d = raw.findings.find((f) => f.id === "dmarc");
  assert.equal(d.status, "pass");
  assert.match(d.evidence, /inherited/);
  assert.equal(orgDomain("a.b.co.uk"), "b.co.uk");
  assert.equal(orgDomain("www.shop.com"), "shop.com");
});
