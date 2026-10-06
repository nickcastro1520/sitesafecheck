import test from "node:test";
import assert from "node:assert/strict";
import * as C from "../api/_lib/checks.js";

const byId = (list, id) => list.find((f) => f.id === id);

test("headers: all missing", () => {
  const f = C.analyzeHeaders({}, { https: true });
  for (const id of ["hsts", "csp", "x_frame_options", "x_content_type_options", "referrer_policy", "permissions_policy"]) assert.equal(byId(f, id).status, "fail", id);
  assert.equal(byId(f, "hsts").severity, "medium");
  assert.equal(byId(f, "x_content_type_options").severity, "low");
});

test("headers: strong set passes, evidence quotes the real header", () => {
  const f = C.analyzeHeaders({
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin", "permissions-policy": "camera=()",
  }, { https: true });
  assert.ok(f.every((x) => x.status === "pass"), JSON.stringify(f));
  assert.match(byId(f, "hsts").evidence, /max-age=63072000/);
  assert.match(byId(f, "x_frame_options").evidence, /frame-ancestors 'none'/);
});

test("headers: HSTS short / zero, HSTS n/a on http", () => {
  assert.equal(byId(C.analyzeHeaders({ "strict-transport-security": "max-age=86400" }, { https: true }), "hsts").status, "warn");
  assert.equal(byId(C.analyzeHeaders({ "strict-transport-security": "max-age=0" }, { https: true }), "hsts").status, "fail");
  assert.equal(byId(C.analyzeHeaders({}, { https: false }), "hsts").status, "info");
});

test("headers: weak CSP, report-only CSP, CSP without script control", () => {
  assert.equal(byId(C.analyzeHeaders({ "content-security-policy": "default-src 'self' 'unsafe-inline'" }, { https: true }), "csp").status, "warn");
  assert.equal(byId(C.analyzeHeaders({ "content-security-policy": "script-src 'self' 'unsafe-inline' 'nonce-x'" }, { https: true }), "csp").status, "pass");
  assert.equal(byId(C.analyzeHeaders({ "content-security-policy": "script-src *" }, { https: true }), "csp").status, "warn");
  assert.equal(byId(C.analyzeHeaders({ "content-security-policy-report-only": "default-src 'self'" }, { https: true }), "csp").status, "warn");
  assert.equal(byId(C.analyzeHeaders({ "content-security-policy": "upgrade-insecure-requests" }, { https: true }), "csp").status, "warn");
});

test("headers: X-Frame-Options values, referrer policy tokens", () => {
  assert.equal(byId(C.analyzeHeaders({ "x-frame-options": "SAMEORIGIN" }, { https: true }), "x_frame_options").status, "pass");
  assert.equal(byId(C.analyzeHeaders({ "x-frame-options": "ALLOW-FROM https://x.com" }, { https: true }), "x_frame_options").status, "warn");
  assert.equal(byId(C.analyzeHeaders({ "referrer-policy": "unsafe-url" }, { https: true }), "referrer_policy").status, "warn");
  assert.equal(byId(C.analyzeHeaders({ "referrer-policy": "no-referrer, strict-origin-when-cross-origin" }, { https: true }), "referrer_policy").status, "pass");
  assert.equal(byId(C.analyzeHeaders({ "referrer-policy": "bogus" }, { https: true }), "referrer_policy").status, "warn");
  assert.equal(byId(C.analyzeHeaders({ "feature-policy": "camera 'none'" }, { https: true }), "permissions_policy").status, "warn");
});

test("banners: versions fail, bare names pass, build hashes aren't versions", () => {
  assert.equal(C.analyzeBanners({ server: "Apache/2.4.41 (Ubuntu)" }).status, "fail");
  assert.equal(C.analyzeBanners({ server: "nginx/1.18.0", "x-powered-by": "PHP/7.4.3" }).data.items.length, 2);
  assert.equal(C.analyzeBanners({ server: "nginx" }).status, "pass");
  assert.equal(C.analyzeBanners({ server: "cloudflare" }).status, "pass");
  assert.equal(C.analyzeBanners({ server: "Framer/26fa766" }).status, "pass");
  assert.equal(C.analyzeBanners({ "x-powered-by": "Express" }).status, "warn");
  assert.equal(C.analyzeBanners({ "x-aspnet-version": "4.0.30319" }).status, "fail");
  assert.equal(C.analyzeBanners({}, '<meta name="generator" content="WordPress 6.4.2">').status, "warn");
});

test("cms detection", () => {
  assert.equal(C.detectCms('<link href="/wp-content/themes/x/style.css">'), "WordPress");
  assert.equal(C.detectCms('<script src="https://cdn.shopify.com/x.js">'), "Shopify");
  assert.equal(C.detectCms("<html></html>"), "");
});

test("cookies: parse flags; never expose values", () => {
  const c = C.parseSetCookie("PHPSESSID=secretvalue; Path=/; Secure; HttpOnly; SameSite=Lax");
  assert.deepEqual(c, { name: "PHPSESSID", secure: true, httpOnly: true, sameSite: "lax" });
  const f = C.analyzeCookies(["PHPSESSID=secretvalue; path=/", "theme=dark; Secure; SameSite=Lax"], { https: true });
  assert.equal(byId(f, "cookie_secure").status, "fail");
  assert.equal(byId(f, "cookie_secure").severity, "medium");
  assert.equal(byId(f, "cookie_httponly").status, "fail");
  assert.equal(byId(f, "cookie_samesite").status, "warn");
  assert.ok(!JSON.stringify(f).includes("secretvalue"));
});

test("cookies: none set, non-session cookie without HttpOnly is info, SameSite=None without Secure fails", () => {
  assert.equal(C.analyzeCookies([], { https: true })[0].id, "cookies");
  const f = C.analyzeCookies(["prefs=1; Secure; SameSite=Lax"], { https: true });
  assert.equal(byId(f, "cookie_httponly").status, "info");
  assert.equal(byId(C.analyzeCookies(["x=1; SameSite=None"], { https: true }), "cookie_samesite").status, "fail");
});

test("https: healthy cert, expiry windows, short-lived certs, bad cert reasons", () => {
  const now = Date.parse("2026-10-05T00:00:00Z"); const d = 86400000;
  const tls = (from, to, extra = {}) => ({ authorized: true, protocol: "TLSv1.3", validFrom: new Date(now + from * d).toUTCString(), validTo: new Date(now + to * d).toUTCString(), issuer: "Let's Encrypt", altNames: ["a.com"], ...extra });
  const run = (t, more = {}) => C.analyzeHttps({ host: "a.com", tls: t, legacy: { tested: true, accepted: false }, httpChain: [{ url: "http://a.com/", status: 301, location: "https://a.com/" }, { url: "https://a.com/", status: 200 }], now, ...more });
  let f = run(tls(-30, 60));
  assert.ok(f.every((x) => x.status === "pass"), JSON.stringify(f));
  assert.equal(byId(run(tls(-80, 10)), "cert_expiry").status, "warn");
  assert.equal(byId(run(tls(-88, 2)), "cert_expiry").status, "fail");
  assert.equal(byId(run(tls(-100, -1)), "cert_expiry").status, "fail");
  assert.equal(byId(run(tls(-4, 2)), "cert_expiry").status, "pass", "6-day certs with 2 days left are normal");
  f = run(tls(-10, 80, { authorized: false, error: "ERR_TLS_CERT_ALTNAME_INVALID" }));
  assert.equal(byId(f, "cert_valid").status, "fail");
  assert.match(byId(f, "cert_valid").evidence, /different domain/);
  assert.match(C.certErrorText("DEPTH_ZERO_SELF_SIGNED_CERT"), /self-signed/);
  assert.match(C.certErrorText("UNABLE_TO_VERIFY_LEAF_SIGNATURE"), /intermediate/);
  assert.equal(byId(run(tls(-10, 80, { protocol: "TLSv1" })), "tls_version").status, "fail");
  assert.equal(byId(run(tls(-10, 80), { legacy: { tested: true, accepted: true, protocol: "TLSv1" } }), "tls_legacy").status, "warn");
  assert.equal(byId(run(tls(-10, 80), { legacy: { tested: false } }), "tls_legacy").status, "info");
});

test("https: unreachable HTTPS, HTTP not redirecting, HTTP closed", () => {
  let f = C.analyzeHttps({ host: "a.com", httpsError: "ECONNREFUSED", httpChain: [{ url: "http://a.com/", status: 200 }] });
  assert.equal(byId(f, "https_available").status, "fail");
  assert.equal(byId(f, "https_available").severity, "high");
  assert.equal(byId(f, "http_redirect").status, "fail");
  f = C.analyzeHttps({ host: "a.com", tls: { authorized: true, protocol: "TLSv1.3", validTo: "" }, httpError: "ECONNREFUSED" });
  assert.equal(byId(f, "http_redirect").status, "pass");
  f = C.analyzeHttps({ host: "a.com", tls: { authorized: true, protocol: "TLSv1.3" }, httpChain: [{ url: "http://a.com/", status: 301, location: "http://www.a.com/" }, { url: "http://www.a.com/", status: 200 }] });
  assert.equal(byId(f, "http_redirect").status, "fail");
});

test("mixed content: active vs passive, comments and inline scripts ignored, CSP upgrade", () => {
  const html = `<!-- <script src="http://old.com/x.js"></script> --><script>var u="<img src='http://inline.com/a.png'>"</script>
  <script src="http://cdn.bad.com/a.js"></script><link rel="stylesheet" href="http://cdn.bad.com/a.css"><img src="http://img.com/a.jpg"><a href="http://fine.com">ok</a><form action="http://post.com/x">`;
  const m = C.findMixedContent(html);
  assert.deepEqual(m.active, ["http://cdn.bad.com/a.js", "http://cdn.bad.com/a.css"]);
  assert.deepEqual(m.passive, ["http://img.com/a.jpg"]);
  assert.deepEqual(m.forms, ["http://post.com/x"]);
  assert.equal(C.analyzeMixed({ https: true, html }).status, "fail");
  assert.equal(C.analyzeMixed({ https: true, html: '<img src="http://img.com/a.jpg">' }).status, "warn");
  assert.equal(C.analyzeMixed({ https: true, html, csp: "upgrade-insecure-requests" }).status, "warn");
  assert.equal(C.analyzeMixed({ https: true, html: '<script src="https://ok.com/a.js"></script><img src="/a.png">' }).status, "pass");
  assert.equal(C.analyzeMixed({ https: false, html }).status, "info");
});

test("SPF parsing", () => {
  assert.equal(C.analyzeSpf([], "a.com").status, "fail");
  assert.equal(C.analyzeSpf(["google-site-verification=x"], "a.com").status, "fail");
  assert.equal(C.analyzeSpf(["v=spf1 include:_spf.google.com ~all"], "a.com").status, "pass");
  assert.equal(C.analyzeSpf(["v=spf1 -all"], "a.com").status, "pass");
  const plus = C.analyzeSpf(["v=spf1 +all"], "a.com");
  assert.equal(plus.status, "fail"); assert.equal(plus.severity, "high");
  assert.equal(C.analyzeSpf(["v=spf1 a mx all"], "a.com").severity, "high");
  assert.equal(C.analyzeSpf(["v=spf1 ?all"], "a.com").status, "warn");
  assert.equal(C.analyzeSpf(["v=spf1 include:a.com"], "a.com").status, "warn");
  assert.equal(C.analyzeSpf(["v=spf1 redirect=_spf.a.com"], "a.com").status, "pass");
  assert.equal(C.analyzeSpf(["v=spf1 -all", "v=spf1 include:x ~all"], "a.com").status, "fail");
  assert.equal(C.analyzeSpf(["v=spf1 " + Array.from({ length: 11 }, (_, i) => `include:s${i}.com`).join(" ") + " ~all"], "a.com").status, "warn");
  assert.equal(C.analyzeSpf([], "a.com", "ETIMEOUT").status, "error");
});

test("DMARC parsing", () => {
  assert.equal(C.analyzeDmarc([], "_dmarc.a.com").status, "fail");
  assert.equal(C.analyzeDmarc(["v=DMARC1; p=reject; rua=mailto:x@a.com"], "_dmarc.a.com").status, "pass");
  assert.equal(C.analyzeDmarc(["v=DMARC1; p=quarantine"], "_dmarc.a.com").status, "pass");
  assert.equal(C.analyzeDmarc(["v=DMARC1; p=none"], "_dmarc.a.com").status, "warn");
  assert.equal(C.analyzeDmarc(["v=DMARC1;p=reject;pct=20"], "_dmarc.a.com").status, "warn");
  assert.equal(C.analyzeDmarc(["v=DMARC1; rua=mailto:x@a.com"], "_dmarc.a.com").status, "fail");
  assert.equal(C.analyzeDmarc(["v=DMARC1; p=bogus"], "_dmarc.a.com").status, "fail");
  assert.equal(C.analyzeDmarc(["v=DMARC1; p=reject", "v=DMARC1; p=none"], "_dmarc.a.com").status, "fail");
});

test("DKIM: found vs 'not found on common selectors' (never 'missing')", () => {
  const found = C.analyzeDkim([{ selector: "google", records: ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"] }, { selector: "s1", records: [] }], "a.com");
  assert.equal(found.status, "pass");
  assert.deepEqual(found.data.selectors, ["google"]);
  const none = C.analyzeDkim(C.DKIM_SELECTORS.map((selector) => ({ selector, records: [] })), "a.com");
  assert.equal(none.status, "info");
  assert.match(none.evidence, /not found on common selectors/i);
  assert.doesNotMatch(none.evidence, /missing/i);
  const revoked = C.analyzeDkim([{ selector: "old", records: ["v=DKIM1; p="] }], "a.com");
  assert.equal(revoked.status, "info");
});

test("MX: providers, none, null MX", () => {
  const f = C.analyzeMx([{ exchange: "aspmx.l.google.com", priority: 1 }], "a.com");
  assert.deepEqual(f.data.providers, ["Google Workspace"]);
  assert.equal(C.analyzeMx([], "a.com").data.receives, false);
  assert.match(C.analyzeMx([{ exchange: "", priority: 0 }], "a.com").evidence, /null MX/);
});

const resp = (status, body, ct = "text/plain") => ({ status, headers: { "content-type": ct }, body, bodyBytes: Buffer.from(body) });

test("exposed files: verified signatures only, soft-404 baseline ignored, contents never shown", () => {
  const p = (path) => C.EXPOSED_PROBES.find((x) => x.path === path);
  const env = resp(200, "APP_KEY=base64:supersecret\nDB_PASSWORD=hunter2\n");
  let f = C.analyzeExposed([{ probe: p("/.env"), res: env }, { probe: p("/.git/HEAD"), res: resp(404, "") }], null);
  assert.equal(f.status, "fail"); assert.equal(f.severity, "high");
  assert.ok(!f.evidence.includes("hunter2") && !f.evidence.includes("supersecret"));
  // A site that returns its home page (HTML, 200) for every path is NOT exposing .env
  const soft = resp(200, "<!doctype html><html><title>Home</title><body>Welcome APP=1</body></html>", "text/html");
  f = C.analyzeExposed(C.EXPOSED_PROBES.map((probe) => ({ probe, res: soft })), soft);
  assert.equal(f.status, "pass");
  // Plain-text catch-all identical to baseline is ignored even if it looks like KEY=value
  const catchall = resp(200, "STATUS=not_found\n");
  f = C.analyzeExposed([{ probe: p("/.env"), res: catchall }], catchall);
  assert.equal(f.status, "pass");
  // .git/HEAD
  assert.equal(C.analyzeExposed([{ probe: p("/.git/HEAD"), res: resp(200, "ref: refs/heads/main\n") }], null).status, "fail");
  assert.equal(C.analyzeExposed([{ probe: p("/.git/HEAD"), res: resp(200, "<html>ref: refs/heads/main</html>", "text/html") }], null).status, "pass");
  // .DS_Store magic bytes
  const ds = Buffer.concat([Buffer.from([0, 0, 0, 1]), Buffer.from("Bud1"), Buffer.alloc(20)]);
  assert.equal(C.analyzeExposed([{ probe: p("/.DS_Store"), res: { status: 200, headers: {}, body: ds.toString(), bodyBytes: ds } }], null).status, "fail");
  // phpinfo
  assert.equal(C.analyzeExposed([{ probe: p("/phpinfo.php"), res: resp(200, "<html><head><title>PHP 8.1.2 - phpinfo()</title></head></html>", "text/html") }], null).status, "fail");
  // redirects / errors are not exposures
  assert.equal(C.analyzeExposed([{ probe: p("/.env"), res: resp(301, "") }, { probe: p("/.git/config"), res: null }], null).status, "pass");
});

test("soft-404 detection tolerates small dynamic differences", () => {
  const a = resp(200, "<html>Not here " + "x".repeat(500) + " token=abcdef0123456789abcdef</html>", "text/html");
  const b = resp(200, "<html>Not here " + "x".repeat(500) + " token=0123456789abcdef0123ab</html>", "text/html");
  assert.equal(C.looksLikeBaseline(a, b), true);
  assert.equal(C.looksLikeBaseline(resp(404, "x"), b), false);
});

test("directory listing and security.txt", () => {
  const listing = resp(200, "<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1></body></html>", "text/html");
  assert.equal(C.analyzeDirListing([{ path: "/uploads/", res: listing }, { path: "/images/", res: resp(403, "") }]).status, "fail");
  assert.equal(C.analyzeDirListing([{ path: "/uploads/", res: resp(200, "<html><title>Uploads gallery</title></html>", "text/html") }]).status, "pass");
  assert.equal(C.isDirListing("[To Parent Directory]"), true);
  assert.equal(C.analyzeSecurityTxt(resp(200, "Contact: mailto:security@a.com\nExpires: 2027-01-01T00:00:00Z\n")).status, "pass");
  assert.equal(C.analyzeSecurityTxt(resp(200, "<html>Contact: us</html>", "text/html")).status, "info");
  assert.equal(C.analyzeSecurityTxt(null).status, "info");
});
