import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { detectPlatform, detectSensitive } from "../api/_lib/checks.js";
import { applyRules, buildReport, PLATFORM_NOTE, PLATFORM_HEADERS } from "../api/_lib/scan.js";
import { CATEGORIES } from "../api/_lib/catalog.js";

test("platform detection fixtures (headers, generator, asset domains)", () => {
  const cases = [
    ["Wix", "", { "x-wix-request-id": "1" }], ["Wix", '<img src="https://static.wixstatic.com/media/a.jpg">', {}], ["Wix", '<meta name="generator" content="Wix.com Website Builder">', {}],
    ["Squarespace", "", { server: "Squarespace" }], ["Squarespace", '<link href="https://static1.squarespace.com/static/x.css">', {}], ["Squarespace", "<!-- This is Squarespace. --><meta name=\"generator\" content=\"Squarespace\">", {}],
    ["Shopify", "", { "powered-by": "Shopify" }], ["Shopify", "", { "x-shopid": "123" }], ["Shopify", '<script src="//cdn.shopify.com/s/files/x.js"></script>', {}],
    ["GoDaddy Website Builder", '<meta name="generator" content="Starfield Technologies; Go Daddy Website Builder 8.0.0000">', {}], ["GoDaddy Website Builder", '<img src="//img1.wsimg.com/isteam/ip/abc.jpg">', {}],
    ["Webflow", '<meta content="Webflow" name="generator">', {}], ["Webflow", '<html data-wf-site="abc">', {}], ["Webflow", '<link href="https://cdn.prod.website-files.com/x.css">', {}],
    ["WordPress.com", '<meta name="generator" content="WordPress.com">', {}], ["WordPress.com", "", { "host-header": "WordPress.com" }],
    ["", '<meta name="generator" content="WordPress 6.5"><link href="/wp-content/themes/x.css">', { server: "Apache" }],
    ["", "<html><body>Hello</body></html>", { server: "nginx" }],
  ];
  for (const [want, html, h] of cases) assert.equal(detectPlatform(html, h), want, `${want || "none"}: ${html || JSON.stringify(h)}`);
});

test("sensitive page detection: login, password, cart/checkout", () => {
  assert.equal(detectSensitive("<html><a href='/about'>About</a></html>").any, false);
  assert.ok(detectSensitive('<input type="password" name="pw">').password);
  assert.ok(detectSensitive('<form action="/wp-login.php" method="post">').login);
  assert.ok(detectSensitive('<a href="/cart">Cart</a>').cart);
  assert.ok(detectSensitive('<a href="https://shop.example/checkout?x=1">').cart);
  assert.ok(detectSensitive('<button class="add-to-cart">').cart);
});

const f = (id, status, severity) => ({ id, status, severity, evidence: "e", category: "headers" });
const raw = (findings, meta) => ({ host: "x.example", meta: { host: "x.example", ...meta }, findings });

test("hosted platform: header checks are 'Controlled by', no deduction, no worst case, not fixable", async () => {
  const fs = [f("csp", "fail", "medium"), f("hsts", "fail", "medium"), f("x_frame_options", "fail", "medium"), f("x_content_type_options", "fail", "low"), f("referrer_policy", "fail", "low"), f("permissions_policy", "fail", "low"), f("spf", "fail", "medium")];
  const rep = await buildReport(raw(fs, { platform: "Squarespace", sensitive: { any: true } }), { useAi: false });
  for (const id of PLATFORM_HEADERS) {
    const x = rep.findings.find((y) => y.id === id);
    assert.equal(x.status, "platform"); assert.equal(x.controlledBy, "Squarespace");
    assert.equal(x.what, PLATFORM_NOTE); assert.ok(!x.worst); assert.notEqual(x.fixBy, "nick");
  }
  assert.equal(PLATFORM_NOTE, "Your host controls this setting. You can't change it yourself, and it isn't something you need to pay to fix.");
  assert.deepEqual(rep.score.deductions.map((d) => d.id), ["spf"]);
  assert.equal(rep.score.score, 92);
});

test("no login/cart: CSP, Permissions-Policy, Referrer-Policy are Recommended (low, max 3, no cap); full weight otherwise", () => {
  const fs = [f("csp", "fail", "high"), f("permissions_policy", "fail", "medium"), f("referrer_policy", "warn", "medium"), f("hsts", "fail", "medium")];
  const plain = applyRules(fs, { sensitive: { any: false } });
  for (const id of ["csp", "permissions_policy", "referrer_policy"]) { const x = plain.find((y) => y.id === id); assert.equal(x.severity, "low"); assert.ok(x.recommended); }
  assert.equal(plain.find((y) => y.id === "hsts").severity, "medium", "HSTS is not part of rule 4");
  const shop = applyRules(fs, { sensitive: { any: true } });
  assert.equal(shop.find((y) => y.id === "csp").severity, "high");
  assert.ok(!shop.find((y) => y.id === "csp").recommended);
  const both = applyRules(fs, { platform: "Wix", sensitive: { any: false } });
  assert.equal(both.find((y) => y.id === "csp").status, "platform", "rule 3 wins");
});

test("recommended items never trigger the 69 cap and cost at most 3", async () => {
  const rep = await buildReport(raw([f("csp", "fail", "high"), f("permissions_policy", "fail", "medium"), f("referrer_policy", "fail", "medium")], { sensitive: { any: false } }), { useAi: false });
  assert.equal(rep.score.score, 91); assert.equal(rep.score.capped, false);
  assert.ok(rep.score.deductions.every((d) => d.points <= 3));
});

test("report category order: email, https, leaks, cookies, headers", () => {
  assert.deepEqual(CATEGORIES.map((c) => c.id), ["email", "https", "leaks", "cookies", "headers"]);
});

test("?url= prefills the box (sanitized) and never auto-runs; report links to the AI visibility check", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const pre = app.slice(app.indexOf('if (params.get("url"))'), app.indexOf("}", app.indexOf('if (params.get("url"))') + 300));
  assert.match(pre, /input\.value = params\.get\("url"\)\.replace\(/);
  assert.doesNotMatch(pre, /requestSubmit|\.submit\(|\.click\(/, "prefill must not start a scan");
  assert.doesNotMatch(app, /params\.(get|has)\("url"\)[^\n]*(requestSubmit|click)/);
  assert.match(app, /Does AI recommend your business\? /);
  assert.match(app, /href: "https:\/\/doesaiknowmybusiness\.com"[^\n]*Run a free AI visibility check →/);
  assert.match(app, /Your site runs on \$\{rep\.meta\.platform\}\./);
  for (const p of ["index", "about", "privacy", "how-i-built-this", "404"]) {
    const html = await readFile(new URL(`../public/${p}.html`, import.meta.url), "utf8");
    assert.match(html, /<a href="https:\/\/doesaiknowmybusiness\.com">Does AI Know My Business \(free AI check\)<\/a>/, p);
  }
});
