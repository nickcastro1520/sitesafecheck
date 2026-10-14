// Static site checks: JSON-LD validity, required SEO tags, GA/Search Console only when configured,
// and the site's own security headers.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { transformHtml, loadSettings } from "../scripts/build.mjs";
import { analyzeHeaders } from "../api/_lib/checks.js";

const html = await readFile(new URL("../public/index.html", import.meta.url), "utf8");

test("JSON-LD parses and has the required types", () => {
  const m = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
  const data = JSON.parse(m[1]);
  const types = data["@graph"].map((n) => n["@type"]);
  for (const t of ["WebSite", "Person", "ProfessionalService", "WebApplication", "FAQPage"]) assert.ok(types.includes(t), t);
  const person = data["@graph"].find((n) => n["@type"] === "Person");
  assert.equal(person.url, "https://nickcastrobuilds.com");
  assert.deepEqual(person.sameAs, ["https://www.linkedin.com/in/nicolas-castro-4081545b"]);
  assert.equal(data["@graph"].find((n) => n["@type"] === "WebApplication").offers.price, "0");
  // FAQ answers in JSON-LD match visible FAQ questions
  for (const q of data["@graph"].find((n) => n["@type"] === "FAQPage").mainEntity) assert.ok(html.includes(`<summary>${q.name}</summary>`), q.name);
});

test("SEO basics present", () => {
  assert.match(html, /<link rel="canonical" href="https:\/\/sitesafecheck\.com\/">/);
  assert.match(html, /property="og:image" content="https:\/\/sitesafecheck\.com\/og\.png"/);
  assert.match(html, /name="twitter:card" content="summary_large_image"/);
  assert.match(html, /<html lang="en">/);
  assert.doesNotMatch(html, /\sstyle="/, "no inline styles (strict CSP)");
  assert.doesNotMatch(html, /<script>(?!\s*$)/, "no inline scripts (strict CSP)");
});

test("GA and Search Console tags only appear when configured", () => {
  const none = transformHtml(html, { ga: "", gsc: "" });
  assert.ok(!none.includes("ga.js") && !none.includes("googletagmanager") && !none.includes("google-site-verification"));
  const on = transformHtml(html, { ga: "G-ABC1234", gsc: "abcDEF123456" });
  assert.ok(on.includes('data-ga="G-ABC1234"') && on.includes('content="abcDEF123456"'));
});

test("settings validation ignores malformed IDs", async () => {
  const s = await loadSettings({ GA_MEASUREMENT_ID: "UA-123\"><script>", GOOGLE_SITE_VERIFICATION: "<bad>" });
  assert.equal(s.ga, ""); assert.equal(s.gsc, ""); assert.ok(s.gaInvalid && s.gscInvalid);
});

test("the site's own headers pass its own header checks", async () => {
  const v = JSON.parse(await readFile(new URL("../vercel.json", import.meta.url), "utf8"));
  const headers = Object.fromEntries(v.headers.find((h) => h.source === "/(.*)").headers.map((h) => [h.key.toLowerCase(), h.value]));
  const f = analyzeHeaders(headers, { https: true });
  assert.ok(f.every((x) => x.status === "pass"), JSON.stringify(f.filter((x) => x.status !== "pass")));
});

test("report UI: red Worst case line with a text label, short How it's fixed line, CTAs tracked", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const css = await readFile(new URL("../public/styles.css", import.meta.url), "utf8");
  assert.match(app, /class: "worst"/); assert.match(app, /"Worst case: "/); assert.match(app, /"How it's fixed: "/);
  assert.doesNotMatch(app, /How to fix/);
  assert.match(app, /Want these fixed\? Nick can handle it\./);
  assert.match(app, /"data-loc": loc/); assert.match(app, /report_top/); assert.match(app, /report_bottom/);
  assert.match(app, /track\("cta_click", \{ method: a\.dataset\.cta, location: a\.dataset\.loc/);
  assert.match(app, /\$250–\$500/); assert.match(app, /\$50–\$100\/mo/);
  assert.match(app, /doesn't do penetration testing, code audits, malware or breach cleanup/);
  assert.match(css, /p\.worst\{color:var\(--hi\)/); assert.match(css, /@media print\{[\s\S]*p\.worst/);
  for (const page of ["about.html", "index.html", "llms.txt"]) {
    const t = await readFile(new URL(`../public/${page}`, import.meta.url), "utf8");
    assert.doesNotMatch(t, /how to fix|v=spf1|v=DMARC1|max-age=/i, page);
  }
});

test("home page: keyword title, one H1, low-friction scan form, trust lines, sample report preview", async () => {
  assert.match(html, /<title>Free Website Security Check for Small Businesses \| SiteSafeCheck<\/title>/);
  assert.match(html, /<meta name="description" content="Free website security check for small businesses\./);
  assert.equal((html.match(/<h1[\s>]/g) || []).length, 1);
  assert.match(html, /<meta property="og:title" content="Free Website Security Check/);
  assert.doesNotMatch(html, /type="checkbox"/, "no required checkbox before scanning");
  assert.match(html, /By scanning, you confirm you own or manage this site/);
  assert.match(html, /id="go">Scan my site free</);
  for (const t of ["Free", "No signup", "Results in under 10 seconds", "Passive checks only (we never attack your site)"]) assert.ok(html.includes(`<li>${t}</li>`), t);
  assert.doesNotMatch(html, /30 seconds/, "old speed claim is gone");
  const form = html.slice(html.indexOf('<form class="scan"'), html.indexOf("</form>"));
  assert.match(form, /id="demo">see a sample report</i, "sample report link sits by the button");
  const demo = JSON.parse(await readFile(new URL("../public/demo.json", import.meta.url), "utf8"));
  const sample = html.slice(html.indexOf('id="sample"'), html.indexOf('id="what"'));
  assert.match(sample, new RegExp(`gradebox g${demo.score.grade}`));
  assert.match(sample, /href="\/\?example"/);
  const ids = [...sample.matchAll(/data-id="([a-z_]+)"/g)].map((m) => m[1]);
  assert.ok(ids.length >= 2 && ids.length <= 3);
  for (const id of ids) {
    const f = demo.findings.find((x) => x.id === id);
    assert.ok(sample.includes(f.title) && sample.includes(f.worst.replace(/'/g, "&#39;")), `preview for ${id} matches the example report`);
  }
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(app, /authorized: true, confirmation: source === "demo" \? "demo_sample_site" : source === "shared" \? "shared_link_v1" : "submit_notice_v1"/);
  assert.match(app, /min-width: 900px\) and \(pointer: fine\)/, "autofocus on desktop only");
});

test("How I built this page: linked everywhere, real numbers only, no assistant names", async () => {
  const { readdir } = await import("node:fs/promises");
  const page = await readFile(new URL("../public/how-i-built-this.html", import.meta.url), "utf8");
  assert.equal((page.match(/<h1[\s>]/g) || []).length, 1);
  assert.match(page, /<link rel="canonical" href="https:\/\/sitesafecheck\.com\/how-i-built-this">/);
  assert.match(page, /href="https:\/\/github\.com\/nickcastro1520\/sitesafecheck"/);
  assert.doesNotMatch(page, /\{TESTS\}|lorem|TODO/i);
  // The stated test count must match the real number of tests.
  let tests = 0;
  for (const f of await readdir(new URL("./", import.meta.url))) if (f.endsWith(".test.js")) tests += ((await readFile(new URL(`./${f}`, import.meta.url), "utf8")).match(/^test\(/gm) || []).length;
  const stated = [...page.matchAll(/(\d+)(?:<\/strong><span>automated tests| automated tests| tests cover)/g)].map((m) => Number(m[1]));
  assert.ok(stated.length >= 3 && stated.every((n) => n === tests), `page says ${stated}, actual ${tests}`);
  // The stated check count must match the catalog.
  const { CATALOG, CATEGORIES } = await import("../api/_lib/catalog.js");
  assert.match(page, new RegExp(`<strong>${Object.keys(CATALOG).length}</strong><span>checks in ${CATEGORIES.length} categories`));
  for (const f of ["sitemap.xml", "llms.txt"]) assert.match(await readFile(new URL(`../public/${f}`, import.meta.url), "utf8"), /sitesafecheck\.com\/how-i-built-this/, f);
  assert.match(await readFile(new URL("../public/about.html", import.meta.url), "utf8"), /href="\/how-i-built-this"/);
  for (const f of (await readdir(new URL("../public/", import.meta.url))).filter((x) => x.endsWith(".html"))) {
    const t = await readFile(new URL(`../public/${f}`, import.meta.url), "utf8");
    const foot = t.slice(t.indexOf("<footer>"), t.indexOf("</footer>"));
    assert.match(foot, /Built by <a href="https:\/\/nickcastrobuilds\.com">Nick Castro<\/a>/, f);
    for (const l of ["/how-i-built-this", "/about", "/privacy"]) assert.ok(foot.includes(`href="${l}"`), `${f} footer ${l}`);
    assert.match(t, /<a class="skip" href="#main">/, f); assert.match(t, /<main id="main"/, f);
  }
  for (const f of ["README.md", "public/how-i-built-this.html", "public/about.html", "public/index.html", "public/llms.txt", "public/app.js"]) {
    assert.doesNotMatch(await readFile(new URL(`../${f}`, import.meta.url), "utf8"), /grok|cursor\b/i, f);
  }
});

test("scan form has a friendly message and next step for every error state", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  for (const k of ["empty", "invalid", "notfound", "unreachable", "timeout", "limited", "server", "offline"]) assert.match(app, new RegExp(`\\n    ${k}: \\["[^"]+", `), k);
  for (const code of ["dns_not_found", "unreachable", "timeout", "rate_limited", "invalid_url"]) assert.ok(app.includes(`"${code}"`), code);
  assert.match(app, /AbortSignal\.timeout\(70000\)/);
  assert.doesNotMatch(app, /err\.textContent = /);
});

test("one-tap live demo button and progressive AI indicator", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(html, /id="try-demo">Try it on a sample site</);
  assert.match(app, /track\("demo_scan_clicked"/);
  assert.match(app, /Writing plain-English explanations/);
  assert.match(app, /stream: true/);
});
