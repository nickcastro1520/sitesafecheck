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
  for (const t of ["WebSite", "Person", "ProfessionalService", "SoftwareApplication", "FAQPage"]) assert.ok(types.includes(t), t);
  const person = data["@graph"].find((n) => n["@type"] === "Person");
  assert.equal(person.url, "https://nickcastrobuilds.com");
  assert.deepEqual(person.sameAs, ["https://www.linkedin.com/in/nicolas-castro-4081545b"]);
  assert.equal(data["@graph"].find((n) => n["@type"] === "SoftwareApplication").offers.price, "0");
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
