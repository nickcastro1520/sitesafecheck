import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";

const PAGES = { "/": "index", "/about": "about", "/privacy": "privacy", "/how-i-built-this": "how-i-built-this" };
const read = (f) => readFile(new URL(`../public/${f}`, import.meta.url), "utf8");

test("indexable pages: unique title, description, h1, self canonical, valid JSON-LD with breadcrumbs", async () => {
  const seen = { title: new Set(), desc: new Set(), h1: new Set() };
  for (const [path, f] of Object.entries(PAGES)) {
    const html = await read(`${f}.html`);
    const title = html.match(/<title>([^<]+)<\/title>/)[1];
    const desc = html.match(/<meta name="description" content="([^"]+)"/)[1];
    const h1s = [...html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/g)];
    assert.equal(h1s.length, 1, `${path} has one h1`);
    for (const [k, v] of [["title", title], ["desc", desc], ["h1", h1s[0][1]]]) { assert.ok(!seen[k].has(v), `${path} ${k} unique`); seen[k].add(v); }
    assert.ok(title.length >= 20 && title.length <= 80, `${path} title length ${title.length}`);
    assert.ok(desc.length >= 70 && desc.length <= 200, `${path} description length ${desc.length}`);
    assert.match(html, new RegExp(`<link rel="canonical" href="https://sitesafecheck\\.com${path === "/" ? "/" : path}">`));
    assert.doesNotMatch(html, /name="robots" content="noindex/);
    const blocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)];
    assert.ok(blocks.length >= 1, `${path} has JSON-LD`);
    const types = blocks.flatMap((b) => JSON.parse(b[1])["@graph"].map((n) => n["@type"]));
    if (path === "/") { assert.ok(types.includes("WebApplication") && types.includes("FAQPage")); }
    else assert.ok(types.includes("BreadcrumbList"), `${path} breadcrumbs`);
    if (path === "/how-i-built-this") assert.ok(types.includes("Article"));
    const text = html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>|<[^>]+>/g, " ").replace(/\s+/g, " ");
    assert.ok(text.length > 1500, `${path} main content is in the static HTML`);
  }
});

test("sitemap lists exactly the indexable pages with real dates; robots.txt; /r stays out", async () => {
  const xml = await read("sitemap.xml");
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  assert.deepEqual(locs.sort(), Object.keys(PAGES).map((p) => `https://sitesafecheck.com${p === "/" ? "/" : p}`).sort());
  for (const m of xml.matchAll(/<lastmod>([^<]+)<\/lastmod>/g)) assert.ok(/^\d{4}-\d{2}-\d{2}$/.test(m[1]) && Date.parse(m[1]) <= Date.now());
  assert.doesNotMatch(xml, /\/r[/?]/);
  const robots = await read("robots.txt");
  assert.match(robots, /^Allow: \/$/m); assert.match(robots, /^Disallow: \/api\/$/m);
  assert.match(robots, /^Sitemap: https:\/\/sitesafecheck\.com\/sitemap\.xml$/m);
  const { sharePage, savedPage } = await import("../api/_lib/share-page.js");
  assert.match(sharePage({ host: "example.com" }), /noindex/);
});

test("IndexNow: key file served from public/, script posts sitemap URLs with keyLocation, daily workflow", async () => {
  const files = (await readdir(new URL("../public/", import.meta.url))).filter((f) => /^[a-f0-9]{32}\.txt$/.test(f));
  assert.equal(files.length, 1);
  assert.equal((await read(files[0])).trim(), files[0].slice(0, 32));
  const s = await readFile(new URL("../scripts/indexnow.mjs", import.meta.url), "utf8");
  assert.match(s, /https:\/\/api\.indexnow\.org\/indexnow/); assert.match(s, /keyLocation/); assert.match(s, /host: HOST/);
  const wf = await readFile(new URL("../.github/workflows/indexnow.yml", import.meta.url), "utf8");
  assert.match(wf, /cron: "37 14 \* \* \*"/); assert.match(wf, /workflow_dispatch/);
});
