import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { parseShare, sharePage, savedPage, ID_RE } from "../api/_lib/share-page.js";
import { GET, POST, slim } from "../api/share.js";
import { prefixed, PREFIX, setJSON } from "../api/_lib/store.js";
import { buildReport } from "../api/_lib/scan.js";

const q = (s) => new URLSearchParams(s);
const sample = async () => buildReport({ host: "shop.example", meta: { host: "shop.example", platform: "Shopify", sensitive: { any: true }, finalUrl: "https://shop.example/" }, findings: [{ id: "spf", status: "fail", severity: "medium", evidence: "No SPF <b>" }, { id: "csp", status: "fail", severity: "medium", evidence: "No CSP" }] }, { useAi: false });

test("store: every key gets the ssc: prefix", () => {
  assert.equal(PREFIX, "ssc:");
  assert.deepEqual(prefixed(["SET", "r:abc", "{}", "EX", "60"]), ["SET", "ssc:r:abc", "{}", "EX", "60"]);
  assert.deepEqual(prefixed(["INCR", "cap:2026-10-14"]), ["INCR", "ssc:cap:2026-10-14"]);
});

test("fallback link: domain only, never a grade; junk rejected", () => {
  assert.deepEqual(parseShare(q("url=Example.com&g=A&s=99")), { host: "example.com" });
  assert.equal(parseShare(q("url=localhost")), null);
  const html = sharePage(parseShare(q("url=example.com&g=A&s=99")));
  assert.doesNotMatch(html, /gradebox|: A"|99\/100/);
  assert.match(html, /<meta name="robots" content="noindex, nofollow">/);
  assert.match(html, /<meta property="og:title" content="Security report for example\.com">/);
  assert.match(html, /href="\/\?url=example\.com&amp;scan=shared" id="run-shared">Run this check</);
  assert.match(html, /By scanning, you confirm you own or manage this site/);
  assert.doesNotMatch(html, /fetch\(|api\/scan/);
});

test("saved report page: real grade, read-only, noindex, OG title with grade, Run a fresh check, escaped", async () => {
  const rep = slim(await sample());
  const html = savedPage(rep, "A".repeat(22));
  assert.match(html, /<meta name="robots" content="noindex, nofollow">/);
  assert.match(html, new RegExp(`og:title" content="Security report for shop\\.example: ${rep.score.grade}"`));
  assert.match(html, /id="run-shared">Run a fresh check</);
  assert.match(html, /Your site runs on Shopify\./);
  assert.match(html, /Controlled by Shopify/);
  assert.match(html, /No SPF &lt;b&gt;/); assert.doesNotMatch(html, /No SPF <b>/);
  assert.match(html, /class="cta"/);
  assert.equal((html.match(/<h1[\s>]/g) || []).length, 1);
  assert.doesNotMatch(html, /<form|<input/);
});

test("POST /api/share without storage returns the no-grade fallback; GET /r/<id> 404s for unknown ids", async () => {
  const r = await POST(new Request("https://sitesafecheck.com/api/share", { method: "POST", body: JSON.stringify({ url: "example.com" }) }));
  assert.deepEqual(await r.json(), { url: "/r?url=example.com", saved: false, reason: "no_storage" });
  const bad = await POST(new Request("https://x/api/share", { method: "POST", body: JSON.stringify({ url: "10.0.0.1" }) }));
  assert.equal(bad.status, 400);
  const miss = await GET(new Request("https://sitesafecheck.com/api/share?id=" + "B".repeat(22)));
  assert.equal(miss.status, 404); assert.match(miss.headers.get("x-robots-tag"), /noindex/);
  const junk = await GET(new Request("https://sitesafecheck.com/api/share?id=../../x"));
  assert.equal(junk.status, 404);
});

test("saved report round trip through the store (memory) with an unguessable id", async () => {
  const rep = await sample();
  await setJSON("r:" + "C".repeat(22), slim(rep), 60);
  const r = await GET(new Request("https://sitesafecheck.com/api/share?id=" + "C".repeat(22)));
  assert.equal(r.status, 200);
  assert.match(await r.text(), new RegExp(`Security report for shop\\.example: ${rep.score.grade}`));
  assert.ok(ID_RE.test(Buffer.from(new Uint8Array(16)).toString("base64url")), "16 random bytes -> 22-char id");
  assert.ok(JSON.stringify(slim(rep)).length < 20000, "stored value stays small");
});

test("client: Copy link + Share call /api/share, fall back to /r?url=, track share_click; scan=shared only prefills", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(app, /text: "Copy link to this report"/);
  assert.match(app, /fetch\("\/api\/share"/);
  assert.match(app, /\/r\?url=\$\{encodeURIComponent\(rep\.host\)\}/);
  assert.match(app, /navigator\.share/); assert.match(app, /track\("share_click"/);
  const blk = app.slice(app.indexOf('params.get("scan") === "shared"'), app.indexOf("history.replaceState"));
  assert.ok(blk.length > 0); assert.doesNotMatch(blk, /requestSubmit|\.submit\(|\.click\(/);
  const v = JSON.parse(await readFile(new URL("../vercel.json", import.meta.url), "utf8"));
  assert.deepEqual(v.rewrites, [{ source: "/r/:id", destination: "/api/share?id=:id" }, { source: "/r", destination: "/api/share" }]);
});
