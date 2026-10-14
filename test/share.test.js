import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { parseShare, sharePage } from "../api/_lib/share-page.js";
import { GET } from "../api/share.js";

const q = (s) => new URLSearchParams(s);

test("share link parsing: normalizes the domain, validates grade/score/date, rejects junk", () => {
  assert.deepEqual(parseShare(q("url=Example.com&g=b&s=83&d=2026-10-14")), { host: "example.com", grade: "B", score: 83, date: "2026-10-14" });
  assert.deepEqual(parseShare(q("url=example.com&g=Z&s=500&d=x")), { host: "example.com", grade: "", score: null, date: "" });
  assert.equal(parseShare(q("url=localhost")), null);
  assert.equal(parseShare(q("url=<script>")), null);
  assert.equal(parseShare(q("")), null);
});

test("shared report page: noindex, OG title with grade, run button (no auto-run), consent line, CTA", () => {
  const html = sharePage(parseShare(q("url=example.com&g=C&s=72&d=2026-10-14")));
  assert.match(html, /<meta name="robots" content="noindex, nofollow">/);
  assert.match(html, /<meta property="og:title" content="Security report for example\.com: C">/);
  assert.match(html, /href="\/\?url=example\.com&amp;scan=shared" id="run-shared">Run this check</);
  assert.match(html, /By scanning, you confirm you own or manage this site/);
  assert.match(html, /class="cta"/); assert.match(html, /tel:\+17082501040/);
  assert.match(html, /Does AI Know My Business \(free AI check\)/);
  assert.doesNotMatch(html, /fetch\(|api\/scan/, "the shared page never starts a scan");
  assert.equal((html.match(/<h1[\s>]/g) || []).length, 1);
});

test("GET /r: HTML with X-Robots-Tag noindex; bad links redirect home", async () => {
  const ok = await GET(new Request("https://sitesafecheck.com/r?url=example.com&g=A&s=95"));
  assert.equal(ok.status, 200); assert.match(ok.headers.get("x-robots-tag"), /noindex/);
  assert.match(await ok.text(), /Security report for example\.com: A/);
  const bad = await GET(new Request("https://sitesafecheck.com/r?url=10.0.0.1"));
  assert.equal(bad.status, 302); assert.equal(bad.headers.get("location"), "/");
});

test("report has Copy link + Share (Web Share with copy fallback), tracks share_click; scan=shared only prefills", async () => {
  const app = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  assert.match(app, /text: "Copy link to this report"/);
  assert.match(app, /navigator\.share/); assert.match(app, /navigator\.clipboard\.writeText/);
  assert.match(app, /track\("share_click"/);
  assert.match(app, /\/r\?url=\$\{encodeURIComponent\(rep\.host\)\}/);
  const blk = app.slice(app.indexOf('params.get("scan") === "shared"'), app.indexOf("history.replaceState"));
  assert.ok(blk.length > 0);
  assert.doesNotMatch(blk, /requestSubmit|\.submit\(|\.click\(/);
  const v = JSON.parse(await readFile(new URL("../vercel.json", import.meta.url), "utf8"));
  assert.deepEqual(v.rewrites, [{ source: "/r", destination: "/api/share" }]);
});
