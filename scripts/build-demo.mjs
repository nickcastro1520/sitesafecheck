// Builds public/demo.json: the clearly-labeled EXAMPLE report for a made-up bakery website.
// It runs the real analyzers, scoring, and hand-written explanations on synthetic inputs, so the
// example always matches what a real report looks like. No network, no AI.
import { writeFile } from "node:fs/promises";
import * as C from "../api/_lib/checks.js";
import { buildReport } from "../api/_lib/scan.js";

const host = "harborbakery.example";
const now = Date.parse("2026-10-05T15:00:00Z");
const day = 86400000;
const headers = {
  "content-type": "text/html; charset=UTF-8",
  server: "Apache/2.4.41 (Ubuntu)",
  "x-powered-by": "PHP/7.4.3",
  "strict-transport-security": "max-age=300",
  "x-content-type-options": "nosniff",
  "x-frame-options": "SAMEORIGIN",
};
const html = `<!doctype html><html><head><meta name="generator" content="WordPress 6.2.2"><link rel="stylesheet" href="/wp-content/themes/bakery/style.css"></head><body><img src="http://harborbakery.example/wp-content/uploads/2021/05/cakes.jpg" alt="Cakes"></body></html>`;
const tls = { authorized: true, error: "", protocol: "TLSv1.3", validFrom: new Date(now - 50 * day).toUTCString(), validTo: new Date(now - 50 * day + 90 * day).toUTCString(), issuer: "Let's Encrypt", altNames: [host, "www." + host] };
const ok = (body, ct = "text/html") => ({ status: 200, headers: { "content-type": ct }, body, bodyBytes: Buffer.from(body) });
const notFound = { status: 404, headers: { "content-type": "text/html" }, body: "<html><title>Not found</title></html>" };

const findings = [
  ...C.analyzeHttps({ host, tls, legacy: { tested: true, accepted: false }, httpChain: [{ url: `http://${host}/`, status: 301, location: `https://${host}/` }, { url: `https://${host}/`, status: 200 }], now }),
  C.analyzeMixed({ https: true, html, csp: "" }),
  ...C.analyzeHeaders(headers, { https: true }),
  C.analyzeBanners(headers, html),
  ...C.analyzeCookies(["PHPSESSID=abc123; path=/; Secure; HttpOnly", "wp_lang=en_US; path=/; Secure; SameSite=Lax"], { https: true }),
  C.analyzeExposed(C.EXPOSED_PROBES.map((probe) => ({ probe, res: notFound })), notFound),
  C.analyzeDirListing([{ path: "/uploads/", res: notFound }, { path: "/images/", res: notFound }, { path: "/wp-content/uploads/", res: ok("<html><head><title>Index of /wp-content/uploads</title></head><body><h1>Index of /wp-content/uploads</h1></body></html>") }]),
  C.analyzeSecurityTxt(notFound),
  C.analyzeMx([{ exchange: "aspmx.l.google.com", priority: 1 }], host),
  C.analyzeSpf(["v=spf1 include:_spf.google.com ~all"], host),
  C.analyzeDmarc([], `_dmarc.${host}`),
  C.analyzeDkim(C.DKIM_SELECTORS.map((selector) => ({ selector, records: [] })), host),
];
const raw = { host, meta: { host, emailDomain: host, finalUrl: `https://${host}/`, status: 200, https: true, offsite: false, cms: "WordPress", server: headers.server, emailProviders: ["Google Workspace"], ms: 6400 }, findings };
const report = await buildReport(raw, { useAi: false, now });
report.example = true;
await writeFile(new URL("../public/demo.json", import.meta.url), JSON.stringify(report));
console.log(`demo.json: grade ${report.score.grade}, score ${report.score.score}, ${report.findings.length} findings`);
