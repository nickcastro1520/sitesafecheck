// Local dev server: serves public/ (with the same HTML transform as the build) and /api/scan.
//   node dev-server.mjs                 real scans, AI only if GEMINI_API_KEY is set
//   MOCK_GEMINI=1 node dev-server.mjs   real scans, fake Gemini explanations (no key, no cost)
import http from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { loadSettings, transformHtml } from "./scripts/build.mjs";

if (process.env.MOCK_GEMINI) {
  process.env.GEMINI_API_KEY ||= "mock";
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    if (!String(url).includes("generativelanguage.googleapis.com")) return realFetch(url, opts);
    const p = JSON.parse(opts.body).contents[0].parts[0].text;
    const ids = [...p.matchAll(/"id":"([a-z_]+)"/g)].map((m) => m[1]);
    await new Promise((r) => setTimeout(r, 800));
    const text = JSON.stringify({
      summary: `(Mock AI) This site has ${ids.length} things worth fixing. Start with the highest-priority item at the top of the report.`,
      items: ids.map((id) => ({ id, what: `(Mock AI) Plain-English meaning of the ${id.replace(/_/g, " ")} finding for a business owner.`, fix: `(Mock AI) A concrete next step for ${id.replace(/_/g, " ")}.` })),
    });
    return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text }] }, finishReason: "STOP" }] }), { status: 200, headers: { "Content-Type": "application/json" } });
  };
}

const api = await import("./api/scan.js");
const settings = await loadSettings();
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".json": "application/json", ".xml": "application/xml", ".txt": "text/plain; charset=utf-8", ".webmanifest": "application/manifest+json", ".ico": "image/x-icon" };
const vercel = JSON.parse(await readFile("vercel.json", "utf8"));
// Same headers as production, minus upgrade-insecure-requests (it would break plain-http localhost).
const SEC_HEADERS = Object.fromEntries(vercel.headers.find((h) => h.source === "/(.*)").headers.map((h) => [h.key, h.value.replace(/;\s*upgrade-insecure-requests/, "")]));

async function handle(req, res, url, fn) {
  const chunks = []; for await (const c of req) chunks.push(c);
  const headers = { ...req.headers, "x-forwarded-for": req.socket.remoteAddress || "127.0.0.1" };
  const request = new Request(url, { method: req.method, headers, body: req.method === "POST" ? Buffer.concat(chunks) : undefined });
  const r = await fn(request);
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (url.pathname === "/api/scan") {
    if (req.method !== "GET" && req.method !== "POST") { res.writeHead(405); return res.end(); }
    return handle(req, res, url, req.method === "POST" ? api.POST : api.GET);
  }
  let p = decodeURIComponent(url.pathname);
  if (p.endsWith("/")) p += "index.html";
  if (!extname(p)) p += ".html"; // cleanUrls
  const file = normalize(join("public", p));
  if (!file.startsWith("public")) { res.writeHead(400); return res.end(); }
  try {
    let data = await readFile(file);
    if (file.endsWith(".html")) data = transformHtml(data.toString(), settings);
    res.writeHead(200, { "Content-Type": TYPES[extname(file)] || "application/octet-stream", ...SEC_HEADERS });
    res.end(data);
  } catch {
    const nf = transformHtml(await readFile("public/404.html", "utf8"), settings);
    res.writeHead(404, { "Content-Type": TYPES[".html"], ...SEC_HEADERS }); res.end(nf);
  }
}).listen(process.env.PORT || 3000, () => console.log("dev on http://localhost:" + (process.env.PORT || 3000)));
