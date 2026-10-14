// GET  /r?url=<domain>   -> fallback share page (no grade, offers to run the check)
// GET  /r/<id>           -> saved read-only report (rewritten to /api/share?id=<id>)
// POST /api/share {url}  -> saves the last report for that domain for 30 days, returns /r/<id>
import { randomBytes, createHash } from "node:crypto";
import { parseShare, sharePage, savedPage, missingPage, ID_RE } from "./_lib/share-page.js";
import { getJSON, setJSON, incr, isPersistent } from "./_lib/store.js";
import { normalizeTarget } from "./_lib/net.js";

const TTL = 30 * 86400;
const html = (body, status = 200) => new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8", "X-Robots-Tag": "noindex, nofollow", "Cache-Control": status === 200 ? "public, max-age=300" : "no-store" } });
const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
const gaId = () => { const g = String(process.env.GA_MEASUREMENT_ID || "").trim(); return /^G-[A-Z0-9]{4,15}$/.test(g) ? g : ""; };
const sha = (s) => createHash("sha256").update(s).digest("hex");

export async function GET(request) {
  const sp = new URL(request.url).searchParams;
  const id = sp.get("id");
  if (id != null) {
    if (!ID_RE.test(id)) return html(missingPage({ ga: gaId() }), 404);
    const rep = await getJSON(`r:${id}`);
    return rep ? html(savedPage(rep, id, { ga: gaId() })) : html(missingPage({ ga: gaId() }), 404);
  }
  const sh = parseShare(sp);
  if (!sh) return new Response(null, { status: 302, headers: { Location: "/", "X-Robots-Tag": "noindex" } });
  return html(sharePage(sh, { ga: gaId() }));
}
export const HEAD = GET;

// Only what the read-only page shows: keeps stored values small.
export function slim(r) {
  const pick = (f) => ({ id: f.id, title: f.title, category: f.category, status: f.status, severity: f.severity, evidence: String(f.evidence || "").slice(0, 400), what: f.what || "", worst: f.worst || "", fix: f.fix || "", fixBy: f.fixBy, controlledBy: f.controlledBy, recommended: f.recommended || undefined });
  return { host: r.host, createdAt: r.createdAt, meta: { platform: r.meta?.platform || "", cms: r.meta?.cms || "", finalUrl: r.meta?.finalUrl || "" }, score: { score: r.score.score, grade: r.score.grade, counts: r.score.counts }, summary: r.summary, categories: r.categories, findings: r.findings.map(pick), ai: { used: Boolean(r.ai?.used) }, scope: r.scope };
}

export async function POST(request) {
  let body = {};
  try { const t = await request.text(); if (t.length > 1000) throw 0; body = JSON.parse(t || "{}"); } catch { return json({ error: "bad_request" }, 400); }
  let host;
  try { host = normalizeTarget(body.url).host; } catch { return json({ error: "invalid_url" }, 400); }
  const fallback = `/r?url=${encodeURIComponent(host)}`;
  if (!isPersistent()) return json({ url: fallback, saved: false, reason: "no_storage" });
  const ip = (request.headers.get("x-real-ip") || request.headers.get("x-forwarded-for") || "0").split(",")[0].trim();
  const hour = new Date().toISOString().slice(0, 13);
  if ((await incr(`shr:${hour}:${sha(ip + "ssc-share").slice(0, 16)}`, 3700)) > 20) return json({ url: fallback, saved: false, reason: "rate_limited" });
  const rep = await getJSON(`scan:v3:${host}`);
  if (!rep || !rep.score) return json({ url: fallback, saved: false, reason: "expired" });
  const dk = `shd:${sha(host + "|" + rep.createdAt).slice(0, 24)}`;
  const existing = await getJSON(dk);
  if (typeof existing === "string" && ID_RE.test(existing)) return json({ url: `/r/${existing}`, saved: true });
  const id = randomBytes(16).toString("base64url");
  const w = await setJSON(`r:${id}`, slim(rep), TTL);
  if (!w.redis) return json({ url: fallback, saved: false, reason: "store_down" });
  await setJSON(dk, id, TTL);
  return json({ url: `/r/${id}`, saved: true });
}
