// POST /api/scan  { url, authorized: true }  ->  { report, cached }
// GET  /api/scan  ->  status (AI on/off, persistence, limits). Never returns secrets.
import { createHash } from "node:crypto";
import { normalizeTarget, ScanError } from "./_lib/net.js";
import { collect, buildReport } from "./_lib/scan.js";
import { isConfigured, ask, DEFAULT_MODELS } from "./_lib/gemini.js";
import { getJSON, setJSON, incr, decr, isPersistent } from "./_lib/store.js";

const num = (v, d) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Number(v) : d);
const cfg = () => ({
  perHour: num(process.env.RATE_LIMIT_PER_HOUR, 10),
  perDay: num(process.env.RATE_LIMIT_PER_DAY, 30),
  burst: num(process.env.RATE_LIMIT_BURST, 30),         // all requests incl. cache hits, per 10 minutes
  dailyCap: num(process.env.DAILY_CAP, 1500),            // fresh scans per day, all visitors
  aiDailyCap: num(process.env.AI_DAILY_CAP, 300),        // Gemini calls per day, all visitors
  cacheSec: num(process.env.SCAN_CACHE_SECONDS, 600),    // short per-domain cache
});

const json = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...extra } });
const sha = (s) => createHash("sha256").update(s).digest("hex");
const inflight = globalThis.__ssc_inflight || (globalThis.__ssc_inflight = new Map());

let lastProbe = 0;
export async function GET(request) {
  // TEMPORARY model probe (removed after measuring): one tiny call per model, max once per 10 min per instance.
  if (request && new URL(request.url).searchParams.get("probe") === "models" && isConfigured() && Date.now() - lastProbe > 600000) {
    lastProbe = Date.now();
    const out = [];
    for (const m of (process.env.GEMINI_MODEL || DEFAULT_MODELS).split(",").map((x) => x.trim()).concat(["gemini-3.1-flash", "gemini-3-flash"])) {
      const t = Date.now();
      try { const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent`, { method: "POST", headers: { "Content-Type": "application/json", "x-goog-api-key": process.env.GEMINI_API_KEY }, body: JSON.stringify({ contents: [{ parts: [{ text: "Say OK" }] }], generationConfig: { maxOutputTokens: 400 } }), signal: AbortSignal.timeout(15000) }); out.push({ m, status: r.status, ms: Date.now() - t }); }
      catch (e) { out.push({ m, status: e.name, ms: Date.now() - t }); }
    }
    return json({ envOverride: Boolean(process.env.GEMINI_MODEL), out });
  }
  const c = cfg();
  return json({ ok: true, ai: isConfigured(), persistent: isPersistent(), limits: { perHour: c.perHour, perDay: c.perDay }, cacheSeconds: c.cacheSec });
}

function clientIp(request) {
  return (request.headers.get("x-real-ip") || request.headers.get("x-forwarded-for") || "0").split(",")[0].trim().slice(0, 64);
}

// Browsers send Origin on cross-site POSTs; only accept our own pages (or no Origin, e.g. curl).
function originOk(request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const o = new URL(origin).host;
    const host = request.headers.get("x-forwarded-host") || request.headers.get("host") || new URL(request.url).host;
    const allowed = (process.env.ALLOWED_ORIGINS || "sitesafecheck.com,www.sitesafecheck.com").split(",").map((s) => s.trim()).filter(Boolean);
    return o === host || allowed.includes(o);
  } catch { return false; }
}

const ERRORS = {
  invalid_url: 400, blocked_target: 400, dns_not_found: 422, dns_timeout: 504, unreachable: 502, timeout: 504, connect_failed: 502,
};

export async function POST(request) {
  if (!originOk(request)) return json({ error: "forbidden", message: "Scans can only be started from sitesafecheck.com." }, 403);
  let body;
  try {
    const text = await request.text();
    if (text.length > 4000) return json({ error: "bad_request" }, 413);
    body = JSON.parse(text || "{}");
  } catch { return json({ error: "bad_request", message: "Bad request." }, 400); }
  if (body.company_website) return json({ error: "bad_request", message: "Bad request." }, 400); // honeypot
  if (body.authorized !== true) return json({ error: "authorization_required", message: "Please confirm you own this website or have permission to check it." }, 400);

  let target;
  try { target = normalizeTarget(body.url); }
  catch (e) { return json({ error: e.code || "invalid_url", message: e.message }, 400); }

  const c = cfg();
  const ip = clientIp(request);
  const ipH = sha(ip + (process.env.RL_SALT || "sitesafecheck")).slice(0, 20);
  const now = Date.now();
  const day = new Date(now).toISOString().slice(0, 10);
  const hour = new Date(now).toISOString().slice(0, 13);
  const win = Math.floor(now / 600000);

  // Record the visitor's ownership/permission confirmation (the form says "By scanning, you confirm
  // you own or manage this site"; the API still refuses requests without authorized: true).
  const confirmation = typeof body.confirmation === "string" ? body.confirmation.replace(/[^\w.-]/g, "").slice(0, 40) : "api";
  console.log(JSON.stringify({ evt: "scan_authorized", host: target.host, confirmation, ip: ipH, at: new Date(now).toISOString() }));

  if ((await incr(`rlb:${win}:${ipH}`, 700)) > c.burst) return json({ error: "rate_limited", message: "Too many requests. Please wait a few minutes." }, 429, { "Retry-After": "600" });

  const cacheKey = `scan:v2:${target.host}`;
  const cached = await getJSON(cacheKey);
  if (cached) return json({ report: cached, cached: true });
  const stream = body.stream === true;

  const hourKey = `rlh:${hour}:${ipH}`; const dayKey = `rld:${day}:${ipH}`; const capKey = `cap:${day}`;
  const nh = await incr(hourKey, 3700);
  const nd = await incr(dayKey, 26 * 3600);
  if (nh > c.perHour || nd > c.perDay) {
    await decr(hourKey); await decr(dayKey);
    return json({ error: "rate_limited", message: nh > c.perHour ? `You've run ${c.perHour} fresh checks this hour. Please try again later.` : `You've reached today's limit of ${c.perDay} checks. Please come back tomorrow.` }, 429, { "Retry-After": nh > c.perHour ? "3600" : "43200" });
  }
  if ((await incr(capKey, 26 * 3600)) > c.dailyCap) {
    await decr(hourKey); await decr(dayKey);
    return json({ error: "daily_cap", message: "SiteSafeCheck has hit its daily scan limit. Please try again tomorrow." }, 429);
  }

  // One scan per domain at a time on this instance; concurrent requests share it.
  // With stream:true the response is NDJSON: first the checks with hand-written copy
  // ({ phase: "checks" }) as soon as they finish, then the AI-worded report ({ phase: "final" }).
  let job = inflight.get(target.host);
  if (!job) {
    const raw = collect(target.host);
    const quick = raw.then((r) => buildReport(r, { useAi: false }));
    const full = raw.then(async (r) => {
      let useAi = false;
      if (isConfigured()) useAi = (await incr(`ai:${day}`, 26 * 3600)) <= c.aiDailyCap;
      const report = await buildReport(r, { useAi });
      await setJSON(cacheKey, report, c.cacheSec);
      return report;
    });
    job = { quick, full, aiPending: isConfigured() };
    quick.catch(() => {});
    full.catch(() => {}).finally(() => inflight.delete(target.host));
    inflight.set(target.host, job);
  }
  try {
    if (!stream) return json({ report: await job.full, cached: false });
    const first = await job.quick; // throws scan errors before any bytes are sent
    const enc = new TextEncoder();
    const body2 = new ReadableStream({
      async start(ctrl) {
        ctrl.enqueue(enc.encode(JSON.stringify({ phase: "checks", report: { ...first, ai: { pending: job.aiPending } }, cached: false }) + "\n"));
        try { ctrl.enqueue(enc.encode(JSON.stringify({ phase: "final", report: await job.full, cached: false }) + "\n")); }
        catch { ctrl.enqueue(enc.encode(JSON.stringify({ phase: "final", report: first, cached: false }) + "\n")); }
        ctrl.close();
      },
    });
    return new Response(body2, { status: 200, headers: { "Content-Type": "application/x-ndjson; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Accel-Buffering": "no" } });
  } catch (e) {
    const code = e instanceof ScanError ? e.code : "scan_failed";
    const status = ERRORS[code] || 500;
    const message = e instanceof ScanError && e.message && e.message !== code ? e.message : code === "scan_failed" ? "Something went wrong running the check. Please try again." : "We couldn't reach that website.";
    if (code !== "scan_failed") console.log("scan error", code); else console.error("scan failed", e?.stack || e);
    return json({ error: code, message }, status);
  }
}
