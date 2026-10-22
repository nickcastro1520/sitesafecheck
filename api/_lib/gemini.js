// Minimal Gemini REST client (generateContent), no SDK. Same pattern as doesaiknowmybusiness:
// tries models in order (GEMINI_MODEL, comma separated) and falls through on "no access",
// "quota 0", and per-model 429s, remembering failures per instance. No Google Search
// grounding here: the explanations only rewrite findings we already measured.
const API = "https://generativelanguage.googleapis.com/v1beta/models";

export const isConfigured = () => Boolean(process.env.GEMINI_API_KEY);
// Order = what answered with the key (probed Oct 22, 2026, 3 rounds each: 3.1-flash-lite 200 x2 / 503 x1
// in about 1s; 3.5-flash 200 x3 in about 1s; 3.5-flash-lite timed out at 9s x3; 3.8-flash 503 x3).
// Live scans that day also showed 3.5-flash-lite timing out before 3.1-flash-lite answered. The model that last
// worked on this warm instance is always tried first; 404/403 models are skipped for 6 hours.
export const DEFAULT_MODELS = "gemini-3.1-flash-lite,gemini-3.5-flash,gemini-3.5-flash-lite,gemini-3.8-flash";
const good = globalThis.__ssc_gm || (globalThis.__ssc_gm = { model: "" });
export const models = () => {
  const list = (process.env.GEMINI_MODEL || DEFAULT_MODELS).split(",").map((s) => s.trim()).filter(Boolean);
  return good.model && list.includes(good.model) ? [good.model, ...list.filter((m) => m !== good.model)] : list;
};
const ATTEMPT_MS = 9000;   // per model
const TOTAL_MS = 20000;    // all attempts together

const caps = globalThis.__ssc_caps || (globalThis.__ssc_caps = new Map());
const blocked = (k) => { const e = caps.get(k); if (!e) return false; if (e < Date.now()) { caps.delete(k); return false; } return true; };
const block = (k, ms) => caps.set(k, Date.now() + ms);
const HOUR = 3600e3;

export class GeminiError extends Error {
  constructor(code, message, status, trail) { super(message); this.code = code; this.status = status; this.trail = trail || []; }
}

const scrub = (s) => String(s || "").replace(/AIza[0-9A-Za-z_\-]{20,}/g, "[key]").replace(/key=[^&\s]+/gi, "key=[key]").slice(0, 300);

function genConfig(model, maxTokens, json) {
  const cfg = { maxOutputTokens: maxTokens, temperature: 0.3 };
  if (/^gemini-2\.5/.test(model)) cfg.thinkingConfig = { thinkingBudget: /pro/.test(model) ? 128 : 0 };
  else cfg.thinkingConfig = { thinkingLevel: "low" };
  if (json) cfg.responseMimeType = "application/json";
  return cfg;
}

async function callOnce(model, { prompt, system, maxTokens, json, timeout = 20000 }) {
  const body = {
    contents: [{ role: "user", parts: [{ text: prompt }] }],
    generationConfig: genConfig(model, maxTokens + (/^gemini-2\.5/.test(model) ? 0 : 800), json),
  };
  if (system) body.systemInstruction = { parts: [{ text: system }] };
  const r = await fetch(`${API}/${encodeURIComponent(model)}:generateContent`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-goog-api-key": process.env.GEMINI_API_KEY },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeout),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const det = (j?.error?.details || []).map((d) => [d.violations?.map((v) => `${v.quotaMetric || ""} ${v.quotaId || ""} ${v.quotaValue ?? ""}`).join(";"), d.reason].filter(Boolean).join(" ")).join(" ");
    throw new GeminiError(r.status === 429 ? "busy" : "api", scrub(`${j?.error?.status || ""} ${j?.error?.message || `HTTP ${r.status}`} ${det}`), r.status);
  }
  const cand = j.candidates?.[0];
  const text = (cand?.content?.parts || []).filter((p) => p.text && !p.thought).map((p) => p.text).join("").trim();
  if (!text) throw new GeminiError("api", `empty (${cand?.finishReason || "no candidate"})`, 200);
  return { text, model, finish: cand?.finishReason || "", tokens: j.usageMetadata?.totalTokenCount || 0 };
}

const zeroQuota = (m) => /limit:\s*0\b|quotaValue\D*0\b| 0$|free_tier[^;]*\s0(\s|;|$)/i.test(m);

export async function ask(opts) {
  if (!isConfigured()) throw new GeminiError("not_configured", "GEMINI_API_KEY is not set");
  const trail = [];
  let sawBusy = false;
  const end = Date.now() + (opts.totalMs || TOTAL_MS);
  for (const model of models()) {
    if (blocked("m:" + model)) continue;
    const left = end - Date.now();
    if (left < 1500) break;
    try {
      const res = await callOnce(model, { ...opts, timeout: Math.min(opts.timeout || ATTEMPT_MS, left) });
      good.model = model;
      res.trail = trail;
      return res;
    } catch (e) {
      const msg = e.message || "";
      trail.push({ model, status: e.status || 0, msg: msg.slice(0, 200) });
      if (good.model === model) good.model = "";
      if (e.name === "TimeoutError" || e.name === "AbortError") continue;
      if (e.status === 404 || e.status === 403 || (e.status === 400 && /model|not found|not supported|no longer available|unavailable/i.test(msg))) { block("m:" + model, 6 * HOUR); continue; }
      if (e.status === 503 || e.status === 500) { block("m:" + model, 10 * 60e3); continue; } // overloaded: skip it for 10 minutes
      if (e.status === 429) {
        if (zeroQuota(msg)) { block("m:" + model, 6 * HOUR); continue; }
        if (/per ?day|PerDay|daily/i.test(msg)) { block("m:" + model, HOUR); continue; }
        sawBusy = true; continue;
      }
      if (e.status === 401 || /API key not valid|API_KEY_INVALID/i.test(msg)) throw new GeminiError("api", "invalid key", e.status, trail);
      continue;
    }
  }
  throw new GeminiError(sawBusy ? "busy" : "api", "No Gemini model available for this API key", 429, trail);
}
