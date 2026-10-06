// Plain-English explanations. ONE batched Gemini call per fresh scan explains every finding that
// needs attention; anything missing, malformed, or off-limits falls back to the hand-written copy
// in catalog.js. The AI never adds findings: it can only rewrite text for ids we send it.
import { ask, isConfigured } from "./gemini.js";
import { CATALOG, fallbackText } from "./catalog.js";

// Words the explanations must never contain: we don't claim safety and don't sell services
// the passive scan (or Nick) can't back up.
export const BANNED = /penetration|pen[ -]?test|pentest|guarantee|hack[- ]?proof|unhackable|100\s?%|fully secure|completely secure|totally secure|perfectly secure|(is|are|now) (secure|safe)\b|code audit|security audit|malware|breach|nick|hire (a|an|us)|contact us/i;

const clean = (s, max) => String(s || "").replace(/\*\*|__|^#+\s*|^[-•]\s*/gm, "").replace(/\s+/g, " ").trim().slice(0, max);

export const SYSTEM = `You explain passive website security scan results to small-business owners in plain, friendly English (8th-grade reading level).
Rules:
- Explain ONLY the findings provided. Never add, remove, or upgrade issues, and never guess about things not in the evidence.
- Never say or imply the website is secure, safe, or protected overall. A passive scan can't prove that.
- Don't recommend penetration tests, audits, or hiring anyone. Don't mention any company or person, except a hosting, platform, or email provider named in the input.
- "what": 1-2 short sentences on what this means for the business and its customers.
- "fix": 1-2 short sentences with concrete next steps, tailored to the platform/server in the input when known (e.g. a WordPress setting, an nginx or Apache line, a DNS TXT record). Use exact header names and values where useful.
- No markdown, no bullet characters, no links.
Return JSON only.`;

export function buildPrompt(findings, ctx) {
  const items = findings.map((f) => ({ id: f.id, check: CATALOG[f.id]?.title || f.id, status: f.status, severity: f.severity, evidence: f.evidence.slice(0, 300) }));
  return `Website: ${ctx.host}
Platform: ${ctx.cms || "unknown"}
Server header: ${ctx.server || "unknown"}
Email provider: ${ctx.emailProviders?.join(", ") || "unknown"}
Findings that need attention (JSON):
${JSON.stringify(items)}

Reply with exactly this JSON shape:
{"summary":"2-3 sentences: how this site did overall and the single most important next step. Do not call the site secure.","items":[{"id":"<id from the list>","what":"...","fix":"..."}]}
Include one item for every id in the list.`;
}

export function parseAiJson(text) {
  let s = String(text || "").trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "");
  const a = s.indexOf("{"); const b = s.lastIndexOf("}");
  if (a < 0 || b < a) return null;
  try { return JSON.parse(s.slice(a, b + 1)); } catch { return null; }
}

export function fallbackSummary(findings, scoreInfo, host) {
  const bad = findings.filter((f) => f.status === "fail" || f.status === "warn");
  const high = bad.filter((f) => f.severity === "high");
  const order = { high: 0, medium: 1, low: 2 };
  const top = [...bad].sort((x, y) => (order[x.severity] ?? 3) - (order[y.severity] ?? 3) || (x.status === "fail" ? -1 : 1))[0];
  const checks = findings.filter((f) => f.status !== "info" && f.status !== "error").length;
  if (!bad.length) return `${host} passed all ${checks} passive checks we ran, scoring ${scoreInfo.score}/100. That's a good sign, but a passive scan only looks at what's publicly visible, so it can't prove a site is secure. Keep certificates renewing automatically and re-check after site changes.`;
  return `${host} scored ${scoreInfo.score}/100 (grade ${scoreInfo.grade}) on ${checks} passive checks. ${bad.length} item${bad.length === 1 ? "" : "s"} need${bad.length === 1 ? "s" : ""} attention${high.length ? `, including ${high.length} high-priority` : ""}. Start with: ${CATALOG[top.id]?.title || top.id}.`;
}

function attachFallback(f) {
  const t = fallbackText(f);
  return { ...f, what: t.what, fix: t.fix, textSource: "fallback" };
}

// Returns { findings, summary, ai: { used, model, reason } }
export async function explain(findings, ctx, { useAi = true, scoreInfo } = {}) {
  const out = findings.map(attachFallback);
  const summary = fallbackSummary(findings, scoreInfo, ctx.host);
  const need = findings.filter((f) => f.status === "fail" || f.status === "warn").slice(0, 24);
  if (!need.length) return { findings: out, summary, ai: { used: false, reason: "nothing_to_explain" } };
  if (!useAi || !isConfigured()) return { findings: out, summary, ai: { used: false, reason: isConfigured() ? "budget" : "not_configured" } };
  try {
    const r = await ask({ system: SYSTEM, prompt: buildPrompt(need, ctx), maxTokens: 2400, json: true });
    const j = parseAiJson(r.text);
    if (!j || !Array.isArray(j.items)) return { findings: out, summary, ai: { used: false, reason: "bad_output", model: r.model } };
    const ids = new Set(need.map((f) => f.id));
    const byId = new Map();
    for (const it of j.items) {
      if (!it || !ids.has(it.id) || byId.has(it.id)) continue;
      const what = clean(it.what, 420); const fix = clean(it.fix, 420);
      if (what.length < 15 || fix.length < 10 || BANNED.test(what) || BANNED.test(fix)) continue;
      byId.set(it.id, { what, fix });
    }
    let used = 0;
    const merged = out.map((f) => {
      const ai = byId.get(f.id);
      if (!ai) return f;
      used++;
      // Referred-out issues always keep the hand-written "who should fix this" copy.
      return CATALOG[f.id]?.fixBy === "refer" ? { ...f, what: ai.what, textSource: "ai" } : { ...f, what: ai.what, fix: ai.fix, textSource: "ai" };
    });
    const s = clean(j.summary, 700);
    const aiSummary = s.length >= 30 && !BANNED.test(s) ? s : "";
    return { findings: merged, summary: aiSummary || summary, ai: { used: used > 0, model: r.model, explained: used, of: need.length, summary: Boolean(aiSummary) } };
  } catch (e) {
    return { findings: out, summary, ai: { used: false, reason: e.code || "error" } };
  }
}
