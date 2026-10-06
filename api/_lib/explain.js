// Plain-English explanations. ONE batched Gemini call per fresh scan explains every finding that
// needs attention; anything missing, malformed, or off-limits falls back to the hand-written copy
// in catalog.js. The AI never adds findings: it can only rewrite text for ids we send it.
import { ask, isConfigured } from "./gemini.js";
import { CATALOG, fallbackText } from "./catalog.js";

// Words the explanations must never contain: we don't claim safety and don't sell services
// the passive scan (or Nick) can't back up.
export const BANNED = /penetration|pen[ -]?test|pentest|guarantee|hack[- ]?proof|unhackable|100\s?%|fully secure|completely secure|totally secure|perfectly secure|(is|are|now) (secure|safe)\b|code audit|security audit|malware|breach|nick|hire (a|an|us)|contact us/i;

// Extra limits for the "worst case" line: no claims that something already happened or definitely
// will, and no statistics. It must stay hedged ("could", "might").
export const WORST_BANNED = /\b(will|won't|definitely|certainly|surely|guaranteed?|already|has been|have been|is being|are being|currently being|right now|likely being)\b|\d+\s?%|\bpercent\b|\bmillions?\b|\bbillions?\b|\bthousands\b|\bhundreds\b|\b\d[\d,]*\s+(people|users|visitors|customers|businesses|sites|websites|companies|attacks|times|days)\b|\b(most|many) (attacks|breaches|hacks|small businesses)\b|\bstud(y|ies)\b|\bresearch\b|\bstatistic/i;
// Nothing the AI writes may carry a copy-paste fix: header syntax, DNS record contents, config
// directives, code, markup, or step-by-step instructions. "How it's fixed" always comes from catalog.js.
export const SNIPPET = /`|<|>|\{|\}|\w=|=\s*["'(\w]|\b[A-Z][A-Za-z]*(-[A-Za-z]+)+:\s*\S|max-age|v=dmarc1|v=spf1|v=dkim1|include:|_dmarc|_domainkey|\b(nosniff|sameorigin|unsafe-inline|unsafe-eval|frame-ancestors|strict-origin|no-referrer|servertokens|server_tokens|expose_php|add_header|header set|htaccess|nginx\.conf|httpd\.conf|wp-config|functions\.php|options -indexes)\b|\.php\b|\b(step \d|navigate to|copy and paste|paste this|paste the)\b|(^|\s)[-~?+]all\b|\b\d{5,}\b/i;
const HEDGE = /\b(could|might|may|can)\b/i;

const clean = (s, max) => String(s || "").replace(/\*\*|__|^#+\s*|^[-•]\s*/gm, "").replace(/\s+/g, " ").trim().slice(0, max);

export const SYSTEM = `You explain passive website security scan results to small-business owners in plain, friendly English (8th-grade reading level).
Rules:
- Explain ONLY the findings provided. Never add, remove, or upgrade issues, and never guess about things not in the evidence.
- Never say or imply the website is secure, safe, or protected overall. A passive scan can't prove that.
- Don't recommend penetration tests, audits, or hiring anyone. Don't mention any company or person, except a hosting, platform, or email provider named in the input.
- "what": 1-2 short sentences on what this means for the business and its customers.
- Never include how-to details anywhere: no header values, DNS record names or contents, config lines, code, or step-by-step instructions. (A separate, fixed line covers how it's fixed.)
- "worst": ONE short sentence (under 25 words) on the realistic worst case if this specific issue is left alone, grounded in its evidence. Concrete and a little alarming, but truthful: use "could" or "might", say who could do what to whom (e.g. "A scammer could invisibly frame your site to trick visitors into clicking things they didn't mean to", "Anyone could send email that looks like it came from you to your customers", "Someone on the same Wi-Fi could read what your visitors type"). Scale it to severity: high = serious but realistic harm, medium = a concrete risk, low = a mild, limited consequence. Each item includes a human-written "baseline" worst case: keep the same level of seriousness or milder (never more alarming, never a bigger harm), and tailor the wording to the evidence and platform. Be technically accurate: for example, browsers still ask visitors before a site can use the camera, microphone, or location, and old TLS versions only affect visitors on old devices. Never say or imply the site is, was, or has been hacked, infected, or attacked. No statistics, numbers, or percentages. No "will" or other certainty words. Don't mention fixing, testing, audits, cleanup, or any service.
- No markdown, no bullet characters, no links.
Return JSON only.`;

export function buildPrompt(findings, ctx) {
  const items = findings.map((f) => ({ id: f.id, check: CATALOG[f.id]?.title || f.id, status: f.status, severity: f.severity, evidence: f.evidence.slice(0, 300), baseline: fallbackText(f).worst }));
  return `Website: ${ctx.host}
Platform: ${ctx.cms || "unknown"}
Server header: ${ctx.server || "unknown"}
Email provider: ${ctx.emailProviders?.join(", ") || "unknown"}
Findings that need attention (JSON):
${JSON.stringify(items)}

Reply with exactly this JSON shape:
{"summary":"2-3 sentences: how this site did overall and the single most important next step. Do not call the site secure.","items":[{"id":"<id from the list>","what":"...","worst":"..."}]}
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

// One hedged sentence, or "" if it overclaims, uses statistics, or sells something.
export function cleanWorst(text) {
  let w = clean(text, 400);
  const m = w.match(/^.+?[.!?](?=\s|$)/);
  if (m) w = m[0];
  if (!/[.!?]$/.test(w)) w += ".";
  if (w.length < 25 || w.length > 220) return "";
  if (!HEDGE.test(w) || BANNED.test(w) || WORST_BANNED.test(w) || SNIPPET.test(w)) return "";
  return w;
}

function attachFallback(f) {
  const t = fallbackText(f);
  const bad = f.status === "fail" || f.status === "warn";
  return { ...f, what: t.what, fix: t.fix, ...(bad && t.worst ? { worst: t.worst, worstSource: "fallback" } : {}), textSource: "fallback" };
}

// Returns { findings, summary, ai: { used, model, reason } }
export async function explain(findings, ctx, { useAi = true, scoreInfo } = {}) {
  const out = findings.map(attachFallback);
  const summary = fallbackSummary(findings, scoreInfo, ctx.host);
  const need = findings.filter((f) => f.status === "fail" || f.status === "warn").slice(0, 24);
  if (!need.length) return { findings: out, summary, ai: { used: false, reason: "nothing_to_explain" } };
  if (!useAi || !isConfigured()) return { findings: out, summary, ai: { used: false, reason: isConfigured() ? "budget" : "not_configured" } };
  try {
    const r = await ask({ system: SYSTEM, prompt: buildPrompt(need, ctx), maxTokens: 3000, json: true });
    const j = parseAiJson(r.text);
    if (!j || !Array.isArray(j.items)) return { findings: out, summary, ai: { used: false, reason: "bad_output", model: r.model } };
    const ids = new Set(need.map((f) => f.id));
    const byId = new Map();
    for (const it of j.items) {
      if (!it || !ids.has(it.id) || byId.has(it.id)) continue;
      const what = clean(it.what, 420);
      if (what.length < 15 || BANNED.test(what) || SNIPPET.test(what)) continue;
      byId.set(it.id, { what, worst: cleanWorst(it.worst) });
    }
    let used = 0;
    const merged = out.map((f) => {
      const ai = byId.get(f.id);
      if (!ai) return f;
      used++;
      // A worst case that fails the filters keeps the hand-written one.
      const w = ai.worst ? { worst: ai.worst, worstSource: "ai" } : {};
      // "How it's fixed" (and the refer-out wording) always stays the hand-written catalog line.
      return { ...f, what: ai.what, ...w, textSource: "ai" };
    });
    const s = clean(j.summary, 700);
    const aiSummary = s.length >= 30 && !BANNED.test(s) && !SNIPPET.test(s) ? s : "";
    return { findings: merged, summary: aiSummary || summary, ai: { used: used > 0, model: r.model, explained: used, of: need.length, worst: merged.filter((f) => f.worstSource === "ai").length, summary: Boolean(aiSummary) } };
  } catch (e) {
    return { findings: out, summary, ai: { used: false, reason: e.code || "error" } };
  }
}
