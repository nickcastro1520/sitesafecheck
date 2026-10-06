import test from "node:test";
import assert from "node:assert/strict";

process.env.GEMINI_API_KEY = "test-key";
process.env.GEMINI_MODEL = "gemini-a,gemini-b";
const { explain, parseAiJson, BANNED } = await import("../api/_lib/explain.js");
const { decorate } = await import("../api/_lib/scan.js");
const { scoreFindings } = await import("../api/_lib/score.js");

const findings = decorate([
  { id: "hsts", status: "fail", severity: "medium", evidence: "No Strict-Transport-Security header." },
  { id: "dmarc", status: "warn", severity: "medium", evidence: "_dmarc.a.com: v=DMARC1; p=none" },
  { id: "exposed_files", status: "fail", severity: "high", evidence: "/.env: readable" },
  { id: "cert_valid", status: "pass", severity: "high", evidence: "Trusted certificate." },
]);
const ctx = { host: "a.com", cms: "WordPress", server: "nginx", emailProviders: ["Google Workspace"] };
const scoreInfo = scoreFindings(findings);

let calls = [];
function mockGemini(handler) {
  calls = [];
  globalThis.fetch = async (url, opts) => {
    const body = JSON.parse(opts.body);
    calls.push({ url: String(url), body, key: opts.headers["x-goog-api-key"] });
    return handler(String(url), body);
  };
}
const ok = (obj) => new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: typeof obj === "string" ? obj : JSON.stringify(obj) }] }, finishReason: "STOP" }] }), { status: 200 });

test("ONE batched call explains every non-passing finding; passes keep hand-written copy", async () => {
  mockGemini(() => ok({ summary: "Your site has a few gaps. Start by adding HSTS so browsers always use HTTPS.", items: [
    { id: "hsts", what: "Browsers aren't told to stick to HTTPS on your WordPress site.", fix: "Add Strict-Transport-Security: max-age=31536000 in your nginx config." },
    { id: "dmarc", what: "Fake emails using your domain still get delivered.", fix: "Change p=none to p=quarantine once reports look clean." },
    { id: "exposed_files", what: "Your settings file can be downloaded by anyone.", fix: "Just delete it yourself in five minutes." },
    { id: "made_up", what: "This finding does not exist at all.", fix: "Ignore me please." },
  ] }));
  const r = await explain(findings, ctx, { useAi: true, scoreInfo });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].key, "test-key");
  assert.match(calls[0].url, /gemini-a:generateContent$/);
  assert.equal(calls[0].body.generationConfig.responseMimeType, "application/json");
  const prompt = calls[0].body.contents[0].parts[0].text;
  assert.ok(prompt.includes('"id":"hsts"') && prompt.includes('"id":"dmarc"') && !prompt.includes('"id":"cert_valid"'));
  const get = (id) => r.findings.find((f) => f.id === id);
  assert.equal(get("hsts").textSource, "ai");
  assert.match(get("hsts").fix, /nginx/);
  assert.equal(get("exposed_files").textSource, "ai");
  assert.match(get("exposed_files").fix, /security professional.*urgently/i, "referred-out fixes always keep the hand-written copy");
  assert.equal(get("cert_valid").textSource, "fallback");
  assert.ok(!r.findings.some((f) => f.id === "made_up"), "AI can't add findings");
  assert.equal(r.findings.length, findings.length);
  assert.match(r.summary, /HSTS/);
  assert.equal(r.ai.used, true);
});

test("AI text that calls the site secure or sells pentests is rejected per item", async () => {
  mockGemini(() => ok({ summary: "Your site is secure overall.", items: [
    { id: "hsts", what: "After this fix your site is secure and hack-proof.", fix: "Add the header." },
    { id: "dmarc", what: "Fake emails using your domain still get delivered.", fix: "Get a penetration test to be sure." },
  ] }));
  const r = await explain(findings, ctx, { useAi: true, scoreInfo });
  assert.equal(r.findings.find((f) => f.id === "hsts").textSource, "fallback");
  assert.equal(r.findings.find((f) => f.id === "dmarc").textSource, "fallback");
  assert.doesNotMatch(r.summary, /is secure/);
});

test("falls through to the next model on 404/429 and uses fallback copy when all fail", async () => {
  mockGemini((url) => url.includes("gemini-a") ? new Response(JSON.stringify({ error: { status: "NOT_FOUND", message: "model not found" } }), { status: 404 }) : ok("```json\n{\"summary\":\"Two things need attention on this site today.\",\"items\":[{\"id\":\"hsts\",\"what\":\"Browsers aren't told to stick to HTTPS.\",\"fix\":\"Add the HSTS header.\"}]}\n```"));
  let r = await explain(findings, ctx, { useAi: true, scoreInfo });
  assert.equal(r.ai.model, "gemini-b");
  assert.equal(r.findings.find((f) => f.id === "hsts").textSource, "ai");
  assert.equal(r.findings.find((f) => f.id === "dmarc").textSource, "fallback");

  mockGemini(() => new Response(JSON.stringify({ error: { status: "RESOURCE_EXHAUSTED", message: "busy" } }), { status: 429 }));
  r = await explain(findings, ctx, { useAi: true, scoreInfo });
  assert.equal(r.ai.used, false);
  assert.ok(r.findings.every((f) => f.textSource === "fallback" && f.what));
  assert.match(r.summary, /a\.com scored/);
});

test("garbage output and disabled AI both fall back cleanly, without calling Gemini when disabled", async () => {
  mockGemini(() => ok("I'm sorry, I can't help with that."));
  let r = await explain(findings, ctx, { useAi: true, scoreInfo });
  assert.equal(r.ai.reason, "bad_output");
  mockGemini(() => { throw new Error("should not be called"); });
  r = await explain(findings, ctx, { useAi: false, scoreInfo });
  assert.equal(calls.length, 0);
  assert.equal(r.ai.used, false);
});

test("parseAiJson and banned words", () => {
  assert.deepEqual(parseAiJson('```json\n{"a":1}\n```'), { a: 1 });
  assert.equal(parseAiJson("nope"), null);
  assert.ok(BANNED.test("We recommend a pentest"));
  assert.ok(BANNED.test("your site is safe"));
  assert.ok(!BANNED.test("Add the header so browsers always use HTTPS."));
});
