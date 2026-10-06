import test from "node:test";
import assert from "node:assert/strict";

process.env.GEMINI_API_KEY = "test-key";
process.env.GEMINI_MODEL = "gemini-a,gemini-b";
const { explain, parseAiJson, BANNED, SNIPPET, cleanWorst } = await import("../api/_lib/explain.js");
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
    { id: "hsts", what: "Browsers aren't told to stick to HTTPS on your WordPress site.", fix: "Add Strict-Transport-Security: max-age=31536000 in your nginx config.", worst: "Someone on the same public Wi-Fi could quietly downgrade a visitor's first visit to an unencrypted page." },
    { id: "dmarc", what: "Fake emails using your domain still get delivered.", fix: "Change p=none to p=quarantine once reports look clean.", worst: "Hackers send 3.4 billion fake emails a day and will target you." },
    { id: "exposed_files", what: "Your settings file can be downloaded by anyone.", fix: "Just delete it yourself in five minutes.", worst: "Anyone could download that settings file and use any passwords in it to get into your site. Act now." },
    { id: "made_up", what: "This finding does not exist at all.", fix: "Ignore me please.", worst: "This could be anything at all, really." },
  ] }));
  const r = await explain(findings, ctx, { useAi: true, scoreInfo });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].key, "test-key");
  assert.match(calls[0].url, /gemini-a:generateContent$/);
  assert.equal(calls[0].body.generationConfig.responseMimeType, "application/json");
  const prompt = calls[0].body.contents[0].parts[0].text;
  assert.ok(prompt.includes('"id":"hsts"') && prompt.includes('"id":"dmarc"') && !prompt.includes('"id":"cert_valid"'));
  const get = (id) => r.findings.find((f) => f.id === id);
  assert.ok(prompt.includes('"worst":"..."') && !prompt.includes('"fix":"..."'), "same single call asks for the worst case, never for a fix");
  assert.equal(get("hsts").textSource, "ai");
  assert.equal(get("hsts").fix, "Fixed with a server or hosting configuration change (adding a security header).", "How it's fixed always comes from the catalog");
  assert.doesNotMatch(JSON.stringify(r), /max-age|p=quarantine|nginx config/, "AI fix snippets never reach the report");
  assert.equal(get("hsts").worstSource, "ai");
  assert.match(get("hsts").worst, /^Someone on the same public Wi-Fi could/);
  assert.equal(get("dmarc").textSource, "ai");
  assert.equal(get("dmarc").worstSource, "fallback", "statistics and certainty words are rejected");
  assert.match(get("dmarc").worst, /could/);
  assert.equal(get("exposed_files").textSource, "ai");
  assert.equal(get("exposed_files").worst, "Anyone could download that settings file and use any passwords in it to get into your site.", "trimmed to one sentence");
  assert.match(get("exposed_files").fix, /security professional/i);
  assert.match(get("exposed_files").fix, /urgently/i, "referred-out fixes always keep the hand-written copy");
  assert.equal(get("cert_valid").worst, undefined, "passing items get no worst case");
  assert.equal(get("cert_valid").textSource, "fallback");
  assert.ok(!r.findings.some((f) => f.id === "made_up"), "AI can't add findings");
  assert.equal(r.findings.length, findings.length);
  assert.match(r.summary, /HSTS/);
  assert.equal(r.ai.used, true);
});

test("AI text that calls the site secure or sells pentests is rejected per item", async () => {
  mockGemini(() => ok({ summary: "Your site is secure overall.", items: [
    { id: "hsts", what: "After this fix your site is secure and hack-proof.", fix: "Add the header." },
    { id: "dmarc", what: "Get a penetration test to be sure fake emails are blocked.", fix: "Add the record." },
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

test("AI 'what' text that leaks a fix snippet falls back; worst-case filters", async () => {
  mockGemini(() => ok({ summary: "Add v=DMARC1; p=reject to fix email spoofing today.", items: [
    { id: "hsts", what: "Add the header Strict-Transport-Security: max-age=31536000 to your server.", worst: "Someone could intercept visitors." },
    { id: "dmarc", what: "Fake emails using your domain still get delivered to people.", worst: "Your site has been hacked and customers could be next." },
  ] }));
  const r = await explain(findings, ctx, { useAi: true, scoreInfo });
  const get = (id) => r.findings.find((f) => f.id === id);
  assert.equal(get("hsts").textSource, "fallback");
  assert.equal(get("dmarc").textSource, "ai");
  assert.equal(get("dmarc").worstSource, "fallback");
  assert.doesNotMatch(r.summary, /DMARC1/);
  for (const bad of ["A pentest could reveal more problems on your site.", "Hackers will steal your data.", "Anyone could do this to 60% of small sites.", "Your site was breached and could be again.", "Someone sees your traffic.", "Add X-Frame-Options: DENY or a scammer could frame you."]) assert.equal(cleanWorst(bad), "", bad);
  assert.equal(cleanWorst("A scammer could invisibly frame your site to trick visitors into clicking things they didn't mean to"), "A scammer could invisibly frame your site to trick visitors into clicking things they didn't mean to.");
  for (const leak of ["max-age=31536000", "v=spf1 include:_spf.google.com ~all", "set p=reject", "```nginx", "<meta>", "X-Frame-Options: SAMEORIGIN", "Options -Indexes", "Step 1: open Settings"]) assert.ok(SNIPPET.test(leak), leak);
  assert.ok(!SNIPPET.test("Browsers aren't told to always use HTTPS on your site, so a first visit could be intercepted."));
});
