import { test } from "node:test";
import assert from "node:assert/strict";

test("gemini: skips 503/404 models quickly and caches the working one first", async () => {
  process.env.GEMINI_API_KEY = "test-dummy";
  delete process.env.GEMINI_MODEL;
  const { ask, models } = await import("../api/_lib/gemini.js?t=" + Date.now());
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const m = decodeURIComponent(String(url).split("/models/")[1].split(":")[0]);
    calls.push(m);
    if (m === "gemini-3.5-flash") return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: "ok" }] } }] }), { status: 200 });
    return new Response(JSON.stringify({ error: { message: "overloaded" } }), { status: m === "gemini-3.1-flash-lite" ? 503 : 404 });
  };
  try {
    const r = await ask({ prompt: "x", maxTokens: 10 });
    assert.equal(r.model, "gemini-3.5-flash");
    assert.deepEqual(calls, ["gemini-3.1-flash-lite", "gemini-3.5-flash"]);
    assert.equal(models()[0], "gemini-3.5-flash");
    calls.length = 0;
    await ask({ prompt: "x", maxTokens: 10 });
    assert.deepEqual(calls, ["gemini-3.5-flash"], "warm instance goes straight to the working model");
  } finally { globalThis.fetch = realFetch; delete process.env.GEMINI_API_KEY; }
});

test("gemini: an overloaded (503) model is skipped for about 60 seconds, then tried again", async () => {
  process.env.GEMINI_API_KEY = "test-dummy";
  process.env.GEMINI_MODEL = "m-a,m-b";
  const mod = await import("../api/_lib/gemini.js?o=" + Date.now());
  assert.equal(mod.OVERLOAD_SKIP_MS, 60000);
  globalThis.__ssc_caps.clear(); globalThis.__ssc_gm.model = "";
  const calls = []; const realFetch = globalThis.fetch; const realNow = Date.now; let t = realNow();
  Date.now = () => t;
  globalThis.fetch = async (url) => {
    const m = String(url).split("/models/")[1].split(":")[0]; calls.push(m);
    return m === "m-a" ? new Response(JSON.stringify({ error: { message: "overloaded" } }), { status: 503 }) : new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: "ok" }] } }] }), { status: 200 });
  };
  try {
    await mod.ask({ prompt: "x", maxTokens: 10 });
    assert.deepEqual(calls, ["m-a", "m-b"]);
    globalThis.__ssc_gm.model = ""; calls.length = 0; t += 30e3;
    await mod.ask({ prompt: "x", maxTokens: 10 });
    assert.deepEqual(calls, ["m-b"], "still skipped after 30s");
    globalThis.__ssc_gm.model = ""; calls.length = 0; t += 31e3;
    await mod.ask({ prompt: "x", maxTokens: 10 });
    assert.deepEqual(calls, ["m-a", "m-b"], "tried again after 61s");
  } finally { globalThis.fetch = realFetch; Date.now = realNow; delete process.env.GEMINI_API_KEY; delete process.env.GEMINI_MODEL; }
});
