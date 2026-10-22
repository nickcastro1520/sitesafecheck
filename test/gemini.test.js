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
