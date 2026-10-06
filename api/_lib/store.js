// Tiny key/value store. Uses Upstash Redis (REST) when configured,
// otherwise falls back to per-instance memory (good enough as a cost guard).
// Env is read per call so either naming pair works:
//   UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN
//   KV_REST_API_URL + KV_REST_API_TOKEN   (Vercel KV)
function redisEnv() {
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL || "";
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN || "";
  return { url, token };
}

// True only when a REST URL and token are both set. Never includes the secret.
export function isPersistent() {
  const { url, token } = redisEnv();
  return Boolean(url && token);
}

const mem = globalThis.__ssc_mem || (globalThis.__daikmb_mem = new Map());

function memGet(key) {
  const hit = mem.get(key);
  if (!hit) return null;
  if (hit.exp && hit.exp < Date.now()) { mem.delete(key); return null; }
  return hit.value;
}

async function redis(cmd) {
  const { url, token } = redisEnv();
  const r = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(cmd),
    signal: AbortSignal.timeout(3000),
  });
  if (!r.ok) throw new Error(`redis ${r.status}`);
  const j = await r.json();
  return j.result;
}

export async function getJSON(key) {
  if (isPersistent()) {
    try { const v = await redis(["GET", key]); return v ? JSON.parse(v) : null; } catch { /* fall through */ }
  }
  return memGet(key);
}

// Memory is always updated so a single instance (local dev, tests) can read it back.
// redis is true only when the value was written to Redis/KV.
export async function setJSON(key, value, ttlSec) {
  if (mem.size > 2000) mem.clear(); // keep memory bounded
  mem.set(key, { value, exp: Date.now() + ttlSec * 1000 });
  let redisOk = false;
  if (isPersistent()) {
    try { await redis(["SET", key, JSON.stringify(value), "EX", String(ttlSec)]); redisOk = true; } catch { /* ignore */ }
  }
  return { redis: redisOk };
}

// Atomic-ish counter with expiry. Returns the new count.
export async function incr(key, ttlSec) {
  if (isPersistent()) {
    try {
      const n = Number(await redis(["INCR", key]));
      if (!Number.isFinite(n)) throw new Error("redis incr");
      if (n === 1) {
        try { await redis(["EXPIRE", key, String(ttlSec)]); } catch { /* counter still valid */ }
      }
      return n;
    } catch { /* fall back to memory */ }
  }
  const cur = memGet(key) || 0;
  mem.set(key, { value: cur + 1, exp: Date.now() + ttlSec * 1000 });
  return cur + 1;
}

export async function decr(key) {
  if (isPersistent()) { try { await redis(["DECR", key]); return; } catch { /* ignore */ } }
  const hit = mem.get(key);
  if (hit && typeof hit.value === "number") hit.value = Math.max(0, hit.value - 1);
}
