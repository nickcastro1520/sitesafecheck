// SSRF-guarded network helpers. Every outbound request in a scan goes through here.
//
// Rules:
//  - Only http: and https: on the default ports (80 / 443). No userinfo, no IP literals typed by the user.
//  - The hostname is resolved once, EVERY resolved address must be public (IPv4, IPv6,
//    IPv4-mapped IPv6, NAT64, 6to4, Teredo, cloud metadata ranges are all checked), and the
//    socket is then pinned to that validated address with a custom `lookup`, so a second
//    DNS answer (DNS rebinding) can't swap in an internal IP between check and connect.
//  - Redirects are never followed automatically; callers re-run the whole check per hop.
//  - Hard wall-clock timeouts and response-body caps on every request.
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import net from "node:net";
import dns from "node:dns";
import zlib from "node:zlib";

export const UA = "SiteSafeCheck/1.0 (+https://sitesafecheck.com/about; passive security check requested by a site visitor)";

export class ScanError extends Error {
  constructor(code, message) { super(message || code); this.code = code; }
}

// ---------- IP classification ----------
function v4ToInt(ip) {
  const p = ip.split(".").map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
const V4_BLOCKS = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.31.196.0", 24], ["192.52.193.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["192.175.48.0", 24], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
].map(([base, bits]) => [v4ToInt(base), bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0]);

function isBlockedV4(ip) {
  const n = v4ToInt(ip);
  return V4_BLOCKS.some(([base, mask]) => ((n & mask) >>> 0) === base);
}

// Expand an IPv6 string (optionally with an embedded IPv4 tail or %zone) into 16 bytes.
export function v6Bytes(ip) {
  let s = String(ip).toLowerCase().replace(/^\[|\]$/g, "").split("%")[0];
  if (!net.isIPv6(s)) return null;
  let tail = [];
  const v4m = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4m) {
    tail = v4m[1].split(".").map(Number);
    s = s.slice(0, -v4m[1].length) + "0:0";
  }
  const [head, rest] = s.split("::");
  const hp = head ? head.split(":") : [];
  const rp = rest !== undefined ? (rest ? rest.split(":") : []) : null;
  const groups = rp === null ? hp : [...hp, ...Array(8 - hp.length - rp.length).fill("0"), ...rp];
  if (groups.length !== 8) return null;
  const out = new Uint8Array(16);
  groups.forEach((g, i) => { const v = parseInt(g || "0", 16); out[i * 2] = v >> 8; out[i * 2 + 1] = v & 255; });
  if (tail.length) out.set(tail, 12);
  return out;
}

const allZero = (b, from, to) => { for (let i = from; i < to; i++) if (b[i] !== 0) return false; return true; };

function isBlockedV6(ip) {
  const b = v6Bytes(ip);
  if (!b) return true;
  const v4 = (o) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
  if (allZero(b, 0, 16)) return true;                                   // ::
  if (allZero(b, 0, 15) && b[15] === 1) return true;                    // ::1
  if (allZero(b, 0, 10) && b[10] === 0xff && b[11] === 0xff) return isBlockedV4(v4(12)); // ::ffff:a.b.c.d
  if (allZero(b, 0, 12)) return true;                                   // ::a.b.c.d (deprecated IPv4-compatible)
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return true; // 64:ff9b::/96 + /48 NAT64
  if (b[0] === 0x01 && b[1] === 0x00 && allZero(b, 2, 8)) return true;  // 100::/64 discard
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00) return true; // 2001::/32 Teredo
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true; // 2001:db8::/32 docs
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && (b[3] & 0xf0) === 0x10) return true; // 2001:10::/28 ORCHID
  if (b[0] === 0x20 && b[1] === 0x02) return true;                      // 2002::/16 6to4 (embeds an IPv4)
  if ((b[0] & 0xfe) === 0xfc) return true;                              // fc00::/7 unique local (incl. fd00:ec2::254 metadata)
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;             // fe80::/10 link local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return true;             // fec0::/10 site local
  if (b[0] === 0xff) return true;                                       // multicast
  if ((b[0] & 0xe0) !== 0x20) return true;                              // only 2000::/3 is global unicast
  return false;
}

// True when the address must never be contacted.
export function isBlockedIp(ip) {
  const s = String(ip || "").trim();
  if (net.isIPv4(s)) return isBlockedV4(s);
  if (net.isIPv6(s.replace(/^\[|\]$/g, "").split("%")[0])) return isBlockedV6(s);
  return true; // not an IP at all
}

// ---------- user input ----------
const BLOCKED_SUFFIX = /(^|\.)(localhost|local|localdomain|internal|intranet|lan|home|corp|private|test|invalid|example|onion|arpa|home\.arpa)$/i;
const METADATA_NAMES = /^(metadata|metadata\.google\.internal|instance-data|169\.254\.169\.254)$/i;

// Turns what a visitor typed into { host, url } or throws ScanError.
export function normalizeTarget(input) {
  let s = String(input ?? "").trim();
  if (!s) throw new ScanError("invalid_url", "Enter a website address.");
  if (s.length > 300) throw new ScanError("invalid_url", "That address is too long.");
  if (/\s/.test(s)) throw new ScanError("invalid_url", "Website addresses can't contain spaces.");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(s) && !/^[^:]+:\d+(\/|$)/.test(s)) throw new ScanError("invalid_url", "Only http:// and https:// websites can be checked.");
    s = "https://" + s.replace(/^\/+/, "");
  }
  let u;
  try { u = new URL(s); } catch { throw new ScanError("invalid_url", "That doesn't look like a website address."); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new ScanError("invalid_url", "Only http:// and https:// websites can be checked.");
  if (u.username || u.password) throw new ScanError("invalid_url", "Remove the username or password from the address.");
  if (u.port && u.port !== "80" && u.port !== "443") throw new ScanError("blocked_target", "Only standard web ports (80 and 443) can be checked.");
  let host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (host.startsWith("[") || net.isIP(host)) throw new ScanError("blocked_target", "Enter a domain name (like yourbusiness.com), not an IP address.");
  if (METADATA_NAMES.test(host) || BLOCKED_SUFFIX.test(host)) throw new ScanError("blocked_target", "Private, internal, and reserved addresses can't be checked.");
  if (host.length > 253 || !host.includes(".")) throw new ScanError("invalid_url", "Enter a full domain, like yourbusiness.com.");
  const labels = host.split(".");
  if (!labels.every((l) => /^(xn--)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l) || /^xn--[a-z0-9-]+$/.test(l))) throw new ScanError("invalid_url", "That domain has characters that aren't allowed.");
  if (!/^([a-z]{2,63}|xn--[a-z0-9-]{2,59})$/.test(labels.at(-1))) throw new ScanError("invalid_url", "That doesn't look like a real domain ending.");
  return { host, url: `https://${host}/` };
}

// ---------- DNS ----------
let lookupImpl = (host) => dns.promises.lookup(host, { all: true, verbatim: true });
export function _setLookup(fn) { lookupImpl = fn; } // tests

// Resolve and validate. Throws blocked_target if ANY answer is non-public.
export async function resolvePublic(host) {
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new ScanError("blocked_target", "That address is private or reserved.");
    return { address: host, family: net.isIPv6(host) ? 6 : 4 };
  }
  let addrs; let t;
  try {
    addrs = await Promise.race([
      lookupImpl(host),
      new Promise((_, rej) => { t = setTimeout(() => rej(new ScanError("dns_timeout", "Looking up that domain took too long.")), 4000); }),
    ]);
  } catch (e) {
    if (e instanceof ScanError) throw e;
    throw new ScanError("dns_not_found", "We couldn't find that domain.");
  } finally { clearTimeout(t); }
  if (!addrs || !addrs.length) throw new ScanError("dns_not_found", "We couldn't find that domain.");
  for (const a of addrs) if (isBlockedIp(a.address)) throw new ScanError("blocked_target", "That domain points to a private or internal address, so it can't be checked.");
  const pick = addrs.find((a) => a.family === 4) || addrs[0];
  return { address: pick.address, family: pick.family };
}

// A lookup function that always answers with the already-validated address.
export function pinnedLookup(address, family) {
  return (hostname, opts, cb) => {
    if (typeof opts === "function") { cb = opts; opts = {}; }
    if (opts && opts.all) cb(null, [{ address, family }]);
    else cb(null, address, family);
  };
}

function checkUrlForRequest(u) {
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new ScanError("blocked_target", "bad protocol");
  if (u.username || u.password) throw new ScanError("blocked_target", "userinfo");
  const defPort = u.protocol === "https:" ? "443" : "80";
  if (u.port && u.port !== defPort) throw new ScanError("blocked_target", "non-standard port");
}

function decoderFor(enc) {
  const e = String(enc || "").toLowerCase().trim();
  if (e === "gzip" || e === "x-gzip") return zlib.createGunzip();
  if (e === "deflate") return zlib.createInflate();
  if (e === "br") return zlib.createBrotliDecompress();
  return null;
}

function tlsInfo(socket) {
  if (!socket || typeof socket.getPeerCertificate !== "function") return null;
  let cert = {};
  try { cert = socket.getPeerCertificate() || {}; } catch {}
  return {
    authorized: Boolean(socket.authorized),
    error: socket.authorizationError ? String(socket.authorizationError) : "",
    protocol: (() => { try { return socket.getProtocol() || ""; } catch { return ""; } })(),
    validFrom: cert.valid_from || "",
    validTo: cert.valid_to || "",
    subject: cert.subject?.CN || "",
    issuer: cert.issuer?.O || cert.issuer?.CN || "",
    altNames: String(cert.subjectaltname || "").split(",").map((x) => x.trim().replace(/^DNS:/, "")).filter(Boolean).slice(0, 20),
  };
}

// One HTTP(S) request, no redirect following. Resolves to
// { url, status, headers, setCookies, body (string), bodyBytes (Buffer, capped), truncated, tls, ms }.
export async function realRequest(urlStr, { method = "GET", timeout = 8000, maxBytes = 1_000_000, accept = "text/html,application/xhtml+xml,*/*;q=0.8" } = {}) {
  const u = new URL(urlStr);
  checkUrlForRequest(u);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const { address, family } = await resolvePublic(host);
  const isHttps = u.protocol === "https:";
  const mod = isHttps ? https : http;
  const t0 = Date.now();
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (err, val) => { if (done) return; done = true; clearTimeout(timer); err ? reject(err) : resolve(val); };
    const req = mod.request({
      protocol: u.protocol, hostname: host, port: u.port || (isHttps ? 443 : 80),
      path: (u.pathname || "/") + (u.search || ""), method,
      headers: { "User-Agent": UA, Accept: accept, "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-US,en;q=0.8", Connection: "close" },
      lookup: pinnedLookup(address, family),
      agent: false,
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false, // we record certificate problems ourselves instead of failing blind
      ALPNProtocols: ["http/1.1"],
    }, (res) => {
      const info = isHttps ? tlsInfo(res.socket) : null;
      const headers = {};
      for (const [k, v] of Object.entries(res.headers)) if (k !== "set-cookie") headers[k] = Array.isArray(v) ? v.join(", ") : String(v);
      const setCookies = [].concat(res.headers["set-cookie"] || []);
      const chunks = []; let size = 0; let truncated = false;
      let stream = res;
      const dec = method === "HEAD" ? null : decoderFor(res.headers["content-encoding"]);
      if (dec) { res.pipe(dec); stream = dec; dec.on("error", () => end()); }
      const end = () => {
        const buf = Buffer.concat(chunks).subarray(0, maxBytes);
        finish(null, { url: u.href, status: res.statusCode, headers, setCookies, body: buf.toString("utf8"), bodyBytes: buf, truncated, tls: info, ms: Date.now() - t0, ip: address });
        res.destroy();
      };
      stream.on("data", (c) => {
        size += c.length; chunks.push(c);
        if (size >= maxBytes) { truncated = true; end(); }
      });
      stream.on("end", end);
      stream.on("error", end);
      res.on("aborted", end);
    });
    const timer = setTimeout(() => { req.destroy(new ScanError("timeout", "The site took too long to respond.")); }, timeout);
    req.on("error", (e) => finish(e instanceof ScanError ? e : Object.assign(new ScanError("connect_failed", e.code || e.message), { cause: e })));
    req.end();
  });
}

let requestImpl = realRequest;
export function _setRequest(fn) { requestImpl = fn; } // tests
export function request(url, opts) { return requestImpl(url, opts); }

// GET with manual redirects, re-validating the target (and its DNS) on every hop.
export async function fetchFollow(url, { maxRedirects = 5, ...opts } = {}) {
  const hops = [];
  let cur = new URL(url);
  for (let i = 0; i <= maxRedirects; i++) {
    let r;
    try {
      checkUrlForRequest(cur);
      if (net.isIP(cur.hostname.replace(/^\[|\]$/g, "")) && isBlockedIp(cur.hostname)) throw new ScanError("blocked_target", "Redirected to a private address.");
      r = await request(cur.href, opts);
    } catch (e) {
      e.hops = hops; e.failedUrl = cur.href;
      throw e;
    }
    hops.push(r);
    const loc = r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc) {
      let next;
      try { next = new URL(loc, cur); } catch { break; }
      if (next.protocol !== "http:" && next.protocol !== "https:") break;
      cur = next;
      continue;
    }
    return { final: r, hops };
  }
  return { final: hops.at(-1), hops, tooManyRedirects: true };
}

// Does the server still complete a TLS 1.0/1.1 handshake? Same SSRF pinning.
async function realLegacyTls(host, { timeout = 5000 } = {}) {
  const { address } = await resolvePublic(host);
  return new Promise((resolve) => {
    let done = false;
    const fin = (v) => { if (!done) { done = true; clearTimeout(t); try { s.destroy(); } catch {} resolve(v); } };
    let s;
    try {
      s = tls.connect({ host: address, port: 443, servername: host, minVersion: "TLSv1", maxVersion: "TLSv1.1", ciphers: "DEFAULT:@SECLEVEL=0", rejectUnauthorized: false }, () => fin({ tested: true, accepted: true, protocol: s.getProtocol() }));
    } catch { return resolve({ tested: false }); }
    s.on("error", (e) => fin(/unsupported protocol|no protocols available|wrong version/i.test(e.message) && !/alert/i.test(e.message) ? { tested: false } : { tested: true, accepted: false }));
    const t = setTimeout(() => fin({ tested: false }), timeout);
  });
}
let legacyImpl = realLegacyTls;
export function _setLegacyTls(fn) { legacyImpl = fn; }
export function legacyTls(host, opts) { return legacyImpl(host, opts); }

// DNS record lookups for email checks (public data, no SSRF concern: we never connect to these).
const resolver = new dns.promises.Resolver({ timeout: 2500, tries: 2 });
const dnsImpl = {
  txt: async (name) => (await resolver.resolveTxt(name)).map((parts) => parts.join("")),
  mx: async (name) => (await resolver.resolveMx(name)).map((r) => ({ exchange: r.exchange.toLowerCase(), priority: r.priority })),
};
let dnsOverride = null;
export function _setDns(obj) { dnsOverride = obj; }
const NODATA = /ENODATA|ENOTFOUND|NXDOMAIN|ENOTIMP/;
// Returns { records: [...] } or { records: [], error } (error only for timeouts / server failures).
export async function dnsQuery(type, name) {
  const impl = dnsOverride || dnsImpl;
  try { return { records: await impl[type](name) }; }
  catch (e) { return NODATA.test(e.code || e.message || "") ? { records: [] } : { records: [], error: e.code || "dns_error" }; }
}
