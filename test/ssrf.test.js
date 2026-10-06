import test from "node:test";
import assert from "node:assert/strict";
import { isBlockedIp, normalizeTarget, resolvePublic, pinnedLookup, realRequest, fetchFollow, _setLookup, _setRequest, v6Bytes } from "../api/_lib/net.js";

test("blocks private, loopback, link-local, metadata, CGNAT, multicast and reserved IPv4", () => {
  for (const ip of ["127.0.0.1", "127.255.255.254", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "169.254.0.1", "100.64.0.1", "100.127.255.255", "0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", "192.0.2.10", "198.51.100.7", "203.0.113.9", "198.18.0.1", "192.0.0.170"]) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
});

test("allows ordinary public IPv4", () => {
  for (const ip of ["8.8.8.8", "1.1.1.1", "140.82.112.3", "76.76.21.21", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1", "11.0.0.1", "169.253.1.1"]) {
    assert.equal(isBlockedIp(ip), false, ip);
  }
});

test("blocks IPv6 loopback, ULA (incl. AWS IPv6 metadata), link-local, mapped/compat/NAT64/6to4/Teredo, docs, multicast", () => {
  for (const ip of ["::1", "::", "fd00:ec2::254", "fc00::1", "fe80::1", "fe80::1%eth0", "fec0::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:7f00:1", "::ffff:a9fe:a9fe", "::127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::808:808", "2002:7f00:1::1", "2001:0:4136:e378::1", "2001:db8::1", "100::1", "[::1]", "::ffff:0.0.0.0"]) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
});

test("allows public IPv6 and public IPv4-mapped addresses", () => {
  for (const ip of ["2606:4700:4700::1111", "2a00:1450:4001:82a::200e", "2620:1ec:bdf::10", "::ffff:8.8.8.8"]) assert.equal(isBlockedIp(ip), false, ip);
});

test("non-IP strings are treated as blocked", () => {
  for (const s of ["", "localhost", "example.com", "1.2.3", "999.1.1.1", null, undefined]) assert.equal(isBlockedIp(s), true, String(s));
});

test("v6Bytes expands compressed and dotted forms", () => {
  assert.deepEqual([...v6Bytes("::ffff:1.2.3.4")].slice(10), [255, 255, 1, 2, 3, 4]);
  assert.equal(v6Bytes("2001:db8::1")[15], 1);
  assert.equal(v6Bytes("not-ip"), null);
});

test("normalizeTarget accepts domains and strips paths, case and default ports", () => {
  assert.deepEqual(normalizeTarget("Example.COM"), { host: "example.com", url: "https://example.com/" });
  assert.equal(normalizeTarget("https://www.shop.co.uk/path?q=1#x").host, "www.shop.co.uk");
  assert.equal(normalizeTarget("http://example.com:80/").host, "example.com");
  assert.equal(normalizeTarget("example.com:443").host, "example.com");
  assert.equal(normalizeTarget("xn--bcher-kva.example.org").host, "xn--bcher-kva.example.org");
  assert.equal(normalizeTarget("bücher.de").host, "xn--bcher-kva.de");
});

test("normalizeTarget rejects localhost, private/metadata names, IP literals (all encodings), odd ports, userinfo, other schemes", () => {
  const cases = {
    blocked_target: ["localhost", "localhost:3000", "http://127.0.0.1/", "127.0.0.1", "0x7f000001", "http://2130706433/", "http://0177.0.0.1/", "[::1]", "http://[::ffff:127.0.0.1]/", "169.254.169.254", "metadata.google.internal", "metadata", "router.lan", "printer.local", "db.internal", "foo.localhost", "x.home.arpa", "1.0.0.10.in-addr.arpa", "example.com:8080", "example.com:22", "test.test", "secret.onion"],
    invalid_url: ["", "   ", "javascript:alert(1)", "file:///etc/passwd", "ftp://example.com", "gopher://x.com", "http://user:pass@example.com", "nodot", "exa mple.com", "example.c0m", "-bad-.com", "a".repeat(400) + ".com"],
  };
  for (const [code, list] of Object.entries(cases)) for (const s of list) {
    assert.throws(() => normalizeTarget(s), (e) => e.code === code, `${s} should be ${code}`);
  }
});

test("resolvePublic rejects a domain if ANY answer is private (no mixed answers)", async () => {
  _setLookup(async (h) => ({ "ok.com": [{ address: "93.184.215.14", family: 4 }], "mixed.com": [{ address: "93.184.215.14", family: 4 }, { address: "10.0.0.5", family: 4 }], "v6meta.com": [{ address: "fd00:ec2::254", family: 6 }], "mapped.com": [{ address: "::ffff:127.0.0.1", family: 6 }], "meta.com": [{ address: "169.254.169.254", family: 4 }] }[h] || []));
  assert.deepEqual(await resolvePublic("ok.com"), { address: "93.184.215.14", family: 4 });
  for (const h of ["mixed.com", "v6meta.com", "mapped.com", "meta.com"]) await assert.rejects(resolvePublic(h), (e) => e.code === "blocked_target", h);
  await assert.rejects(resolvePublic("nothing.com"), (e) => e.code === "dns_not_found");
});

test("resolvePublic prefers IPv4 when both families are returned", async () => {
  _setLookup(async () => [{ address: "2606:4700::1", family: 6 }, { address: "104.16.1.1", family: 4 }]);
  assert.equal((await resolvePublic("dual.com")).address, "104.16.1.1");
});

test("pinnedLookup always answers with the validated address (both callback styles)", async () => {
  const lk = pinnedLookup("93.184.215.14", 4);
  await new Promise((r) => lk("evil.com", {}, (e, a, f) => { assert.equal(a, "93.184.215.14"); assert.equal(f, 4); r(); }));
  await new Promise((r) => lk("evil.com", { all: true }, (e, list) => { assert.deepEqual(list, [{ address: "93.184.215.14", family: 4 }]); r(); }));
  await new Promise((r) => lk("evil.com", (e, a) => { assert.equal(a, "93.184.215.14"); r(); }));
});

test("realRequest refuses before connecting when DNS points inside, or the port/scheme is wrong", async () => {
  _setLookup(async () => [{ address: "127.0.0.1", family: 4 }]);
  await assert.rejects(realRequest("https://rebind.example.org/"), (e) => e.code === "blocked_target");
  await assert.rejects(realRequest("http://ok.example.org:8080/"), (e) => e.code === "blocked_target");
  await assert.rejects(realRequest("ftp://ok.example.org/"), (e) => e.code === "blocked_target");
});

test("fetchFollow re-validates every redirect hop", async () => {
  const seen = [];
  _setRequest(async (url) => {
    seen.push(url);
    if (url === "https://site.com/") return { url, status: 301, headers: { location: "http://169.254.169.254/latest/meta-data/" }, setCookies: [], body: "" };
    if (url === "https://site2.com/") return { url, status: 302, headers: { location: "https://site2.com:8443/admin" }, setCookies: [], body: "" };
    if (url === "https://site3.com/") return { url, status: 302, headers: { location: "/next" }, setCookies: [], body: "" };
    return { url, status: 200, headers: {}, setCookies: [], body: "ok" };
  });
  await assert.rejects(fetchFollow("https://site.com/"), (e) => e.code === "blocked_target" && e.hops.length === 1);
  await assert.rejects(fetchFollow("https://site2.com/"), (e) => e.code === "blocked_target");
  const r = await fetchFollow("https://site3.com/");
  assert.equal(r.final.url, "https://site3.com/next");
  assert.deepEqual(seen, ["https://site.com/", "https://site2.com/", "https://site3.com/", "https://site3.com/next"]);
});

test("fetchFollow stops after too many redirects", async () => {
  let n = 0;
  _setRequest(async (url) => ({ url, status: 302, headers: { location: `https://loop.com/${++n}` }, setCookies: [], body: "" }));
  const r = await fetchFollow("https://loop.com/", { maxRedirects: 3 });
  assert.equal(r.tooManyRedirects, true);
  assert.equal(n, 4);
});
