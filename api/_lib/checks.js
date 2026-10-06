// Pure analyzers: raw network results in, findings out. No I/O here, so every parser is unit-tested.
// A finding is { id, status: pass|warn|fail|info|error, severity: high|medium|low|info, evidence, data? }.
// Evidence is always something we actually observed (a header value, a DNS record, a status code).

const clip = (s, n = 240) => { s = String(s ?? "").replace(/[\u0000-\u001f\u007f]+/g, " ").trim(); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
const F = (id, status, severity, evidence, data) => ({ id, status, severity, evidence: clip(evidence, 600), ...(data ? { data } : {}) });

// ---------------- security headers ----------------
export function parseDirectives(csp) {
  const out = {};
  for (const part of String(csp || "").split(";")) {
    const bits = part.trim().split(/\s+/).filter(Boolean);
    if (!bits.length) continue;
    const name = bits[0].toLowerCase();
    if (!(name in out)) out[name] = bits.slice(1);
  }
  return out;
}

export function analyzeHeaders(h, { https }) {
  const out = [];
  const get = (k) => (h[k] ?? "").toString().trim();

  // HSTS
  const hsts = get("strict-transport-security");
  if (!https) out.push(F("hsts", "info", "medium", "Not applicable: the site didn't load over HTTPS, so browsers ignore this header."));
  else if (!hsts) out.push(F("hsts", "fail", "medium", "No Strict-Transport-Security header on the HTTPS home page."));
  else {
    const m = hsts.match(/max-age\s*=\s*"?(\d+)/i);
    const age = m ? Number(m[1]) : 0;
    const days = Math.floor(age / 86400);
    if (!m || age === 0) out.push(F("hsts", "fail", "medium", `Strict-Transport-Security: ${clip(hsts, 160)} (max-age is 0 or missing, so it does nothing)`));
    else if (age < 15552000) out.push(F("hsts", "warn", "medium", `Strict-Transport-Security: ${clip(hsts, 160)} (${age < 86400 ? `${Math.max(1, Math.round(age / 60))} minutes` : `${days} days`}; that's short, so browsers forget it quickly)`, { days }));
    else out.push(F("hsts", "pass", "medium", `Strict-Transport-Security: ${clip(hsts, 160)}`, { days }));
  }

  // CSP
  const csp = get("content-security-policy");
  const cspRO = get("content-security-policy-report-only");
  const d = parseDirectives(csp);
  if (!csp && cspRO) out.push(F("csp", "warn", "medium", `Only Content-Security-Policy-Report-Only is set (it reports but doesn't block): ${clip(cspRO, 200)}`));
  else if (!csp) out.push(F("csp", "fail", "medium", "No Content-Security-Policy header."));
  else {
    const script = d["script-src"] || d["default-src"];
    const weakInline = script && script.some((x) => x.toLowerCase() === "'unsafe-inline'") && !script.some((x) => /^'(nonce-|sha(256|384|512)-|strict-dynamic')/i.test(x));
    const unsafeEval = script && script.some((x) => x.toLowerCase() === "'unsafe-eval'");
    const wildcard = script && script.some((x) => x === "*" || /^(https?:|data:)$/i.test(x));
    if (!script) out.push(F("csp", "warn", "medium", `Content-Security-Policy is set but doesn't limit scripts (no script-src or default-src): ${clip(csp, 200)}`));
    else if (weakInline || wildcard) out.push(F("csp", "warn", "medium", `Content-Security-Policy allows ${weakInline ? "'unsafe-inline' scripts" : "scripts from anywhere"}${unsafeEval ? " and 'unsafe-eval'" : ""}, which weakens it: ${clip(csp, 200)}`));
    else out.push(F("csp", "pass", "medium", `Content-Security-Policy: ${clip(csp, 200)}`));
  }

  // Clickjacking: X-Frame-Options or CSP frame-ancestors
  const xfo = get("x-frame-options");
  const fa = d["frame-ancestors"];
  if (fa) out.push(F("x_frame_options", "pass", "medium", `Content-Security-Policy frame-ancestors ${clip(fa.join(" "), 120)}${xfo ? `; X-Frame-Options: ${clip(xfo, 40)}` : ""}`));
  else if (/^(deny|sameorigin)$/i.test(xfo)) out.push(F("x_frame_options", "pass", "medium", `X-Frame-Options: ${clip(xfo, 40)}`));
  else if (xfo) out.push(F("x_frame_options", "warn", "medium", `X-Frame-Options: ${clip(xfo, 80)} (not a value modern browsers honor)`));
  else out.push(F("x_frame_options", "fail", "medium", "No X-Frame-Options header and no frame-ancestors rule in a Content-Security-Policy."));

  // nosniff
  const xcto = get("x-content-type-options");
  if (/nosniff/i.test(xcto)) out.push(F("x_content_type_options", "pass", "low", `X-Content-Type-Options: ${clip(xcto, 40)}`));
  else out.push(F("x_content_type_options", "fail", "low", xcto ? `X-Content-Type-Options: ${clip(xcto, 60)} (not a value browsers recognize)` : "No X-Content-Type-Options header."));

  // Referrer-Policy (last recognized token wins, per spec)
  const rp = get("referrer-policy");
  const known = ["no-referrer", "no-referrer-when-downgrade", "same-origin", "origin", "strict-origin", "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url"];
  const tok = rp.split(",").map((x) => x.trim().toLowerCase()).filter((x) => known.includes(x)).pop();
  if (!rp) out.push(F("referrer_policy", "fail", "low", "No Referrer-Policy header (modern browsers fall back to a reasonable default, but older ones may leak full page addresses)."));
  else if (!tok) out.push(F("referrer_policy", "warn", "low", `Referrer-Policy: ${clip(rp, 80)} (not a recognized value)`));
  else if (tok === "unsafe-url" || tok === "no-referrer-when-downgrade") out.push(F("referrer_policy", "warn", "low", `Referrer-Policy: ${clip(rp, 80)} (shares full page addresses with other sites)`));
  else out.push(F("referrer_policy", "pass", "low", `Referrer-Policy: ${clip(rp, 80)}`));

  // Permissions-Policy
  const pp = get("permissions-policy");
  const fp = get("feature-policy");
  if (pp) out.push(F("permissions_policy", "pass", "low", `Permissions-Policy: ${clip(pp, 160)}`));
  else if (fp) out.push(F("permissions_policy", "warn", "low", `Only the old Feature-Policy header is set: ${clip(fp, 140)}`));
  else out.push(F("permissions_policy", "fail", "low", "No Permissions-Policy header."));

  return out;
}

// ---------------- version banners ----------------
export function analyzeBanners(h, html = "") {
  const issues = []; const notes = [];
  const server = (h["server"] || "").trim();
  if (server && /\d+\.\d+/.test(server)) issues.push({ level: "fail", text: `Server: ${clip(server, 80)}` });
  else if (server) notes.push(`Server: ${clip(server, 60)} (no version number shown)`);
  const xpb = (h["x-powered-by"] || "").trim();
  if (xpb && /\d/.test(xpb)) issues.push({ level: "fail", text: `X-Powered-By: ${clip(xpb, 80)}` });
  else if (xpb) issues.push({ level: "warn", text: `X-Powered-By: ${clip(xpb, 80)}` });
  for (const k of ["x-aspnet-version", "x-aspnetmvc-version"]) if (h[k]) issues.push({ level: "fail", text: `${k.replace(/(^|-)\w/g, (s) => s.toUpperCase())}: ${clip(h[k], 40)}` });
  const gen = (html.match(/<meta[^>]+name\s*=\s*["']?generator["']?[^>]*>/i) || [""])[0];
  const genVal = (gen.match(/content\s*=\s*["']([^"']+)["']/i) || [])[1] || "";
  if (genVal && /\d+\.\d+/.test(genVal)) issues.push({ level: "warn", text: `Page meta generator: ${clip(genVal, 60)}` });
  if (!issues.length) return F("server_banner", "pass", "low", notes.length ? `No software version numbers found in headers. ${notes.join("; ")}` : "No software version numbers found in the response headers or page generator tag.");
  const status = issues.some((i) => i.level === "fail") ? "fail" : "warn";
  return F("server_banner", status, "low", issues.map((i) => i.text).join("; "), { items: issues.map((i) => i.text) });
}

export function detectCms(html = "", h = {}) {
  if (/\/wp-content\/|\/wp-includes\/|name=["']generator["'][^>]*WordPress/i.test(html)) return "WordPress";
  if (/cdn\.shopify\.com|Shopify\.theme/i.test(html)) return "Shopify";
  if (/static\.wixstatic\.com|wix\.com/i.test(html) || /wix/i.test(h["x-wix-request-id"] ? "wix" : "")) return "Wix";
  if (/squarespace\.com|static1\.squarespace/i.test(html)) return "Squarespace";
  if (/Joomla!/i.test(html)) return "Joomla";
  if (/Drupal/i.test(h["x-generator"] || "") || /drupal-settings-json|\/sites\/default\/files\//i.test(html)) return "Drupal";
  if (/webflow/i.test(html.slice(0, 5000))) return "Webflow";
  if (/godaddy|img1\.wsimg\.com/i.test(html)) return "GoDaddy Website Builder";
  return "";
}

// ---------------- cookies ----------------
export function parseSetCookie(line) {
  const parts = String(line).split(";").map((s) => s.trim());
  const [nv, ...attrs] = parts;
  const eq = nv.indexOf("=");
  const name = (eq >= 0 ? nv.slice(0, eq) : nv).trim();
  const a = {};
  for (const x of attrs) {
    const i = x.indexOf("=");
    const k = (i >= 0 ? x.slice(0, i) : x).trim().toLowerCase();
    a[k] = i >= 0 ? x.slice(i + 1).trim() : true;
  }
  return { name, secure: "secure" in a, httpOnly: "httponly" in a, sameSite: typeof a.samesite === "string" ? a.samesite.toLowerCase() : a.samesite === true ? "invalid" : "" };
}
const SESSIONISH = /(sess|^sid$|_sid$|auth|token|login|logged|jwt|remember|csrf|xsrf|^wordpress_|^wp-|laravel|connect\.sid|ASP\.NET|JSESSIONID|PHPSESSID|ci_session)/i;
const names = (list) => list.slice(0, 8).map((c) => clip(c.name, 40)).join(", ") + (list.length > 8 ? ` +${list.length - 8} more` : "");

export function analyzeCookies(setCookieLines, { https }) {
  const cookies = []; const seen = new Set();
  for (const l of setCookieLines || []) { const c = parseSetCookie(l); if (c.name && !seen.has(c.name)) { seen.add(c.name); cookies.push(c); } }
  if (!cookies.length) return [F("cookies", "info", "info", "The home page didn't set any cookies, so there were no cookie flags to check.")];
  const out = [];
  const total = `${cookies.length} cookie${cookies.length === 1 ? "" : "s"} set by the home page`;
  if (!https) out.push(F("cookie_secure", "info", "low", `${total}; the Secure flag only matters once the site uses HTTPS.`));
  else {
    const bad = cookies.filter((c) => !c.secure);
    const badSess = bad.filter((c) => SESSIONISH.test(c.name));
    if (!bad.length) out.push(F("cookie_secure", "pass", "low", `${total}; all have the Secure flag.`));
    else out.push(F("cookie_secure", "fail", badSess.length ? "medium" : "low", `Missing the Secure flag: ${names(bad)} (of ${total}).`, { cookies: bad.map((c) => c.name).slice(0, 20) }));
  }
  const noHttp = cookies.filter((c) => !c.httpOnly);
  const noHttpSess = noHttp.filter((c) => SESSIONISH.test(c.name) && !/csrf|xsrf/i.test(c.name));
  if (!noHttp.length) out.push(F("cookie_httponly", "pass", "low", `${total}; all have the HttpOnly flag.`));
  else if (noHttpSess.length) out.push(F("cookie_httponly", "fail", "medium", `Login/session-style cookies readable by page scripts (no HttpOnly): ${names(noHttpSess)}.`, { cookies: noHttpSess.map((c) => c.name).slice(0, 20) }));
  else out.push(F("cookie_httponly", "info", "low", `No HttpOnly flag on: ${names(noHttp)}. None look like login or session cookies, and preference cookies often need to be readable by scripts.`));
  const noneInsecure = cookies.filter((c) => c.sameSite === "none" && !c.secure);
  const noSS = cookies.filter((c) => !c.sameSite || c.sameSite === "invalid");
  if (noneInsecure.length) out.push(F("cookie_samesite", "fail", "low", `SameSite=None without Secure (browsers reject these): ${names(noneInsecure)}.`));
  else if (noSS.length) out.push(F("cookie_samesite", "warn", "low", `No SameSite attribute on: ${names(noSS)}.`, { cookies: noSS.map((c) => c.name).slice(0, 20) }));
  else out.push(F("cookie_samesite", "pass", "low", `${total}; all set a SameSite attribute.`));
  return out;
}

// ---------------- HTTPS / TLS ----------------
const CERT_ERRORS = [
  [/CERT_HAS_EXPIRED/i, "the certificate has expired"],
  [/SELF_SIGNED|DEPTH_ZERO/i, "the certificate is self-signed (not issued by a trusted authority)"],
  [/ALTNAME|Hostname\/IP does not match/i, "the certificate was issued for a different domain name"],
  [/UNABLE_TO_VERIFY_LEAF|UNABLE_TO_GET_ISSUER|CHAIN/i, "the certificate chain is incomplete (a missing intermediate certificate)"],
  [/CERT_NOT_YET_VALID/i, "the certificate isn't valid yet (its start date is in the future)"],
  [/REVOKED/i, "the certificate was revoked"],
];
export const certErrorText = (code) => (CERT_ERRORS.find(([re]) => re.test(code || "")) || [null, `the certificate didn't verify (${clip(code, 60)})`])[1];

const fmtDate = (d) => d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });

export function analyzeHttps({ host, httpsError, tls, legacy, httpChain, httpError, now = Date.now() }) {
  const out = [];
  if (httpsError || !tls) {
    out.push(F("https_available", "fail", "high", `Couldn't open https://${host}/ (${clip(httpsError || "no secure connection", 80)}).`));
    out.push(F("cert_valid", "info", "high", "Not checked: no HTTPS connection."));
    out.push(F("cert_expiry", "info", "medium", "Not checked: no HTTPS connection."));
    out.push(F("tls_version", "info", "medium", "Not checked: no HTTPS connection."));
  } else {
    out.push(F("https_available", "pass", "high", `https://${host}/ answered over an encrypted connection.`));
    const names = tls.altNames?.length ? ` for ${tls.altNames.slice(0, 3).join(", ")}${tls.altNames.length > 3 ? "…" : ""}` : "";
    if (tls.authorized) out.push(F("cert_valid", "pass", "high", `Trusted certificate${names}${tls.issuer ? `, issued by ${clip(tls.issuer, 60)}` : ""}.`));
    else out.push(F("cert_valid", "fail", "high", `Browsers will show a warning: ${certErrorText(tls.error)}${tls.error ? ` [${clip(tls.error, 50)}]` : ""}.`, { code: tls.error }));
    const to = Date.parse(tls.validTo); const from = Date.parse(tls.validFrom);
    if (!Number.isFinite(to)) out.push(F("cert_expiry", "info", "medium", "Couldn't read the certificate's expiry date."));
    else {
      const days = (to - now) / 86400000;
      const life = Number.isFinite(from) ? (to - from) / 86400000 : 90;
      const warnAt = Math.min(21, Math.max(1, life * 0.25));
      const failAt = Math.min(7, Math.max(0.5, life * 0.08));
      const when = `${fmtDate(new Date(to))} (${days < 0 ? `${Math.ceil(-days)} days ago` : `${Math.floor(days)} days from now`})`;
      if (days < 0) out.push(F("cert_expiry", "fail", "high", `Certificate expired ${when}.`, { days: Math.floor(days) }));
      else if (days < failAt) out.push(F("cert_expiry", "fail", "high", `Certificate expires ${when}. Automatic renewal may be failing.`, { days: Math.floor(days) }));
      else if (days < warnAt) out.push(F("cert_expiry", "warn", "medium", `Certificate expires ${when}. Check that automatic renewal is working.`, { days: Math.floor(days) }));
      else out.push(F("cert_expiry", "pass", "medium", `Certificate valid until ${when}.`, { days: Math.floor(days) }));
    }
    const p = tls.protocol || "";
    if (/TLSv1\.3|TLSv1\.2/.test(p)) out.push(F("tls_version", "pass", "medium", `Connected with ${p}.`));
    else if (p) out.push(F("tls_version", "fail", "high", `Connected with ${p}, an outdated version.`));
    else out.push(F("tls_version", "info", "medium", "Couldn't read the TLS version."));
  }
  if (!httpsError && tls) {
    if (!legacy || !legacy.tested) out.push(F("tls_legacy", "info", "medium", "Couldn't test whether outdated TLS 1.0/1.1 is still accepted."));
    else if (legacy.accepted) out.push(F("tls_legacy", "warn", "medium", `The server still accepts ${legacy.protocol || "TLS 1.0/1.1"}, which browsers retired in 2020.`));
    else out.push(F("tls_legacy", "pass", "medium", "Outdated TLS 1.0 and 1.1 connections are refused."));
  }
  // HTTP -> HTTPS
  if (httpError && !httpChain) out.push(F("http_redirect", "pass", "medium", `Plain http://${host}/ isn't served at all (${clip(httpError, 50)}), so nobody lands on an unencrypted page.`));
  else if (httpChain && httpChain.length) {
    const path = httpChain.map((x) => `${x.url.replace(/\/$/, "")} (${x.status})`).join(" → ");
    const last = httpChain.at(-1);
    const endsHttps = last.url.startsWith("https://");
    if (endsHttps) out.push(F("http_redirect", "pass", "medium", `http:// redirects to HTTPS: ${clip(path, 300)}`));
    else if (last.status >= 200 && last.status < 400) out.push(F("http_redirect", "fail", "medium", `http://${host}/ loads without switching to HTTPS: ${clip(path, 300)}`));
    else out.push(F("http_redirect", "warn", "medium", `http://${host}/ returned ${last.status} instead of redirecting to HTTPS: ${clip(path, 300)}`));
  }
  return out;
}

// ---------------- mixed content ----------------
const ACTIVE = { script: "src", iframe: "src", embed: "src", object: "data", frame: "src" };
const PASSIVE = { img: "src", audio: "src", video: "src", source: "src", track: "src" };
const attrOf = (tag, name) => { const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, "i")); return m ? (m[2] ?? m[3] ?? m[4] ?? "").trim() : ""; };

export function findMixedContent(html) {
  const active = []; const passive = []; const forms = [];
  const src = String(html || "").replace(/<!--[\s\S]*?-->/g, "").replace(/(<script\b[^>]*>)[\s\S]*?<\/script>/gi, "$1</script>");
  for (const m of src.matchAll(/<(script|iframe|embed|object|frame|img|audio|video|source|track|link|form)\b[^>]*>/gi)) {
    const tag = m[0]; const name = m[1].toLowerCase();
    if (name === "link") {
      const rel = attrOf(tag, "rel").toLowerCase();
      const href = attrOf(tag, "href");
      if (/^http:\/\//i.test(href) && /stylesheet|preload|modulepreload|icon/.test(rel)) (/stylesheet|preload|modulepreload/.test(rel) ? active : passive).push(href);
    } else if (name === "form") {
      const a = attrOf(tag, "action"); if (/^http:\/\//i.test(a)) forms.push(a);
    } else {
      const k = ACTIVE[name] || PASSIVE[name];
      const v = attrOf(tag, k);
      if (/^http:\/\//i.test(v)) (ACTIVE[name] ? active : passive).push(v);
      if (name === "img" || name === "source") { const ss = attrOf(tag, "srcset"); if (/(^|,\s*)http:\/\//i.test(ss)) passive.push(ss.split(/\s+/)[0]); }
    }
  }
  const uniq = (a) => [...new Set(a)];
  return { active: uniq(active), passive: uniq(passive), forms: uniq(forms) };
}

export function analyzeMixed({ https, html, csp, truncated }) {
  if (!https) return F("mixed_content", "info", "medium", "Not applicable: the page wasn't loaded over HTTPS.");
  if (!html) return F("mixed_content", "info", "medium", "No HTML to check.");
  const { active, passive, forms } = findMixedContent(html);
  const upgrade = /upgrade-insecure-requests/i.test(csp || "");
  const list = (a) => a.slice(0, 4).map((x) => clip(x, 90)).join(", ") + (a.length > 4 ? ` +${a.length - 4} more` : "");
  const note = truncated ? " (checked the first 1 MB of the home page)" : " (home page only)";
  if (!active.length && !passive.length && !forms.length) return F("mixed_content", "pass", "medium", `No insecure http:// scripts, styles, frames, images, or form targets found${note}.`);
  const parts = [];
  if (active.length) parts.push(`insecure scripts/styles/frames: ${list(active)}`);
  if (forms.length) parts.push(`forms that submit over http://: ${list(forms)}`);
  if (passive.length) parts.push(`insecure images/media: ${list(passive)}`);
  const data = { active: active.slice(0, 20), passive: passive.slice(0, 20), forms: forms.slice(0, 10) };
  if (upgrade) return F("mixed_content", "warn", "low", `Found ${parts.join("; ")}. The site's Content-Security-Policy upgrades these to https:// automatically, but they should be fixed at the source${note}.`, data);
  if (active.length || forms.length) return F("mixed_content", "fail", "medium", `Found ${parts.join("; ")}${note}.`, data);
  return F("mixed_content", "warn", "low", `Found ${parts.join("; ")}${note}.`, data);
}

// ---------------- email: SPF / DMARC / DKIM / MX ----------------
export function analyzeSpf(txtRecords, domain, err) {
  if (err) return F("spf", "error", "medium", `Couldn't look up SPF for ${domain} (${err}).`);
  const recs = (txtRecords || []).filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
  if (!recs.length) return F("spf", "fail", "medium", `No SPF record (TXT starting with v=spf1) found on ${domain}.`);
  if (recs.length > 1) return F("spf", "fail", "medium", `${recs.length} SPF records found on ${domain}; only one is allowed, so receivers treat SPF as broken: ${recs.map((r) => clip(r, 120)).join(" | ")}`);
  const r = recs[0].trim();
  const all = r.match(/\s([+?~-]?)all(\s|$)/i);
  const lookups = (r.match(/\b(include:|a(:|\s|$)|mx(:|\s|$)|ptr|exists:|redirect=)/gi) || []).length;
  const ev = `${domain}: ${clip(r, 260)}`;
  if (all && (all[1] === "+" || all[1] === "")) return F("spf", "fail", "high", `${ev} (ends in "+all", which lets ANY server send mail as this domain)`);
  if (all && all[1] === "?") return F("spf", "warn", "medium", `${ev} (ends in "?all", which tells receivers to treat unknown senders as neutral)`);
  if (!all && !/redirect=/i.test(r)) return F("spf", "warn", "low", `${ev} (no closing "all" rule)`);
  if (lookups > 10) return F("spf", "warn", "low", `${ev} (at least ${lookups} DNS lookups; SPF breaks above 10)`);
  return F("spf", "pass", "medium", ev);
}

export function analyzeDmarc(txtRecords, name, err) {
  if (err) return F("dmarc", "error", "medium", `Couldn't look up DMARC at ${name} (${err}).`);
  const recs = (txtRecords || []).filter((t) => /^v=DMARC1\s*(;|$)/i.test(t.trim()));
  if (!recs.length) return F("dmarc", "fail", "medium", `No DMARC record found at ${name}.`);
  if (recs.length > 1) return F("dmarc", "fail", "medium", `${recs.length} DMARC records at ${name}; only one is allowed, so receivers ignore them.`);
  const r = recs[0].trim();
  const tags = Object.fromEntries(r.split(";").map((x) => x.trim().split("=").map((s) => s && s.trim())).filter((x) => x[0]).map(([k, v]) => [k.toLowerCase(), (v || "").toLowerCase()]));
  const ev = `${name}: ${clip(r, 220)}`;
  const pct = tags.pct ? Number(tags.pct) : 100;
  if (!tags.p) return F("dmarc", "fail", "medium", `${ev} (no p= policy, so the record is invalid)`);
  if (tags.p === "none") return F("dmarc", "warn", "medium", `${ev} (p=none only monitors; spoofed mail is still delivered)`, { policy: "none", rua: Boolean(tags.rua) });
  if (tags.p === "quarantine" || tags.p === "reject") {
    if (pct < 100) return F("dmarc", "warn", "low", `${ev} (policy applies to only ${pct}% of failing mail)`, { policy: tags.p, pct });
    return F("dmarc", "pass", "medium", ev, { policy: tags.p, rua: Boolean(tags.rua) });
  }
  return F("dmarc", "fail", "medium", `${ev} (p=${clip(tags.p, 20)} isn't a valid policy)`);
}

export const DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "k2", "s1", "s2", "dkim", "mail", "smtp", "zoho", "zmail", "protonmail", "fm1", "mandrill", "mxvault", "sig1"];

export function analyzeDkim(results, domain) {
  // results: [{ selector, records: [...] }]
  const found = results.filter((r) => (r.records || []).some((t) => /(^|;)\s*(v=DKIM1|k=rsa|k=ed25519|p=[A-Za-z0-9+/]{20,})/i.test(t) && !/(^|;)\s*p=\s*(;|$)/i.test(t)));
  const checked = results.map((r) => r.selector);
  if (found.length) return F("dkim", "pass", "low", `DKIM key found at ${found.map((f) => `${f.selector}._domainkey.${domain}`).slice(0, 4).join(", ")}.`, { selectors: found.map((f) => f.selector) });
  return F("dkim", "info", "low", `DKIM not found on common selectors. We looked up ${checked.length} common selector names (${checked.slice(0, 6).join(", ")}…) under ${domain}. Your email provider may use a different selector name, so this isn't proof that DKIM is turned off.`, { checked });
}

const MX_PROVIDERS = [[/google\.com$|googlemail\.com$/, "Google Workspace"], [/outlook\.com$|office365|protection\.outlook/, "Microsoft 365"], [/zoho/, "Zoho Mail"], [/secureserver\.net$/, "GoDaddy"], [/protonmail/, "Proton Mail"], [/messagingengine\.com$/, "Fastmail"], [/icloud\.com$/, "iCloud"], [/mimecast/, "Mimecast"], [/pphosted|ppe-hosted/, "Proofpoint"], [/emailsrvr\.com$/, "Rackspace"], [/yahoodns/, "Yahoo"], [/mail\.ovh/, "OVH"], [/titan\.email/, "Titan"], [/improvmx/, "ImprovMX"]];

export function analyzeMx(mx, domain, err) {
  if (err) return F("mx", "error", "info", `Couldn't look up MX records for ${domain} (${err}).`);
  if (!mx || !mx.length) return F("mx", "info", "info", `No MX records on ${domain}: it doesn't appear to receive email. It can still be spoofed as a sender, so SPF and DMARC still matter.`, { receives: false });
  if (mx.length === 1 && (mx[0].exchange === "" || mx[0].exchange === ".")) return F("mx", "info", "info", `${domain} publishes a "null MX", saying it never accepts email.`, { receives: false });
  const sorted = [...mx].sort((a, b) => a.priority - b.priority);
  const providers = [...new Set(sorted.map((m) => (MX_PROVIDERS.find(([re]) => re.test(m.exchange)) || [])[1]).filter(Boolean))];
  return F("mx", "info", "info", `${domain} receives email via ${sorted.slice(0, 3).map((m) => m.exchange).join(", ")}${providers.length ? ` (${providers.join(", ")})` : ""}.`, { receives: true, providers });
}

// ---------------- information leaks ----------------
const isHtmlish = (body, ct) => /text\/html/i.test(ct || "") || /^\s*(<!doctype|<html|<head|<body|<\?xml|<!--)/i.test(body || "");

export const EXPOSED_PROBES = [
  { path: "/.env", label: "environment settings file (.env)", verify: (b, ct) => !isHtmlish(b, ct) && /^\s*(export\s+)?[A-Z][A-Z0-9_]{1,60}\s*=\s*\S*/m.test(b) && b.length < 60000, desc: "readable; it looks like KEY=value app settings, which often include passwords or API keys (contents not shown)" },
  { path: "/.git/HEAD", label: "Git repository (.git/HEAD)", verify: (b, ct) => !isHtmlish(b, ct) && /^(ref:\s*refs\/[\w./-]+|[0-9a-f]{40})\s*$/m.test(b.trim()) && b.length < 300, desc: "readable; the site's source-code history may be downloadable" },
  { path: "/.git/config", label: "Git config (.git/config)", verify: (b, ct) => !isHtmlish(b, ct) && /^\s*\[core\]/m.test(b), desc: "readable; the site's source-code repository is exposed" },
  { path: "/.DS_Store", label: "macOS folder index (.DS_Store)", verify: (_b, _ct, bytes) => bytes && bytes.length >= 8 && bytes.readUInt32BE(0) === 1 && bytes.subarray(4, 8).toString("latin1") === "Bud1", desc: "readable; it lists file and folder names on the server" },
  { path: "/.htpasswd", label: "password file (.htpasswd)", verify: (b, ct) => !isHtmlish(b, ct) && /^[^:\s<>]{1,64}:(\$apr1\$|\$2[aby]?\$|\{SHA\}|\$[156]\$)/m.test(b), desc: "readable; it contains usernames and password hashes (contents not shown)" },
  { path: "/phpinfo.php", label: "PHP info page (phpinfo.php)", verify: (b) => /<title>\s*(PHP \d[\w.]* - )?phpinfo\(\)\s*<\/title>/i.test(b) || (/phpinfo\(\)/i.test(b) && /PHP Version\s*<\/?[a-z]/i.test(b)), desc: "public; it reveals detailed server configuration" },
  { path: "/info.php", label: "PHP info page (info.php)", verify: (b) => /<title>\s*(PHP \d[\w.]* - )?phpinfo\(\)\s*<\/title>/i.test(b) || (/phpinfo\(\)/i.test(b) && /PHP Version\s*<\/?[a-z]/i.test(b)), desc: "public; it reveals detailed server configuration" },
  { path: "/server-status", label: "Apache server-status page", verify: (b) => /Apache Server Status for/i.test(b), desc: "public; it shows live server activity and visitor requests" },
  { path: "/wp-config.php.bak", label: "WordPress config backup (wp-config.php.bak)", verify: (b, ct) => !isHtmlish(b, ct) && /define\s*\(\s*['"]DB_(PASSWORD|NAME|USER)['"]/i.test(b), desc: "readable; it contains the database login (contents not shown)" },
  { path: "/backup.sql", label: "database dump (backup.sql)", verify: (b, ct) => !isHtmlish(b, ct) && /(CREATE TABLE|INSERT INTO)\s/i.test(b), desc: "readable; it looks like a database export (contents not shown)" },
];

const normBody = (s) => String(s || "").replace(/\s+/g, " ").replace(/[0-9a-f]{16,}/gi, "").trim().slice(0, 4000);

// Same response as the random "this does not exist" page? Then it's a soft-404, not a real file.
export function looksLikeBaseline(probe, baseline) {
  if (!baseline || baseline.status !== probe.status) return false;
  const a = normBody(probe.body); const b = normBody(baseline.body);
  if (a === b) return true;
  if (!a.length || !b.length) return a.length === b.length;
  return Math.abs(a.length - b.length) / Math.max(a.length, b.length) < 0.05 && a.slice(0, 200) === b.slice(0, 200);
}

export function analyzeExposed(results, baseline) {
  // results: [{ probe, res }] where res may be null (error/timeout)
  const hits = [];
  for (const { probe, res } of results) {
    if (!res || res.status !== 200) continue;
    if (looksLikeBaseline(res, baseline)) continue;
    if (probe.verify(res.body || "", res.headers?.["content-type"] || "", res.bodyBytes)) hits.push(probe);
  }
  const checked = results.length;
  if (!hits.length) return F("exposed_files", "pass", "high", `Checked ${checked} commonly exposed sensitive files (like .env, .git, backups, phpinfo); none were publicly readable.`, { checked: results.map((r) => r.probe.path) });
  return F("exposed_files", "fail", "high", hits.map((p) => `${p.path}: ${p.desc}`).join(" | "), { files: hits.map((p) => ({ path: p.path, label: p.label })) });
}

export function isDirListing(body) {
  return /<title>\s*Index of \/|<h1>\s*Index of \/|<title>\s*Directory listing for \/|\[To Parent Directory\]/i.test(body || "");
}

export function analyzeDirListing(results) {
  const hits = results.filter(({ res }) => res && res.status === 200 && isDirListing(res.body)).map(({ path }) => path);
  if (hits.length) return F("directory_listing", "fail", "medium", `Folder contents are publicly listed at: ${hits.join(", ")}`, { paths: hits });
  return F("directory_listing", "pass", "medium", `No public folder listings at ${results.map((r) => r.path).join(", ")}.`);
}

export function analyzeSecurityTxt(res) {
  const ok = res && res.status === 200 && !isHtmlish(res.body, res.headers?.["content-type"]) && /^\s*contact\s*:/im.test(res.body || "");
  if (ok) {
    const c = (res.body.match(/^\s*contact\s*:\s*(.+)$/im) || [])[1] || "";
    return F("security_txt", "pass", "info", `/.well-known/security.txt is published (Contact: ${clip(c, 80)}).`);
  }
  return F("security_txt", "info", "info", "No /.well-known/security.txt file. It's optional: it tells security researchers how to report a problem to you.");
}
