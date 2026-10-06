// Orchestrates one passive scan. Network work happens through net.js (SSRF-guarded);
// every decision about what a response means lives in checks.js.
import { randomBytes } from "node:crypto";
import { normalizeTarget, resolvePublic, fetchFollow, request, legacyTls, dnsQuery, ScanError } from "./net.js";
import * as C from "./checks.js";
import { CATALOG, CATEGORIES } from "./catalog.js";
import { scoreFindings, SCORING_RULES } from "./score.js";
import { explain } from "./explain.js";

const MULTI_SUFFIX = /\.(co|com|org|net|gov|ac|edu)\.(uk|au|nz|br|jp|mx|za|sg|in|ar|tr|il|kr|hk|tw|my|ph)$/i;
export function orgDomain(domain) {
  const labels = domain.split(".");
  const keep = MULTI_SUFFIX.test(domain) ? 3 : 2;
  return labels.slice(-keep).join(".");
}

const isSameSite = (host, root) => host === root || host.endsWith("." + root);

async function pool(tasks, size, deadline) {
  const results = new Array(tasks.length).fill(null);
  let i = 0;
  const worker = async () => {
    while (i < tasks.length) {
      const k = i++;
      if (Date.now() > deadline) return;
      try { results[k] = await tasks[k](); } catch { results[k] = null; }
    }
  };
  let t;
  await Promise.race([
    Promise.all(Array.from({ length: Math.min(size, tasks.length) }, worker)),
    new Promise((r) => { t = setTimeout(r, Math.max(0, deadline - Date.now())); }),
  ]);
  clearTimeout(t);
  return results.slice();
}

async function emailChecks(domain) {
  const isDmarc = (t) => /^v=DMARC1/i.test(t.trim());
  const [txt, dmarc, mx, dkim] = await Promise.all([
    dnsQuery("txt", domain),
    dnsQuery("txt", `_dmarc.${domain}`),
    dnsQuery("mx", domain),
    Promise.all(C.DKIM_SELECTORS.map(async (s) => ({ selector: s, ...(await dnsQuery("txt", `${s}._domainkey.${domain}`)) }))),
  ]);
  let dmarcRes = dmarc; let dmarcName = `_dmarc.${domain}`;
  const org = orgDomain(domain);
  if (!dmarc.error && !dmarc.records.some(isDmarc) && org !== domain) {
    const o = await dnsQuery("txt", `_dmarc.${org}`);
    if (o.records.some(isDmarc)) { dmarcRes = o; dmarcName = `_dmarc.${org} (inherited from the main domain)`; }
  }
  const mxF = C.analyzeMx(mx.records, domain, mx.error);
  return [
    mxF,
    C.analyzeSpf(txt.records, domain, txt.error),
    C.analyzeDmarc(dmarcRes.records, dmarcName, dmarcRes.error),
    C.analyzeDkim(dkim, domain),
  ];
}

const chainOf = (hops) => hops.map((h) => ({ url: h.url, status: h.status, location: h.headers?.location || "" }));
const errText = (e) => (e?.code === "timeout" ? "timed out" : e?.code === "blocked_target" ? "redirected to a private address" : (e?.cause?.code || e?.message || "connection failed")).toString().slice(0, 80);

// Raw scan: findings without explanations or score.
export async function collect(input, { now = Date.now(), budgetMs = 24000 } = {}) {
  const t0 = Date.now();
  const deadline = t0 + budgetMs;
  const { host, url } = normalizeTarget(input);
  await resolvePublic(host); // fail fast with a clear error (not found / private)
  const root = host.replace(/^www\./, "");

  const [mainR, httpR, legacy, email] = await Promise.all([
    fetchFollow(url, { timeout: 9000, maxBytes: 1_000_000 }).catch((e) => ({ error: e })),
    fetchFollow(`http://${host}/`, { timeout: 7000, maxBytes: 32_000 }).catch((e) => ({ error: e })),
    legacyTls(host).catch(() => ({ tested: false })),
    emailChecks(root),
  ]);

  // HTTPS facts come from the first hop to the host the visitor typed.
  const firstHttps = mainR.hops?.[0] || mainR.error?.hops?.[0];
  const httpsError = mainR.error && !firstHttps ? errText(mainR.error) : "";
  const tls = firstHttps?.tls || null;

  // Which response do we judge headers on? The final HTTPS page if it worked, else the HTTP one.
  const final = mainR.final || httpR.final || null;
  if (!final && httpsError && httpR.error && !httpR.error.hops?.length) {
    const e = mainR.error;
    if (e?.code === "blocked_target") throw e;
    throw new ScanError("unreachable", `We couldn't reach ${host} over HTTPS or HTTP (${errText(e)}).`);
  }
  const httpChain = httpR.final ? chainOf(httpR.hops) : httpR.error?.hops?.length ? chainOf(httpR.error.hops) : null;
  const httpError = httpR.error ? errText(httpR.error) : "";

  const findings = [];
  findings.push(...C.analyzeHttps({ host, httpsError, tls, legacy, httpChain, httpError, now }));

  let meta = { host, emailDomain: root, finalUrl: final?.url || "", status: final?.status || 0, https: false, offsite: false, cms: "", server: "" };
  if (final) {
    const fu = new URL(final.url);
    const https = fu.protocol === "https:";
    const offsite = !isSameSite(fu.hostname, root);
    const html = /html|xml|^$/i.test(final.headers["content-type"] || "") ? final.body : "";
    const altHtml = httpR.final && httpR.final !== final ? httpR.final.body || "" : "";
    meta = { ...meta, https, offsite, cms: C.detectCms(html, final.headers) || (offsite ? "" : C.detectCms(altHtml, httpR.final?.headers || {})), server: (final.headers.server || "").slice(0, 60), ms: final.ms };
    findings.push(C.analyzeMixed({ https, html, csp: final.headers["content-security-policy"], truncated: final.truncated }));
    findings.push(...C.analyzeHeaders(final.headers, { https }));
    findings.push(C.analyzeBanners(final.headers, html));
    const hops = (mainR.hops || httpR.hops || []).filter((h) => isSameSite(new URL(h.url).hostname, root));
    findings.push(...C.analyzeCookies(hops.flatMap((h) => h.setCookies || []), { https }));

    // Light file probes, only on the visitor's own site (never on a domain it redirects to).
    if (!offsite) {
      const origin = fu.origin;
      const probeOpts = { timeout: 5000, maxBytes: 64_000, accept: "*/*" };
      const dirs = ["/uploads/", "/images/", meta.cms === "WordPress" ? "/wp-content/uploads/" : "/assets/"];
      const tasks = [
        () => request(`${origin}/sitesafecheck-not-a-real-page-${randomBytes(6).toString("hex")}.txt`, probeOpts),
        ...C.EXPOSED_PROBES.map((p) => () => request(origin + p.path, probeOpts)),
        ...dirs.map((d) => () => request(origin + d, probeOpts)),
        () => fetchFollow(`${origin}/.well-known/security.txt`, { ...probeOpts, maxRedirects: 2 }).then((r) => r.final),
      ];
      const res = await pool(tasks, 4, Math.min(deadline, Date.now() + 9000));
      const baseline = res[0];
      const exposed = C.EXPOSED_PROBES.map((probe, k) => ({ probe, res: res[1 + k] }));
      const dirRes = dirs.map((path, k) => ({ path, res: res[1 + C.EXPOSED_PROBES.length + k] }));
      const unanswered = res.slice(1, 1 + C.EXPOSED_PROBES.length).filter((x) => !x).length;
      const ex = C.analyzeExposed(exposed, baseline);
      if (ex.status === "pass" && unanswered > C.EXPOSED_PROBES.length / 2) findings.push({ ...ex, status: "error", evidence: `Only ${C.EXPOSED_PROBES.length - unanswered} of ${C.EXPOSED_PROBES.length} file checks got an answer (the site was slow or blocked them), so this wasn't fully tested.` });
      else findings.push(ex);
      findings.push(C.analyzeDirListing(dirRes));
      findings.push(C.analyzeSecurityTxt(res.at(-1)));
    } else {
      const note = `Skipped: the site redirects to ${fu.hostname}, a different domain, so we didn't probe it.`;
      findings.push({ id: "exposed_files", status: "info", severity: "high", evidence: note });
      findings.push({ id: "directory_listing", status: "info", severity: "medium", evidence: note });
    }
  }
  findings.push(...email);
  meta.emailProviders = email[0].data?.providers || [];
  meta.ms = Date.now() - t0;
  return { host, meta, findings };
}

const CAT_ORDER = Object.fromEntries(CATEGORIES.map((c, i) => [c.id, i]));
const ID_ORDER = Object.fromEntries(Object.keys(CATALOG).map((k, i) => [k, i]));

export function decorate(findings) {
  return findings
    .filter((f) => CATALOG[f.id])
    .map((f) => ({ ...f, title: CATALOG[f.id].title, category: CATALOG[f.id].cat, fixBy: CATALOG[f.id].fixBy }))
    .sort((a, b) => CAT_ORDER[a.category] - CAT_ORDER[b.category] || ID_ORDER[a.id] - ID_ORDER[b.id]);
}

// Full report: collect + score + explanations.
export async function buildReport(raw, { useAi = true, now = Date.now() } = {}) {
  const findings = decorate(raw.findings);
  const scoreInfo = scoreFindings(findings);
  const ex = await explain(findings, raw.meta, { useAi, scoreInfo });
  return {
    v: 2,
    createdAt: new Date(now).toISOString(),
    host: raw.host,
    meta: raw.meta,
    score: scoreInfo,
    rules: SCORING_RULES,
    summary: ex.summary,
    ai: ex.ai,
    categories: CATEGORIES,
    findings: ex.findings,
    scope: "Passive check of the public home page, its HTTP headers, its certificate, public DNS records, and a short list of well-known file paths. No logins, form submissions, or attack traffic.",
  };
}

export async function runScan(input, opts = {}) {
  const raw = await collect(input, opts);
  return buildReport(raw, opts);
}
