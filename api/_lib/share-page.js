// Share pages. Saved reports (/r/<id>) are real reports read from the store for 30 days.
// The fallback link (/r?url=<domain>) stores nothing and shows no grade: it only offers to run the check.
import { normalizeTarget } from "./net.js";

export const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const TEL = "+17082501040", EMAIL = "nickcastro1520@gmail.com";

export function parseShare(sp) {
  try { return { host: normalizeTarget(sp.get("url") || "").host }; } catch { return null; }
}

function layout({ title, desc, url, body, ga }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} | SiteSafeCheck</title>
<meta name="robots" content="noindex, nofollow">
<meta name="description" content="${esc(desc)}">
<meta name="theme-color" content="#0b1f3a">
<link rel="icon" href="/favicon.ico" sizes="48x48">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<meta property="og:type" content="website">
<meta property="og:site_name" content="SiteSafeCheck">
<meta property="og:url" content="${esc(url)}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:image" content="https://sitesafecheck.com/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="SiteSafeCheck: free website security check for small businesses">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(desc)}">
<link rel="stylesheet" href="/styles.css">
${ga ? `<script src="/ga.js" data-ga="${esc(ga)}" defer></script>` : ""}
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="top">
 <div class="wrap">
  <a class="logo" href="/" aria-label="SiteSafeCheck home"><svg viewBox="0 0 64 64" aria-hidden="true"><path d="M32 6 11 14v16c0 13.4 8.9 23.8 21 27.6C44.1 53.8 53 43.4 53 30V14L32 6Z" fill="#14907d"/><path d="m22 32 7 7 13-14" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></svg>SiteSafeCheck</a>
  <nav class="main" aria-label="Main"><a href="/#what">What we check</a><a href="/#fixes">Get it fixed</a><a href="/#faq">FAQ</a><a href="/about">About</a></nav>
 </div>
</header>
<main id="main" class="wrap page shared">
${body}
<p class="aivis">Does AI recommend your business? <a href="https://doesaiknowmybusiness.com">Run a free AI visibility check →</a></p>
</main>
<footer>
 <div class="wrap">
  <span>Built by <a href="https://nickcastrobuilds.com">Nick Castro</a> · <a href="tel:${TEL}">(708) 250-1040</a> · <a href="mailto:${EMAIL}">${EMAIL}</a></span>
  <nav aria-label="Footer"><a href="/how-i-built-this">How I built this</a><a href="/about">About</a><a href="/privacy">Privacy</a><a href="https://doesaiknowmybusiness.com">Does AI Know My Business (free AI check)</a><a href="/llms.txt">llms.txt</a></nav>
 </div>
</footer>
<script src="/share.js" defer></script>
</body>
</html>`;
}

const runBlock = (host, label) => `<p class="ractions"><a class="btn btn-go" href="/?url=${encodeURIComponent(host)}&amp;scan=shared" id="run-shared">${label}</a></p>
<p class="consent">By scanning, you confirm you own or manage this site, or have permission to check it.</p>`;

const ctaBlock = (host, n) => `<section class="cta" aria-labelledby="cta-h">
 <h2 id="cta-h">${n ? `Want these fixed? Nick can handle it.` : "Want the gaps fixed? Nick can handle it."}</h2>
 <p>${n ? `${n} of the issues in this report ${n === 1 ? "is" : "are"} the kind Nick fixes. ` : ""}Nick Castro fixes the everyday configuration gaps this check finds: security headers, HTTPS/SSL setup, SPF, DKIM and DMARC email protection, version banners, and cookie flags. One-time fix $250–$500, or a monthly re-scan and watch for $50–$100/mo.</p>
 <div class="contact"><a class="btn btn-light" href="tel:${TEL}" data-cta="call" data-loc="shared">Call (708) 250-1040</a><a class="btn btn-ghost" href="sms:${TEL}" data-cta="text" data-loc="shared">Text (708) 250-1040</a><a class="btn btn-ghost" href="mailto:${EMAIL}?subject=${encodeURIComponent(`SiteSafeCheck: help with ${host}`)}" data-cta="email" data-loc="shared">Email ${EMAIL}</a></div>
</section>`;

// Fallback: no stored report, so no grade.
export function sharePage(sh, { ga = "" } = {}) {
  const title = `Security report for ${sh.host}`;
  const body = `<p class="kicker">Shared security check</p>
<h1>Security report for ${esc(sh.host)}</h1>
<p class="rmeta">This link doesn't include a saved report. Run the free check to see the current results for ${esc(sh.host)}.</p>
${runBlock(sh.host, "Run this check")}
<p class="small">The check is free, passive, and needs no signup. You'll confirm the address on the next page before anything runs.</p>
${ctaBlock(sh.host, 0)}`;
  return layout({ title, desc: `Run SiteSafeCheck's free, passive website security check on ${sh.host}.`, url: `https://sitesafecheck.com/r?url=${encodeURIComponent(sh.host)}`, body, ga });
}

const STATUS = { fail: "Needs fixing", warn: "Could be better", pass: "Looks good", info: "Info", error: "Couldn't check" };
const SEV = { high: "High priority", medium: "Medium", low: "Low" };

function findingHtml(f) {
  if (f.status === "platform") return `<article class="find s-platform"><div class="fhead"><h3>${esc(f.title)}</h3><span class="tag t-platform">Controlled by ${esc(f.controlledBy)}</span></div>${f.evidence ? `<p class="ev">${esc(f.evidence)}</p>` : ""}<p class="pnote">${esc(f.what)}</p></article>`;
  const bad = f.status === "fail" || f.status === "warn";
  const tag = bad ? (f.recommended ? `<span class="tag t-rec">Recommended</span>` : SEV[f.severity] ? `<span class="tag t-sev">${SEV[f.severity]}</span>` : "") : "";
  return `<article class="find s-${esc(f.status)} v-${esc(f.severity)}"><div class="fhead"><h3>${esc(f.title)}</h3><span class="tag t-${esc(f.status)}">${STATUS[f.status] || esc(f.status)}</span>${tag}</div><p class="ev">${esc(f.evidence)}</p>${f.what ? `<p>${bad ? `<span class="lab">What this means: </span>` : ""}${esc(f.what)}</p>` : ""}${bad && f.worst ? `<p class="worst"><span class="wicon" aria-hidden="true">!</span><span class="lab">Worst case: </span>${esc(f.worst)}</p>` : ""}${bad && f.fix ? `<p><span class="lab">How it's fixed: </span>${esc(f.fix)}</p>` : ""}${bad && f.fixBy === "nick" ? `<p class="who">${esc(f.who || "Nick can fix this.")}</p>` : ""}${bad && f.fixBy === "refer" ? `<p class="who refer">Have your developer, host, or a security professional handle this urgently. Nick can refer you out.</p>` : ""}</article>`;
}

// Saved, read-only report.
export function savedPage(r, id, { ga = "" } = {}) {
  const s = r.score;
  const when = (() => { try { return new Date(r.createdAt).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short", timeZone: "America/Chicago" }) + " CT"; } catch { return ""; } })();
  const isBad = (f) => f.status === "fail" || f.status === "warn";
  const cats = (r.categories || []).map((c) => {
    const items = r.findings.filter((f) => f.category === c.id);
    if (!items.length) return "";
    const bad = items.filter(isBad), plat = items.filter((f) => f.status === "platform"), ok = items.filter((f) => !isBad(f) && f.status !== "platform");
    const cnt = bad.length ? `${bad.length} to review` : plat.length && !ok.some((f) => f.status === "pass") ? `controlled by ${plat[0].controlledBy}` : "no issues found";
    return `<section class="cat" aria-labelledby="cat-${esc(c.id)}"><h2 id="cat-${esc(c.id)}">${esc(c.title)}<span class="cnt">${esc(cnt)}</span></h2>${bad.map(findingHtml).join("")}${plat.map(findingHtml).join("")}${ok.length ? `<details class="passed"><summary>${ok.filter((f) => f.status === "pass").length} passed, ${ok.filter((f) => f.status !== "pass").length} info</summary>${ok.map(findingHtml).join("")}</details>` : ""}</section>`;
  }).join("");
  const chips = [s.counts?.high ? `<span class="chip c-high">${s.counts.high} high</span>` : "", s.counts?.medium ? `<span class="chip c-medium">${s.counts.medium} medium</span>` : "", s.counts?.low ? `<span class="chip c-low">${s.counts.low} low</span>` : "", `<span class="chip c-pass">${s.counts?.pass || 0} passed</span>`].join("");
  const nick = r.findings.filter((f) => isBad(f) && f.fixBy === "nick").length;
  const body = `<p class="kicker">Saved security report</p>
<div class="rhead">
 <div class="gradebox g${esc(s.grade)}" role="img" aria-label="Grade ${esc(s.grade)}, score ${esc(s.score)} out of 100"><span class="g">${esc(s.grade)}</span><span class="s">${esc(s.score)}/100</span></div>
 <div>
  <h1>Security report for ${esc(r.host)}</h1>
  <p class="rmeta">Checked ${esc(when)}${r.meta?.finalUrl ? ` · ${esc(r.meta.finalUrl)}` : ""}. Saved read-only copy; this link expires 30 days after it was shared.</p>
  ${r.meta?.platform ? `<p class="platform-line">Your site runs on ${esc(r.meta.platform)}.</p>` : ""}
  <p class="summary">${esc(r.summary)}</p>
  <div class="chips">${chips}</div>
 </div>
</div>
${runBlock(r.host, "Run a fresh check")}
${cats}
${ctaBlock(r.host, nick)}
<p class="scope">${esc(r.scope || "")} A passive check can't prove a site is secure; it shows common gaps that are visible from the outside.${r.ai?.used ? " Explanations were written with help from Google Gemini, based only on the evidence shown." : ""}</p>`;
  return layout({ title: `Security report for ${r.host}: ${s.grade}`, desc: `${r.host} got a ${s.grade} (${s.score}/100) on SiteSafeCheck's free, passive website security check.`, url: `https://sitesafecheck.com/r/${id}`, body, ga });
}

export function missingPage({ ga = "" } = {}) {
  return layout({ title: "Saved report not found", desc: "This saved SiteSafeCheck report has expired or doesn't exist.", url: "https://sitesafecheck.com/", ga,
    body: `<h1>This saved report isn't available</h1>
<p>Saved reports last 30 days, so this one may have expired, or the link may be incomplete. You can run a fresh, free check any time.</p>
<p class="ractions"><a class="btn btn-go" href="/">Run a free check</a></p>` });
}
