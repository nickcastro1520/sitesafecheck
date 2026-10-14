// Shared report page (/r?url=<domain>&g=<grade>&s=<score>&d=<date>). Nothing is stored: the link
// carries the domain plus the grade it had when shared, and offers to run the check again.
import { normalizeTarget } from "./net.js";

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

export function parseShare(searchParams) {
  let host = "";
  try { host = normalizeTarget(searchParams.get("url") || "").host; } catch { return null; }
  const g = String(searchParams.get("g") || "").toUpperCase();
  const grade = /^[A-F]$/.test(g) && g !== "E" ? g : "";
  const n = Number(searchParams.get("s"));
  const score = grade && Number.isInteger(n) && n >= 0 && n <= 100 ? n : null;
  const d = String(searchParams.get("d") || "");
  const date = /^\d{4}-\d{2}-\d{2}$/.test(d) && !Number.isNaN(Date.parse(d)) ? d : "";
  return { host, grade, score, date };
}

export function sharePage(sh, { ga = "" } = {}) {
  const fmt = sh.date ? new Date(sh.date + "T12:00:00Z").toLocaleDateString("en-US", { dateStyle: "long", timeZone: "UTC" }) : "";
  const title = sh.grade ? `Security report for ${sh.host}: ${sh.grade}` : `Security report for ${sh.host}`;
  const desc = sh.grade
    ? `${sh.host} got a ${sh.grade}${sh.score != null ? ` (${sh.score}/100)` : ""} on SiteSafeCheck's free, passive website security check. Run it again to see the current report.`
    : `Run SiteSafeCheck's free, passive website security check on ${sh.host}.`;
  const runUrl = `/?url=${encodeURIComponent(sh.host)}&scan=shared`;
  const self = `https://sitesafecheck.com/r?url=${encodeURIComponent(sh.host)}${sh.grade ? `&g=${sh.grade}` : ""}${sh.score != null ? `&s=${sh.score}` : ""}${sh.date ? `&d=${sh.date}` : ""}`;
  const tel = "+17082501040", email = "nickcastro1520@gmail.com";
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
<meta property="og:url" content="${esc(self)}">
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
<p class="kicker">Shared security report</p>
<div class="rhead">
 ${sh.grade ? `<div class="gradebox g${sh.grade}" role="img" aria-label="Grade ${sh.grade}${sh.score != null ? `, score ${sh.score} out of 100` : ""}"><span class="g">${sh.grade}</span>${sh.score != null ? `<span class="s">${sh.score}/100</span>` : ""}</div>` : ""}
 <div>
  <h1>Security report for ${esc(sh.host)}</h1>
  <p class="rmeta">${sh.grade ? `Grade when this link was shared${fmt ? ` on ${esc(fmt)}` : ""}.` : "Shared check."} The link doesn't store the report, so run the check to see the full, current results.</p>
 </div>
</div>
<p class="ractions"><a class="btn btn-go" href="${esc(runUrl)}" id="run-shared">Run this check</a></p>
<p class="consent">By scanning, you confirm you own or manage this site, or have permission to check it.</p>
<p class="small">The check is free, passive, and needs no signup. You'll confirm the address on the next page before anything runs.</p>
<section class="cta" aria-labelledby="cta-h">
 <h2 id="cta-h">Want the gaps fixed? Nick can handle it.</h2>
 <p>Nick Castro fixes the everyday configuration gaps this check finds: security headers, HTTPS/SSL setup, SPF, DKIM and DMARC email protection, version banners, and cookie flags. One-time fix $250–$500, or a monthly re-scan and watch for $50–$100/mo.</p>
 <div class="contact"><a class="btn btn-light" href="tel:${tel}" data-cta="call" data-loc="shared">Call (708) 250-1040</a><a class="btn btn-ghost" href="sms:${tel}" data-cta="text" data-loc="shared">Text (708) 250-1040</a><a class="btn btn-ghost" href="mailto:${email}?subject=${encodeURIComponent(`SiteSafeCheck: help with ${sh.host}`)}" data-cta="email" data-loc="shared">Email ${email}</a></div>
</section>
<p class="aivis">Does AI recommend your business? <a href="https://doesaiknowmybusiness.com">Run a free AI visibility check →</a></p>
</main>
<footer>
 <div class="wrap">
  <span>Built by <a href="https://nickcastrobuilds.com">Nick Castro</a> · <a href="tel:${tel}">(708) 250-1040</a> · <a href="mailto:${email}">${email}</a></span>
  <nav aria-label="Footer"><a href="/how-i-built-this">How I built this</a><a href="/about">About</a><a href="/privacy">Privacy</a><a href="https://doesaiknowmybusiness.com">Does AI Know My Business (free AI check)</a><a href="/llms.txt">llms.txt</a></nav>
 </div>
</footer>
<script src="/share.js" defer></script>
</body>
</html>`;
}
