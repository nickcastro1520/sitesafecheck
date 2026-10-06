# SiteSafeCheck

**sitesafecheck.com** — a free, passive website security check for small businesses, built by [Nick Castro](https://nickcastrobuilds.com).

A visitor enters their website, confirms they own it (or are authorized to test it), and gets a plain-English report of common, publicly visible security gaps: what was found (with the real evidence), what it means, a short hedged "worst case" line, what kind of change fixes it (deliberately no copy-paste instructions), a transparent 0–100 score, and an A–F grade. The report ends with an honest offer: Nick fixes the common configuration gaps; anything beyond that is referred out.

## What it checks (passive only)

| Area | Checks |
| --- | --- |
| HTTPS & certificate | HTTPS works · certificate trusted (expired / self-signed / wrong name / missing intermediate explained) · expiry window (scaled for short-lived certs) · negotiated TLS version · whether TLS 1.0/1.1 is still accepted · http:// → https:// redirect chain · mixed content on the home page (active vs passive, form targets, `upgrade-insecure-requests` noted) |
| Security headers | HSTS (max-age), Content-Security-Policy (missing / report-only / `unsafe-inline` / no script control), X-Frame-Options or CSP `frame-ancestors`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Email spoofing | SPF (missing, multiple, `+all`, `?all`, no `all`, >10 lookups) · DMARC (missing, multiple, `p=none`, `pct<100`, invalid; inherits the org domain for subdomains) · DKIM on 18 common selectors, reported as **"not found on common selectors"**, never "missing", and never scored · MX (provider detection, null MX) |
| Information leaks | Version banners (`Server`, `X-Powered-By`, `X-AspNet-Version`, generator tag) · directory listing on 3 common folders · 10 commonly exposed files (`.env`, `.git/HEAD`, `.git/config`, `.DS_Store`, `.htpasswd`, `phpinfo.php`, `info.php`, `server-status`, `wp-config.php.bak`, `backup.sql`), each verified by content signature **and** compared against a random-path soft-404 baseline; contents are never shown · `security.txt` (info only) |
| Cookies | Secure, HttpOnly (strict for session/login-style names), SameSite (and SameSite=None without Secure). Only cookie **names** are ever shown, never values. |

No logins, form submissions, password guessing, fuzzing, or attack traffic. User-Agent: `SiteSafeCheck/1.0 (+https://sitesafecheck.com/about; passive security check requested by a site visitor)`.

If the site redirects to a different domain, headers are reported for where it lands but **no file probes are sent to the other domain**.

## Score

Start at 100. A failed check subtracts 15 (high), 8 (medium), or 3 (low); a warning subtracts 8 / 4 / 1. Info and "couldn't check" subtract nothing. Any high-severity failure caps the score at 69. A 90+, B 80+, C 70+, D 60+, F below 60. Every report lists exactly which checks cost points (`api/_lib/score.js`).

## Honesty guardrails

- Findings come from code, not AI. The AI only rewrites text for findings that exist (unknown ids are dropped).
- Fixes Nick offers (`fixBy: "nick"`): security headers, HTTPS/SSL config, SPF/DKIM/DMARC, version banners, cookie flags.
- Referred out (`fixBy: "refer"`): exposed files and directory listing get "have your developer, host, or a security professional handle this urgently; Nick can refer you out". The AI is never allowed to replace that fix text.
- AI text is rejected (hand-written copy used instead) if it says things like "secure", "safe", "guarantee", "penetration test", "audit", "malware", "breach", or mentions Nick.
- The site never calls a scanned site "secure"; a clean report says a passive scan can't prove that.

## Stack

Same conventions as [doesaiknowmybusiness](https://github.com/nickcastro1520/doesaiknowmybusiness): plain JS, no framework, no dependencies.

- `public/` static site (HTML/CSS/vanilla JS, no web fonts, no inline scripts or styles so the CSP stays strict)
- One Vercel Function: `api/scan.js` (`GET` status, `POST` scan)
- Gemini REST `generateContent`, no SDK, model fallback list, **one batched call per fresh scan**
- `scripts/build.mjs` copies `public/` to `dist/` and injects optional GA4 / Search Console tags
- No `middleware.js`: nothing needs rewriting before the filesystem (no language routes, no share pages)

```
api/scan.js            request validation, origin check, rate limits, cache, in-flight dedupe
api/_lib/net.js        SSRF guard: URL rules, IP classification, DNS pinning, capped requests, TLS probe, DNS lookups
api/_lib/checks.js     pure analyzers (headers, banners, cookies, TLS, mixed content, SPF/DMARC/DKIM/MX, exposed files)
api/_lib/catalog.js    titles, categories, who fixes it, hand-written copy for every check/status
api/_lib/score.js      scoring rules
api/_lib/explain.js    one Gemini call + validation + fallbacks
api/_lib/gemini.js     Gemini REST client (same model-fallback logic as doesaiknowmybusiness)
api/_lib/scan.js       orchestration
api/_lib/store.js      memory or Upstash / Vercel KV (same as doesaiknowmybusiness)
public/demo.json       the labeled example report (built by scripts/build-demo.mjs from synthetic inputs)
```

## SSRF protection

- Only `http:`/`https:` on ports 80/443; no userinfo; IP literals are rejected outright (every encoding: decimal, hex, octal, IPv6, mapped), along with `localhost`, `.local`, `.internal`, `.lan`, `.home.arpa`, `metadata.google.internal`, etc.
- The hostname is resolved and **every** returned address must be public. Blocked: RFC1918, loopback, link-local/metadata (169.254.0.0/16, fd00:ec2::254), CGNAT, 0/8, multicast, reserved, docs ranges, IPv6 ULA/link-local/site-local, IPv4-mapped/compatible, NAT64, 6to4, Teredo, anything outside 2000::/3.
- The socket is pinned to the validated address with a custom `lookup` (DNS-rebinding safe); TLS still uses the real hostname for SNI and certificate checks.
- Redirects are followed manually and every hop is re-validated (scheme, port, DNS).
- Hard wall-clock timeouts (9 s page, 5 s probes, 4 s DNS), body caps (1 MB page, 64 KB probes), probe phase budget of 9 s, at most 4 probes in flight.

## Abuse and cost limits

- Ownership/authorization checkbox required (`authorized: true`), plus a honeypot field and a same-origin check on browser POSTs.
- Per IP: `RATE_LIMIT_PER_HOUR` (10) and `RATE_LIMIT_PER_DAY` (30) fresh scans, `RATE_LIMIT_BURST` (30 requests / 10 min, including cache hits).
- Global: `DAILY_CAP` (1500 fresh scans/day), `AI_DAILY_CAP` (300 Gemini calls/day; over the cap reports use hand-written copy).
- Per domain: results cached `SCAN_CACHE_SECONDS` (600) and concurrent scans of the same domain share one run, so the tool can't be used to hammer a site.

## Environment (Vercel → Settings → Environment Variables)

| Var | Purpose |
| --- | --- |
| `GEMINI_API_KEY` | Optional but recommended. Turns on AI explanations. Without it every report uses the hand-written copy. |
| `GEMINI_MODEL` | Optional comma list, first that works wins. Default `gemini-3.8-flash,gemini-3.5-flash,gemini-3.5-flash-lite,gemini-3.1-flash-lite`. |
| `GA_MEASUREMENT_ID` | Optional, e.g. `G-XXXXXXX`, from Nick's **personal** GA account (nickcastro1520@gmail.com), not the NC Web Services account. Empty = no analytics code at all. Needs a redeploy (it's applied at build time). |
| `GOOGLE_SITE_VERIFICATION` | Optional. Just the `content` value of Search Console's HTML-tag method. (DNS TXT verification at Namecheap works too and covers the whole domain.) |
| `RATE_LIMIT_PER_HOUR`, `RATE_LIMIT_PER_DAY`, `RATE_LIMIT_BURST`, `DAILY_CAP`, `AI_DAILY_CAP`, `SCAN_CACHE_SECONDS`, `RL_SALT` | Limits (defaults above). |
| `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` (or `KV_REST_API_URL` + `KV_REST_API_TOKEN`) | Optional. Makes rate limits and the cache shared across instances. Without them, memory per instance (fine to start). |
| `ALLOWED_ORIGINS` | Optional extra hosts allowed to POST (default `sitesafecheck.com,www.sitesafecheck.com`; same-origin previews always work). |

GA4 events: `scan_started`, `scan_completed` (grade, score, cached), `scan_failed`, `cta_click` (call / text / email, report or page), `example_viewed`. The scanned domain is never sent to analytics.

## Local dev

```
npm test                                # unit tests, all network mocked
node dev-server.mjs                     # http://localhost:3000, real scans, hand-written explanations
MOCK_GEMINI=1 node dev-server.mjs       # real scans, fake Gemini (exercises the AI path for free)
GA_MEASUREMENT_ID=G-TEST123 node scripts/build.mjs   # check the injected tags in dist/
node scripts/build-demo.mjs             # rebuild public/demo.json
```

`/?example` opens the sample report directly.

## Social image

`public/og.png` is 1200×630 RGB, rendered from `scripts/og.html` with headless Chrome. Keep the size if you replace it.

## Deploy notes (not done yet)

1. Import the repo in Vercel (framework: Other; `vercel.json` sets the build command and `dist` output).
2. Add `GEMINI_API_KEY` (and later `GA_MEASUREMENT_ID`).
3. Add the domain `sitesafecheck.com` (+ `www`, which redirects to the apex).
4. Namecheap DNS: `A @ 76.76.21.21`, `CNAME www cname.vercel-dns.com`.
5. So the site grades A on its own scanner, also add (this domain sends no email): `TXT @ "v=spf1 -all"` and `TXT _dmarc "v=DMARC1; p=reject;"`.
