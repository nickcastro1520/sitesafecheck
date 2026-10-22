# AGENTS.md — sitesafecheck.com

## What the site is and who it's for
A free, passive website security checker for small business owners. Enter a URL and get a plain-English report covering security headers, SSL/HTTPS, email spoofing protection (SPF/DKIM/DMARC), exposed version info, cookie flags, and mixed content. Each report includes a grade, and AI explains each finding. The report ends with an offer from Nick Castro to fix common issues. The site is also a portfolio piece for recruiters.

## Current status
- Live at https://sitesafecheck.com. It's hosted on Vercel, and every push to `main` auto-deploys.
- Stack: plain JS, a Vercel Function in `api/`, a static `public/` folder built by `scripts/build.mjs`, the Gemini REST API with model fallback, and an Upstash Redis store for saved `/r/<id>` reports, which last 30 days.
- Live features: an outdated-PHP check (PHP2Shell), a streamed report, platform detection (Wix, Squarespace, Shopify, GoDaddy, Webflow, WordPress.com), "worst case" lines, a fix CTA, share links, a sample demo, and a /how-i-built-this page.
- SEO is fully set up: GA4 on Nick's personal account, Search Console (verified, sitemap submitted), JSON-LD, IndexNow (daily workflow), and Lighthouse 100 on all pages.
- In progress: the weekly Google ranking program (rules in `/workspace/seo/RULES.md` on Grok's computer). The first run is Mon 2026-10-26.
- Open pull requests: none.

## Decisions (newest first)
- 2026-10-22: PHP failures always use the hand-written "What this means" (catalog `lockWhat`), because the AI softened it to "stability and reliability". The PHP fail CTA reads "Nick can hide the version and coordinate the update with your host." (catalog `who`) instead of "Nick can fix this.", since PHP upgrades are host work.
- 2026-10-22: Added a passive "Outdated PHP version" check (info leaks) for PHP2Shell (CVE-2026-109618/109619). It reads only the X-Powered-By and Server headers already fetched. Fail (medium, 8 pts, no 69 cap) if below the patched release per branch (8.2.35, 8.3.36, 8.4.27, 8.5.12, per php.net 21 Oct 2026) or end of life (below 8.2); warn (low) if the version is shown but current; skipped if no PHP version is visible. Medium, not high, because hosts often backport fixes without changing the number. Hiding the banner is a Nick fix; PHP upgrades are host work Nick can help coordinate.
- 2026-10-21: Added AGENTS.md so every AI on this repo stays in sync.
- 2026-10-20: SEO approval period. Through 2026-11-16, ranking changes are only proposed and go live after Nick OKs them. From 2026-11-23, allowed changes can be made directly, logged and committed first.
- 2026-10-20: Commit and push to GitHub before publishing, and confirm live matches GitHub.
- 2026-10-16: Added IndexNow plus richer JSON-LD to speed up indexing.
- 2026-10-14: Saved share reports use Upstash Redis on the free plan, so no fake grades appear in links.
- 2026-10: Hosted platforms get "Controlled by [Platform]" with no deduction for headers the owner can't change. Sites without a login or checkout get light weighting for CSP, Permissions-Policy and Referrer-Policy. These rules keep grades fair.
- 2026-10: Replaced the required checkbox with a confirmation line because it was blocking scans (78 visitors, 1 scan). The API still requires `authorized: true`.
- 2026-10: AI "worst case" lines can't go beyond a hand-written baseline, so the AI never overstates risk.
- 2026-10-06: The site is built by Grok on its own computer, not by cloud agents.

## Next steps
- Update PHP_PATCHED in api/_lib/checks.js when PHP ships new security releases; PHP 8.2 reaches end of life on 2026-12-31.
- Run the weekly ranking report every Monday and propose changes for Nick's OK during the approval period.
- Watch the scan-to-visitor ratio and conversions on the fix CTA.

## Rules
- Read AGENTS.md at the start of every session. Update it at the end with what changed and what's next, then commit.
- Grok is the main builder. Claude is used for reviews and big decisions, and reads AGENTS.md to catch up.
- Only one AI edits a repo at a time. If Claude has an open pull request on this repo, don't edit until it's merged.
- Commit to GitHub before publishing. Never put keys in code or chat.
- Never claim a test ran unless you show its results.
- Scans stay passive and run only on sites the user owns or is authorized to test. Only offer fixes Nick can deliver (headers, SSL/HTTPS, SPF/DKIM/DMARC, version banners, cookie flags). Never offer pentests, code audits or breach cleanup; refer those out.
- Free plans only. Spending money or sending messages needs Nick's OK. Never mention Grok Bot or Cursor on the site. Use real numbers only.
