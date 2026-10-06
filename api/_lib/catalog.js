// Titles, categories, who fixes it, and hand-written plain-English copy for every check.
// The hand-written copy is the fallback whenever the AI layer is off, over budget, or returns
// something we don't trust. fixBy: "nick" = within what Nick offers; "refer" = referred out; "none" = informational.

export const CATEGORIES = [
  { id: "https", title: "HTTPS & certificate" },
  { id: "headers", title: "Security headers" },
  { id: "email", title: "Email spoofing protection" },
  { id: "leaks", title: "Information leaks" },
  { id: "cookies", title: "Cookies" },
];

const C = (cat, title, fixBy, what, fix) => ({ cat, title, fixBy, what, fix });

export const CATALOG = {
  https_available: C("https", "HTTPS works", "nick",
    { pass: "Your site loads over an encrypted HTTPS connection, so what visitors type and see can't be read in transit.", fail: "Your site couldn't be opened over HTTPS. Visitors may see a 'Not secure' warning, and anything they type (like a contact form) can travel unencrypted." },
    { fail: "Install a free SSL certificate (most hosts include Let's Encrypt) and make sure the site answers on https://." }),
  cert_valid: C("https", "Certificate is trusted", "nick",
    { pass: "Your SSL certificate is valid and trusted by browsers.", fail: "Browsers don't trust your SSL certificate, so visitors get a full-page security warning and most will leave." },
    { fail: "Reissue or reinstall the certificate for the exact domain name (including www if you use it), with the full certificate chain." }),
  cert_expiry: C("https", "Certificate expiry", "nick",
    { pass: "Your certificate isn't close to expiring.", warn: "Your certificate expires soon. If it isn't renewed in time, visitors will get a security warning.", fail: "Your certificate has expired or is about to. Visitors will get a security warning that blocks the site." },
    { warn: "Confirm automatic renewal is turned on with your host or certificate provider, or renew it now.", fail: "Renew the certificate now and turn on automatic renewal so it doesn't happen again." }),
  tls_version: C("https", "Modern TLS version", "nick",
    { pass: "The secure connection uses a modern version of TLS (the encryption behind HTTPS).", fail: "The secure connection uses an outdated version of TLS that modern browsers reject or warn about." },
    { fail: "Update the server or hosting SSL settings to use TLS 1.2 and TLS 1.3." }),
  tls_legacy: C("https", "Old TLS 1.0/1.1 turned off", "nick",
    { pass: "The server refuses the old, weak TLS 1.0 and 1.1 versions.", warn: "The server still accepts TLS 1.0 or 1.1. Browsers stopped using these in 2020 and they're considered weak.", info: "We couldn't test whether old TLS versions are still accepted." },
    { warn: "Turn off TLS 1.0 and 1.1 in your server, CDN, or hosting SSL settings and keep TLS 1.2 and 1.3." }),
  http_redirect: C("https", "HTTP redirects to HTTPS", "nick",
    { pass: "Visitors who type or click an http:// link are sent to the secure version.", fail: "Someone who types your address without https:// can land on an unencrypted version of your site.", warn: "The plain http:// version of your site doesn't send visitors to the secure version." },
    { fail: "Add a permanent (301) redirect from http:// to https:// in your hosting settings or server config.", warn: "Add a permanent (301) redirect from http:// to https:// in your hosting settings or server config." }),
  mixed_content: C("https", "No insecure (mixed) content", "nick",
    { pass: "Your home page doesn't load scripts, styles, or images over insecure http:// links.", warn: "Your home page loads some images or media over insecure http:// links. Browsers may block them or show a warning.", fail: "Your secure page loads scripts, styles, frames, or forms over insecure http:// links. Browsers block these, which can break the page, and they weaken HTTPS." },
    { warn: "Change those http:// links to https:// (or to relative links) in your site's pages or theme.", fail: "Change those http:// links to https:// in your site's pages, theme, or plugins." }),
  hsts: C("headers", "HSTS (Strict-Transport-Security)", "nick",
    { pass: "Browsers are told to always use HTTPS for your site, even if someone types http://.", warn: "HSTS is set, but for a short time, so browsers forget it quickly.", fail: "Browsers aren't told to always use HTTPS for your site, which leaves a small window for someone on public Wi-Fi to intercept the first visit." },
    { warn: "Raise the max-age to at least 15552000 (180 days); one year (31536000) is common.", fail: "Add the header Strict-Transport-Security: max-age=31536000; includeSubDomains (after confirming every subdomain works on HTTPS)." }),
  csp: C("headers", "Content-Security-Policy", "nick",
    { pass: "Your site tells browsers which sources of scripts and content are allowed, which limits damage from injected code.", warn: "A Content-Security-Policy exists, but it's loose enough that it may not stop injected scripts.", fail: "There's no Content-Security-Policy, so if an attacker ever injects a script into a page (for example through a vulnerable plugin), the browser will run it." },
    { warn: "Tighten the policy: remove 'unsafe-inline' for scripts (use nonces or hashes) and list only the domains you actually use.", fail: "Add a Content-Security-Policy header that lists the script, style, and image sources your site uses. Start in report-only mode, then enforce it." }),
  x_frame_options: C("headers", "Clickjacking protection", "nick",
    { pass: "Other websites can't secretly load your pages inside a frame.", warn: "Your anti-framing header uses an outdated value that browsers ignore.", fail: "Other websites can load your pages inside an invisible frame and trick visitors into clicking things (\"clickjacking\")." },
    { warn: "Use X-Frame-Options: SAMEORIGIN, or frame-ancestors 'self' in your Content-Security-Policy.", fail: "Add X-Frame-Options: SAMEORIGIN (or frame-ancestors 'self' in your Content-Security-Policy)." }),
  x_content_type_options: C("headers", "X-Content-Type-Options", "nick",
    { pass: "Browsers are told not to guess file types, which blocks a class of file-upload tricks.", fail: "Browsers may 'guess' a file's type, which attackers can abuse to run a disguised file as a script." },
    { fail: "Add the header X-Content-Type-Options: nosniff." }),
  referrer_policy: C("headers", "Referrer-Policy", "nick",
    { pass: "Your site controls how much of your page addresses are shared with other sites when visitors click away.", warn: "Your site shares full page addresses (which can include private details in the URL) with other sites.", fail: "Your site doesn't say how much of a page's address to share when visitors click a link to another site." },
    { warn: "Change it to Referrer-Policy: strict-origin-when-cross-origin.", fail: "Add Referrer-Policy: strict-origin-when-cross-origin." }),
  permissions_policy: C("headers", "Permissions-Policy", "nick",
    { pass: "Your site limits which browser features (camera, microphone, location) pages and embeds can use.", warn: "Your site uses an old, mostly unsupported header to limit browser features.", fail: "Your site doesn't limit which browser features (camera, microphone, location) pages and embedded content can ask for." },
    { warn: "Replace Feature-Policy with Permissions-Policy, for example: camera=(), microphone=(), geolocation=().", fail: "Add Permissions-Policy: camera=(), microphone=(), geolocation=() (allow only what your site actually uses)." }),
  mx: C("email", "Email (MX) records", "none",
    { info: "This shows where email for your domain is delivered. It's background for the email checks." }, {}),
  spf: C("email", "SPF record", "nick",
    { pass: "Your domain lists which servers are allowed to send email as you, which helps stop scammers sending fake emails from your address.", warn: "Your SPF record exists but is set up in a way that weakens it.", fail: "Your domain doesn't properly list which servers may send email as you, so scammers can more easily send emails that look like they're from your business.", error: "We couldn't look up this record right now." },
    { warn: "Fix the SPF record so it lists only your real email senders and ends in ~all or -all.", fail: "Publish one SPF TXT record listing your email provider (for example v=spf1 include:_spf.google.com ~all for Google Workspace). If the domain never sends email, use v=spf1 -all." }),
  dmarc: C("email", "DMARC policy", "nick",
    { pass: "Your domain tells email providers to quarantine or reject fake emails that pretend to be from you.", warn: "You have DMARC, but it only monitors, so fake emails pretending to be from you are still delivered.", fail: "There's no working DMARC policy, so email providers aren't told what to do with fake emails that use your domain (a common trick in invoice and payment scams).", error: "We couldn't look up this record right now." },
    { warn: "After checking the DMARC reports to confirm your real mail passes, move to p=quarantine, then p=reject.", fail: "Add a TXT record at _dmarc with v=DMARC1; p=none; rua=mailto:you@yourdomain to start, then move to p=quarantine or p=reject." }),
  dkim: C("email", "DKIM signing", "nick",
    { pass: "We found a DKIM key, which lets receivers verify your emails really came from you and weren't changed.", info: "We didn't find DKIM on the common selector names we know. Your provider may use a different name, so this isn't proof it's turned off." },
    { info: "Check your email provider's settings (Google Workspace, Microsoft 365, etc.) and confirm DKIM signing is turned on.", fail: "Turn on DKIM signing in your email provider's settings and publish the DNS record it gives you." }),
  server_banner: C("leaks", "Software version banners", "nick",
    { pass: "Your server doesn't advertise exact software versions.", warn: "Your site reveals which software it runs. It's minor, but it helps attackers pick targets.", fail: "Your server advertises exact software versions, which tells attackers which known bugs to try." },
    { warn: "Remove or hide the X-Powered-By header and generator tag in your server, host, or CMS settings.", fail: "Turn off version numbers in the Server and X-Powered-By headers (for example ServerTokens Prod in Apache, server_tokens off in nginx, expose_php = Off in PHP)." }),
  directory_listing: C("leaks", "Directory listing", "refer",
    { pass: "We didn't find any folders that publicly list their files.", fail: "Some folders on your site show a public list of every file inside, which can expose files you didn't mean to publish." },
    { fail: "Have your developer or host turn off directory listing (for example Options -Indexes in Apache) and check what was exposed." }),
  exposed_files: C("leaks", "Exposed sensitive files", "refer",
    { pass: "None of the commonly leaked sensitive files we checked are publicly readable.", fail: "Files that should never be public can be downloaded from your site. They can reveal passwords, database logins, or your site's source code." },
    { fail: "Have your developer, host, or a security professional handle this urgently: remove or block the file(s), then change any passwords or keys they contained. Nick doesn't fix this kind of issue himself, but he can refer you to someone who does." }),
  security_txt: C("leaks", "security.txt", "none",
    { pass: "You publish a security.txt file so people who find a problem know how to reach you.", info: "security.txt is an optional file that tells security researchers how to report problems. Nice to have, not required." }, {}),
  cookies: C("cookies", "Cookies", "none",
    { info: "Your home page didn't set any cookies, so there's nothing to check here." }, {}),
  cookie_secure: C("cookies", "Cookie Secure flag", "nick",
    { pass: "Your cookies are only sent over encrypted connections.", fail: "Some cookies can be sent over unencrypted connections, where someone on the same network could read them.", info: "This matters once the site runs on HTTPS." },
    { fail: "Set the Secure flag on those cookies in your site, plugin, or server settings." }),
  cookie_httponly: C("cookies", "Cookie HttpOnly flag", "nick",
    { pass: "Your cookies can't be read by page scripts, which protects them if a malicious script ever runs.", fail: "Login or session cookies can be read by page scripts. If a malicious script ever runs on your site, it could steal logged-in sessions.", info: "Some cookies don't have HttpOnly, but they don't look like login cookies, so that's usually fine." },
    { fail: "Set the HttpOnly flag on session and login cookies." }),
  cookie_samesite: C("cookies", "Cookie SameSite attribute", "nick",
    { pass: "Your cookies say when they can be sent from other sites, which helps block cross-site request tricks.", warn: "Some cookies don't say when they can be sent from other sites. Modern browsers default to a safe setting, but older ones don't.", fail: "Some cookies are set in a way browsers reject (SameSite=None without Secure)." },
    { warn: "Add SameSite=Lax (or Strict) to those cookies.", fail: "Add the Secure flag to cookies that use SameSite=None, or change them to SameSite=Lax." }),
};

export function fallbackText(f) {
  const c = CATALOG[f.id];
  if (!c) return { what: "", fix: "" };
  const st = f.status;
  const alt = { warn: "fail", fail: "warn", error: "info", info: "pass", pass: "info" }[st];
  const what = c.what[st] || c.what[alt] || c.what.fail || c.what.info || c.what.pass || "";
  const fix = st === "pass" ? "" : c.fix[st] || ((st === "warn" || st === "fail") ? c.fix[alt] || "" : "");
  return { what, fix };
}
