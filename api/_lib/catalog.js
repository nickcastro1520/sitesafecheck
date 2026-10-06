// Titles, categories, who fixes it, and hand-written plain-English copy for every check.
// "fix" is deliberately a short, non-technical "How it's fixed" line naming only the TYPE of change
// (no header values, DNS record contents, config snippets, or step-by-step instructions).
// The hand-written copy is the fallback whenever the AI layer is off, over budget, or returns
// something we don't trust. fixBy: "nick" = within what Nick offers; "refer" = referred out; "none" = informational.

export const CATEGORIES = [
  { id: "https", title: "HTTPS & certificate" },
  { id: "headers", title: "Security headers" },
  { id: "email", title: "Email spoofing protection" },
  { id: "leaks", title: "Information leaks" },
  { id: "cookies", title: "Cookies" },
];

// worst: one short, truthful "worst case" sentence per problem status (warn/fail), scaled to severity.
const C = (cat, title, fixBy, what, fix, worst = {}) => ({ cat, title, fixBy, what, fix, worst });

export const CATALOG = {
  https_available: C("https", "HTTPS works", "nick",
    { pass: "Your site loads over an encrypted HTTPS connection, so what visitors type and see can't be read in transit.", fail: "Your site couldn't be opened over HTTPS. Visitors may see a 'Not secure' warning, and anything they type (like a contact form) can travel unencrypted." },
    { fail: "Fixed by setting up an SSL certificate with your host." },
    { fail: "Someone on the same Wi-Fi could read or change what your visitors type into your site, like contact-form messages." }),
  cert_valid: C("https", "Certificate is trusted", "nick",
    { pass: "Your SSL certificate is valid and trusted by browsers.", fail: "Browsers don't trust your SSL certificate, so visitors get a full-page security warning and most will leave." },
    { fail: "Fixed by reissuing or reinstalling the SSL certificate." },
    { fail: "Visitors could be stopped by a full-page security warning and leave, with no reliable way to tell your real site from an impostor." }),
  cert_expiry: C("https", "Certificate expiry", "nick",
    { pass: "Your certificate isn't close to expiring.", warn: "Your certificate expires soon. If it isn't renewed in time, visitors will get a security warning.", fail: "Your certificate has expired or is about to. Visitors will get a security warning that blocks the site." },
    { warn: "Fixed by renewing the SSL certificate and making sure it renews automatically.", fail: "Fixed by renewing the SSL certificate and making sure it renews automatically." },
    { warn: "If renewal quietly fails, visitors could suddenly see a security warning instead of your site.", fail: "Visitors could be blocked by a full-page security warning that keeps them off your site until the certificate is renewed." }),
  tls_version: C("https", "Modern TLS version", "nick",
    { pass: "The secure connection uses a modern version of TLS (the encryption behind HTTPS).", fail: "The secure connection uses an outdated version of TLS that modern browsers reject or warn about." },
    { fail: "Fixed with a server or hosting SSL configuration change." },
    { fail: "Someone on the same Wi-Fi could read what your visitors type, and modern browsers could refuse to open your site." }),
  tls_legacy: C("https", "Old TLS 1.0/1.1 turned off", "nick",
    { pass: "The server refuses the old, weak TLS 1.0 and 1.1 versions.", warn: "The server still accepts TLS 1.0 or 1.1. Browsers stopped using these in 2020 and they're considered weak.", info: "We couldn't test whether old TLS versions are still accepted." },
    { warn: "Fixed with a server or hosting SSL configuration change." },
    { warn: "Someone on the same network could try to force visitors on older devices onto a weak connection that's easier to snoop on." }),
  http_redirect: C("https", "HTTP redirects to HTTPS", "nick",
    { pass: "Visitors who type or click an http:// link are sent to the secure version.", fail: "Someone who types your address without https:// can land on an unencrypted version of your site.", warn: "The plain http:// version of your site doesn't send visitors to the secure version." },
    { fail: "Fixed with a redirect setting in your hosting or server configuration.", warn: "Fixed with a redirect setting in your hosting or server configuration." },
    { fail: "A visitor who types your address on public Wi-Fi could land on an unencrypted page that someone nearby could read or tamper with.", warn: "Visitors who type your address without https:// could hit an error page and think your business has closed." }),
  mixed_content: C("https", "No insecure (mixed) content", "nick",
    { pass: "Your home page doesn't load scripts, styles, or images over insecure http:// links.", warn: "Your home page loads some images or media over insecure http:// links. Browsers may block them or show a warning.", fail: "Your secure page loads scripts, styles, frames, or forms over insecure http:// links. Browsers block these, which can break the page, and they weaken HTTPS." },
    { warn: "Fixed by updating links in your site's pages or theme.", fail: "Fixed by updating links in your site's pages, theme, or plugins." },
    { fail: "Someone on the same Wi-Fi could swap an insecure script or form on your page for one that captures what visitors type.", warn: "Some images could be blocked or swapped on public Wi-Fi, and visitors could see a 'Not secure' warning." }),
  hsts: C("headers", "HSTS (Strict-Transport-Security)", "nick",
    { pass: "Browsers are told to always use HTTPS for your site, even if someone types http://.", warn: "HSTS is set, but for a short time, so browsers forget it quickly.", fail: "Browsers aren't told to always use HTTPS for your site, which leaves a small window for someone on public Wi-Fi to intercept the first visit." },
    { warn: "Fixed with a server or hosting configuration change (adjusting a security header).", fail: "Fixed with a server or hosting configuration change (adding a security header)." },
    { fail: "Someone on the same public Wi-Fi could intercept a visitor's first visit and quietly downgrade it to an unencrypted connection.", warn: "After browsers forget the short setting, a visitor on public Wi-Fi could be quietly sent to an unencrypted copy of your site." }),
  csp: C("headers", "Content-Security-Policy", "nick",
    { pass: "Your site tells browsers which sources of scripts and content are allowed, which limits damage from injected code.", warn: "A Content-Security-Policy exists, but it's loose enough that it may not stop injected scripts.", fail: "There's no Content-Security-Policy, so if an attacker ever injects a script into a page (for example through a vulnerable plugin), the browser will run it." },
    { warn: "Fixed with a server or hosting configuration change (tightening a security header).", fail: "Fixed with a server or hosting configuration change (adding a security header)." },
    { fail: "If a plugin or form bug ever let a malicious script onto a page, the browser could run it and it could steal what visitors type.", warn: "If a malicious script ever slips onto a page, this loose policy might not stop it from stealing what visitors type." }),
  x_frame_options: C("headers", "Clickjacking protection", "nick",
    { pass: "Other websites can't secretly load your pages inside a frame.", warn: "Your anti-framing header uses an outdated value that browsers ignore.", fail: "Other websites can load your pages inside an invisible frame and trick visitors into clicking things (\"clickjacking\")." },
    { warn: "Fixed with a server or hosting configuration change (correcting a security header).", fail: "Fixed with a server or hosting configuration change (adding a security header)." },
    { fail: "A scammer could invisibly frame your site to trick visitors into clicking things they didn't mean to.", warn: "Because browsers ignore this value, a scammer could invisibly frame your site to trick visitors into clicking things they didn't mean to." }),
  x_content_type_options: C("headers", "X-Content-Type-Options", "nick",
    { pass: "Browsers are told not to guess file types, which blocks a class of file-upload tricks.", fail: "Browsers may 'guess' a file's type, which attackers can abuse to run a disguised file as a script." },
    { fail: "Fixed with a server or hosting configuration change (adding a security header)." },
    { fail: "In rare cases, a file on your site could be disguised and run as a script in your visitors' browsers." }),
  referrer_policy: C("headers", "Referrer-Policy", "nick",
    { pass: "Your site controls how much of your page addresses are shared with other sites when visitors click away.", warn: "Your site shares full page addresses (which can include private details in the URL) with other sites.", fail: "Your site doesn't say how much of a page's address to share when visitors click a link to another site." },
    { warn: "Fixed with a server or hosting configuration change (correcting a security header).", fail: "Fixed with a server or hosting configuration change (adding a security header)." },
    { fail: "Older browsers could pass full page addresses, including any private details in them, to the sites your visitors click through to.", warn: "Full page addresses, including any private details in them, could be shared with every site your visitors click through to." }),
  permissions_policy: C("headers", "Permissions-Policy", "nick",
    { pass: "Your site limits which browser features (camera, microphone, location) pages and embeds can use.", warn: "Your site uses an old, mostly unsupported header to limit browser features.", fail: "Your site doesn't limit which browser features (camera, microphone, location) pages and embedded content can ask for." },
    { warn: "Fixed with a server or hosting configuration change (updating a security header).", fail: "Fixed with a server or hosting configuration change (adding a security header)." },
    { fail: "An embedded ad or widget on your page could ask visitors for camera, microphone, or location access without you knowing.", warn: "Newer browsers ignore the old header, so an embedded widget could still ask visitors for camera, microphone, or location access." }),
  mx: C("email", "Email (MX) records", "none",
    { info: "This shows where email for your domain is delivered. It's background for the email checks." }, {}),
  spf: C("email", "SPF record", "nick",
    { pass: "Your domain lists which servers are allowed to send email as you, which helps stop scammers sending fake emails from your address.", warn: "Your SPF record exists but is set up in a way that weakens it.", fail: "Your domain doesn't properly list which servers may send email as you, so scammers can more easily send emails that look like they're from your business.", error: "We couldn't look up this record right now." },
    { warn: "Fixed by correcting a DNS record.", fail: "Fixed by adding or correcting a DNS record." },
    { fail: "Scammers could more easily send emails that look like they came from your business to your customers.", warn: "Some fake emails using your address could slip through, and some of your real emails could land in spam." }),
  dmarc: C("email", "DMARC policy", "nick",
    { pass: "Your domain tells email providers to quarantine or reject fake emails that pretend to be from you.", warn: "You have DMARC, but it only monitors, so fake emails pretending to be from you are still delivered.", fail: "There's no working DMARC policy, so email providers aren't told what to do with fake emails that use your domain (a common trick in invoice and payment scams).", error: "We couldn't look up this record right now." },
    { warn: "Fixed by updating a DNS record.", fail: "Fixed by adding a DNS record." },
    { fail: "Anyone could send email that looks like it came from you to your customers, like a fake invoice asking for payment.", warn: "Fake emails that look like they came from you, like a fake invoice, could still land in your customers' inboxes." }),
  dkim: C("email", "DKIM signing", "nick",
    { pass: "We found a DKIM key, which lets receivers verify your emails really came from you and weren't changed.", info: "We didn't find DKIM on the common selector names we know. Your provider may use a different name, so this isn't proof it's turned off." },
    { fail: "Fixed by turning on a setting with your email provider and adding a DNS record." },
    { fail: "Your real emails could be easier to fake and more likely to land in your customers' spam folders." }),
  server_banner: C("leaks", "Software version banners", "nick",
    { pass: "Your server doesn't advertise exact software versions.", warn: "Your site reveals which software it runs. It's minor, but it helps attackers pick targets.", fail: "Your server advertises exact software versions, which tells attackers which known bugs to try." },
    { warn: "Fixed with a server, hosting, or website platform setting change.", fail: "Fixed with a server or hosting configuration change." },
    { fail: "Attackers could match those exact version numbers to publicly known bugs and try them on your site.", warn: "It could make your site slightly easier for attackers to pick out as a target for known bugs." }),
  directory_listing: C("leaks", "Directory listing", "refer",
    { pass: "We didn't find any folders that publicly list their files.", fail: "Some folders on your site show a public list of every file inside, which can expose files you didn't mean to publish." },
    { fail: "Fixed with a server configuration change by your developer or host, who should also check what was exposed." },
    { fail: "Anyone could browse and download every file in those folders, including ones you never meant to publish." }),
  exposed_files: C("leaks", "Exposed sensitive files", "refer",
    { pass: "None of the commonly leaked sensitive files we checked are publicly readable.", fail: "Files that should never be public can be downloaded from your site. They can reveal passwords, database logins, or your site's source code." },
    { fail: "Fixed by your developer, host, or a security professional, urgently: they remove or block the files and change any passwords or keys inside. Nick doesn't fix this kind of issue himself, but he can refer you to someone who does." },
    { fail: "Anyone could download these files, and any passwords or keys inside could be used to get into your site or its data." }),
  security_txt: C("leaks", "security.txt", "none",
    { pass: "You publish a security.txt file so people who find a problem know how to reach you.", info: "security.txt is an optional file that tells security researchers how to report problems. Nice to have, not required." }, {}),
  cookies: C("cookies", "Cookies", "none",
    { info: "Your home page didn't set any cookies, so there's nothing to check here." }, {}),
  cookie_secure: C("cookies", "Cookie Secure flag", "nick",
    { pass: "Your cookies are only sent over encrypted connections.", fail: "Some cookies can be sent over unencrypted connections, where someone on the same network could read them.", info: "This matters once the site runs on HTTPS." },
    { fail: "Fixed by tightening cookie settings." },
    { fail: "Someone on the same Wi-Fi could grab those cookies, and if one is a login cookie, use it to act as the logged-in person." }),
  cookie_httponly: C("cookies", "Cookie HttpOnly flag", "nick",
    { pass: "Your cookies can't be read by page scripts, which protects them if a malicious script ever runs.", fail: "Login or session cookies can be read by page scripts. If a malicious script ever runs on your site, it could steal logged-in sessions.", info: "Some cookies don't have HttpOnly, but they don't look like login cookies, so that's usually fine." },
    { fail: "Fixed by tightening cookie settings." },
    { fail: "If a malicious script ever runs on your site, it could steal logged-in sessions and act as your customers or staff." }),
  cookie_samesite: C("cookies", "Cookie SameSite attribute", "nick",
    { pass: "Your cookies say when they can be sent from other sites, which helps block cross-site request tricks.", warn: "Some cookies don't say when they can be sent from other sites. Modern browsers default to a safe setting, but older ones don't.", fail: "Some cookies are set with a combination of options that browsers reject, so they are quietly ignored." },
    { warn: "Fixed by tightening cookie settings.", fail: "Fixed by tightening cookie settings." },
    { fail: "Browsers reject those cookies, so features that rely on them, like logins or carts, could quietly break.", warn: "On older browsers, another site could trick a visitor's browser into sending those cookies with requests they didn't intend." }),
};

export function fallbackText(f) {
  const c = CATALOG[f.id];
  if (!c) return { what: "", fix: "", worst: "" };
  const st = f.status;
  const alt = { warn: "fail", fail: "warn", error: "info", info: "pass", pass: "info" }[st];
  const what = c.what[st] || c.what[alt] || c.what.fail || c.what.info || c.what.pass || "";
  const fix = st === "pass" ? "" : c.fix[st] || ((st === "warn" || st === "fail") ? c.fix[alt] || "" : "");
  const bad = st === "warn" || st === "fail";
  const worst = bad ? c.worst[st] || c.worst[alt] || "" : "";
  return { what, fix, worst };
}
