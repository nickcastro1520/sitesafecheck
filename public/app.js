// SiteSafeCheck front end. No framework, no dependencies. Everything that came from a scanned
// site (headers, DNS records, cookie names) is inserted with textContent, never innerHTML.
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const PHONE = "+17082501040";
  const EMAIL = "nickcastro1520@gmail.com";
  const track = (name, params) => { try { if (typeof window.gtag === "function") window.gtag("event", name, params || {}); } catch {} };

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    return el;
  }

  const form = $("#scan-form"), input = $("#url"), btn = $("#go"), err = $("#form-err");
  const progress = $("#progress"), plist = $("#progress-list"), plive = $("#progress-live"), out = $("#report");
  const STEPS = ["Looking up the domain", "Checking HTTPS and the certificate", "Reading security headers", "Checking email spoofing protection (SPF, DKIM, DMARC)", "Looking for exposed files and version banners", "Writing your plain-English report"];
  let timer = null;
  let source = "form";

  function startProgress() {
    plist.replaceChildren(...STEPS.map((s) => h("li", {}, h("span", { class: "dot", "aria-hidden": "true" }), s)));
    progress.hidden = false;
    let i = 0;
    const tick = () => {
      [...plist.children].forEach((li, k) => { li.className = k < i ? "done" : k === i ? "run" : ""; });
      plive.textContent = STEPS[i] + "…";
      if (i < STEPS.length - 1) i++;
    };
    tick();
    timer = setInterval(tick, 2300);
  }
  function stopProgress() { clearInterval(timer); timer = null; progress.hidden = true; plive.textContent = ""; }

  // Desktop only: focus the box (on phones it would pop the keyboard over the page).
  if (!location.search && matchMedia("(min-width: 900px) and (pointer: fine)").matches) { try { input.focus({ preventScroll: true }); } catch {} }

  const params = new URLSearchParams(location.search);
  if (params.get("url")) {
    // Prefill only (never auto-run): keep plain host/URL characters.
    input.value = params.get("url").replace(/[^A-Za-z0-9.\-:/_?=&%~]/g, "").slice(0, 200);
    // A shared link (/r -> "Run this check") lands here prefilled. Never auto-run: the visitor still taps Scan.
    if (params.get("scan") === "shared" && input.value) {
      source = "shared";
      const note = h("p", { class: "shared-note", role: "status" }, "Shared check for ", h("strong", { text: input.value }), ". Tap ", h("strong", { text: "Scan my site free" }), " to run it.");
      $("#consent").before(note);
    }
    try { history.replaceState(null, "", location.pathname + location.hash); } catch {} // keep the domain out of analytics page URLs
  }

  // Friendly error states: what happened, plus a next step.
  const ERR = {
    empty: ["Enter your website address", "Type your domain, like yourbusiness.com. Any form works, including www or a full link."],
    invalid: ["That address didn't work", null, "Try just the domain, like yourbusiness.com."],
    notfound: ["We couldn't find that website", "No website answered at that address.", "Check the spelling, or try it with or without www."],
    unreachable: ["The site didn't respond", "We found the domain but couldn't connect to the website.", "Make sure it opens in your browser, then try again in a few minutes."],
    timeout: ["The site took too long to answer", "Slow or busy websites sometimes time out.", "Try again in a minute."],
    limited: ["Scan limit reached", null, "In the meantime, you can look at a sample report."],
    server: ["Something went wrong on our side", "It's not you: the scan didn't finish.", `Try again in a minute. If it keeps happening, email ${EMAIL}.`],
    offline: ["Connection lost", "Your device couldn't reach SiteSafeCheck.", "Check your internet connection and try again."],
  };
  function showError(kind, serverMsg) {
    const [title, msg, next] = ERR[kind];
    err.replaceChildren(h("strong", { text: title }), h("span", { text: [serverMsg || msg, next].filter(Boolean).join(" ") }),
      ...(kind === "limited" ? [h("button", { type: "button", class: "linkbtn", text: "See a sample report", onclick: () => $("#demo").click() })] : []));
    err.dataset.kind = kind;
  }
  function errorKind(status, code) {
    if (code === "invalid_url" || code === "blocked_target" || code === "bad_request") return "invalid";
    if (code === "dns_not_found") return "notfound";
    if (code === "unreachable" || code === "connect_failed") return "unreachable";
    if (code === "timeout" || code === "dns_timeout" || status === 504) return "timeout";
    if (status === 429 || code === "rate_limited" || code === "daily_cap") return "limited";
    return "server";
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (e.submitter !== tryBtn && !form.dataset.demo && source !== "shared") source = "form";
    delete form.dataset.demo;
    err.replaceChildren(); delete err.dataset.kind;
    // Accept any form people paste: bare domain, www, http(s), paths. The server normalizes it.
    const url = input.value.trim().replace(/^[<"'(\[]+|[>"')\],;.]+$/g, "");
    if (!url) { showError("empty"); input.focus(); return; }
    btn.disabled = true; tryBtn.disabled = true; btn.textContent = "Checking…";
    out.hidden = true; out.setAttribute("aria-busy", "true");
    startProgress();
    track("scan_started", { source });
    const t0 = performance.now();
    try {
      const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, authorized: true, confirmation: source === "demo" ? "demo_sample_site" : source === "shared" ? "shared_link_v1" : "submit_notice_v1", stream: true, company_website: $("#company_website").value }), signal: AbortSignal.timeout(70000) });
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        const kind = errorKind(r.status, j.error);
        showError(kind, kind === "invalid" || kind === "limited" ? j.message : "");
        track("scan_failed", { reason: j.error || String(r.status), source });
        input.focus();
        return;
      }
      // NDJSON: the checks arrive first (hand-written copy), then the AI-worded report.
      let last = null, firstMs = 0;
      const onMsg = (j) => {
        if (!j || !j.report) return;
        last = j;
        if (j.phase === "checks") {
          firstMs = Math.round(performance.now() - t0);
          stopProgress();
          render(j.report, { cached: j.cached, pending: Boolean(j.report.ai && j.report.ai.pending) });
        } else render(j.report, { cached: j.cached, keepPlace: Boolean(firstMs) });
      };
      if ((r.headers.get("content-type") || "").includes("ndjson") && r.body && r.body.getReader) {
        const rd = r.body.getReader(), dec = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await rd.read();
          buf += dec.decode(value || new Uint8Array(), { stream: !done });
          let nl;
          while ((nl = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, nl); buf = buf.slice(nl + 1); if (line.trim()) onMsg(JSON.parse(line)); }
          if (done) break;
        }
        if (buf.trim()) onMsg(JSON.parse(buf));
      } else onMsg(await r.json().catch(() => null));
      if (!last) { showError("server"); track("scan_failed", { reason: "empty", source }); return; }
      const rep = last.report;
      track("scan_completed", { grade: rep.score.grade, score: rep.score.score, cached: Boolean(last.cached), source, first_findings_ms: firstMs || Math.round(performance.now() - t0), full_report_ms: Math.round(performance.now() - t0) });
    } catch (ex) {
      showError(ex && ex.name === "TimeoutError" ? "timeout" : "offline");
      track("scan_failed", { reason: ex && ex.name === "TimeoutError" ? "client_timeout" : "network" });
    } finally {
      stopProgress();
      btn.disabled = false; tryBtn.disabled = false; btn.textContent = "Scan my site free";
      out.setAttribute("aria-busy", "false");
    }
  });

  // One-tap live demo: a real scan of a public sample site with a few fixable gaps.
  const DEMO_SITE = "example.com";
  const tryBtn = $("#try-demo");
  tryBtn.addEventListener("click", () => {
    source = "demo"; form.dataset.demo = "1";
    input.value = DEMO_SITE;
    track("demo_scan_clicked", { site: DEMO_SITE });
    form.requestSubmit();
  });

  $("#demo").addEventListener("click", async () => {
    err.replaceChildren();
    try {
      const r = await fetch("/demo.json");
      render(await r.json(), { demo: true });
      track("example_viewed");
    } catch { showError("offline"); }
  });

  if (params.has("example")) $("#demo").click(); // /?example opens the sample report directly

  document.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest("a[data-cta]");
    if (a) track("cta_click", { method: a.dataset.cta, location: a.dataset.loc || (a.closest("#report") ? "report" : "page") });
  });

  // Print: open every collapsed section so nothing is hidden on paper.
  let reopened = [];
  window.addEventListener("beforeprint", () => { reopened = [...document.querySelectorAll("#report details:not([open])")]; reopened.forEach((d) => (d.open = true)); });
  window.addEventListener("afterprint", () => { reopened.forEach((d) => (d.open = false)); reopened = []; });

  const STATUS = { fail: "Needs fixing", warn: "Could be better", pass: "Looks good", info: "Info", error: "Couldn't check" };
  const SEV = { high: "High priority", medium: "Medium", low: "Low" };
  const fmtDate = (iso) => { try { return new Date(iso).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" }); } catch { return iso; } };

  function findingEl(f) {
    if (f.status === "platform") {
      return h("article", { class: "find s-platform" },
        h("div", { class: "fhead" }, h("h4", { text: f.title }), h("span", { class: "tag t-platform", text: `Controlled by ${f.controlledBy}` })),
        f.evidence ? h("p", { class: "ev", text: f.evidence }) : null,
        h("p", { class: "pnote", text: f.what }));
    }
    const bad = f.status === "fail" || f.status === "warn";
    const card = h("article", { class: `find s-${f.status} v-${f.severity}` },
      h("div", { class: "fhead" },
        h("h4", { text: f.title }),
        h("span", { class: `tag t-${f.status}`, text: STATUS[f.status] || f.status }),
        bad && f.recommended ? h("span", { class: "tag t-rec", text: "Recommended" }) : bad && SEV[f.severity] ? h("span", { class: "tag t-sev", text: SEV[f.severity] }) : null),
      h("p", { class: "ev", text: f.evidence }));
    if (f.what) card.append(h("p", {}, h("span", { class: "lab", text: bad ? "What this means: " : "" }), f.what));
    if (bad && f.worst) card.append(h("p", { class: "worst" }, h("span", { class: "wicon", "aria-hidden": "true", text: "!" }), h("span", { class: "lab", text: "Worst case: " }), f.worst));
    if (bad && f.fix) card.append(h("p", {}, h("span", { class: "lab", text: "How it's fixed: " }), f.fix));
    if (bad && f.fixBy === "nick") card.append(h("p", { class: "who", text: "Nick can fix this." }));
    if (bad && f.fixBy === "refer") card.append(h("p", { class: "who refer", text: "Have your developer, host, or a security professional handle this urgently. Nick can refer you out." }));
    return card;
  }

  function scoreTable(rep) {
    const rows = rep.score.deductions.map((d) => {
      const f = rep.findings.find((x) => x.id === d.id);
      return h("tr", {}, h("td", { text: f ? f.title : d.id }), h("td", { text: `${d.status === "fail" ? "Fail" : "Warning"} · ${d.severity}` }), h("td", { text: `−${d.points}` }));
    });
    const r = rep.rules;
    return h("details", { class: "scorebox card" },
      h("summary", { text: "How the score works" }),
      h("p", { text: `Start at ${r.start}. Each failed check subtracts ${r.fail.high} (high), ${r.fail.medium} (medium), or ${r.fail.low} (low) points. Warnings subtract ${r.warn.high}, ${r.warn.medium}, or ${r.warn.low}. Info and "couldn't check" items subtract nothing. Any high-severity failure caps the score at ${r.highCap}. Checks your hosting platform controls cost nothing, and when the home page has no login, password field, cart or checkout, Content-Security-Policy, Permissions-Policy and Referrer-Policy are "Recommended" (at most 3 points each, never the cap). Grades: ${r.grades.map((g) => `${g.grade} ${g.min}+`).join(", ").replace(" 0+", " below 60")}.` }),
      rows.length ? h("table", {}, h("thead", {}, h("tr", {}, h("th", { scope: "col", text: "Check" }), h("th", { scope: "col", text: "Result" }), h("th", { scope: "col", text: "Points" }))), h("tbody", {}, rows),
        h("tfoot", {}, h("tr", {}, h("th", { scope: "row", text: "Score" }), h("td", { text: rep.score.capped ? `capped at ${r.highCap} (high-severity failure)` : "" }), h("td", { text: String(rep.score.score) })))) : h("p", { text: "Nothing was deducted." }));
  }

  const PRICES = "One-time fix $250–$500 · Monthly re-scan & watch $50–$100/mo · or bundled into a website package.";
  const SCOPE_NOTE = "Nick fixes common configuration gaps: security headers, SSL/HTTPS, SPF/DKIM/DMARC email protection, hiding version banners, and cookie flags. He doesn't do penetration testing, code audits, malware or breach cleanup, or server repairs; for those he'll refer you to a specialist.";

  function contactLinks(rep, nick, loc, light) {
    const host = rep.host;
    const body = `Hi Nick,\n\nI ran SiteSafeCheck on ${host} (grade ${rep.score.grade}, ${rep.score.score}/100) and I'd like help with:\n${nick.map((f) => `- ${f.title}`).join("\n") || "- a monthly re-scan"}\n\nName:\nBest phone:\n`;
    const mail = `mailto:${EMAIL}?subject=${encodeURIComponent(`SiteSafeCheck: help with ${host}`)}&body=${encodeURIComponent(body)}`;
    const sms = `sms:${PHONE}?&body=${encodeURIComponent(`Hi Nick, I ran SiteSafeCheck on ${host} (grade ${rep.score.grade}). Can you help fix the issues?`)}`;
    return h("div", { class: "contact" },
      h("a", { class: `btn ${light ? "btn-light" : "btn-dark"}`, href: `tel:${PHONE}`, "data-cta": "call", "data-loc": loc, text: "Call (708) 250-1040" }),
      h("a", { class: "btn btn-ghost", href: sms, "data-cta": "text", "data-loc": loc, text: "Text (708) 250-1040" }),
      h("a", { class: "btn btn-ghost", href: mail, "data-cta": "email", "data-loc": loc, text: `Email ${EMAIL}` }));
  }

  // Compact offer at the top of the report, only when there's something Nick can actually fix.
  function ctaTopEl(rep) {
    const nick = rep.findings.filter((f) => (f.status === "fail" || f.status === "warn") && f.fixBy === "nick");
    if (!nick.length) return null;
    return h("aside", { class: "cta-top", "aria-label": "Get these fixed" },
      h("p", { class: "ct-h" }, h("strong", { text: "Want these fixed? Nick can handle it." }), ` ${nick.length} of the issues below ${nick.length === 1 ? "is" : "are"} the kind Nick fixes.`),
      h("p", { class: "ct-p", text: PRICES }),
      contactLinks(rep, nick, "report_top", false),
      h("p", { class: "print-contact", text: `Call or text (708) 250-1040 · ${EMAIL}` }));
  }

  function ctaEl(rep) {
    const bad = rep.findings.filter((f) => f.status === "fail" || f.status === "warn");
    const nick = bad.filter((f) => f.fixBy === "nick");
    const refer = bad.filter((f) => f.fixBy === "refer");
    const lists = h("div", { class: "lists" });
    if (nick.length) lists.append(h("div", {}, h("h3", { text: `Nick can fix ${nick.length === 1 ? "this" : `these ${nick.length}`} from your report` }), h("ul", {}, nick.map((f) => h("li", { text: f.title })))));
    if (refer.length) lists.append(h("div", { class: "refer" }, h("h3", { text: "Referred out (handle urgently)" }), h("ul", {}, refer.map((f) => h("li", { text: f.title }))), h("p", { class: "small", text: "Have your developer, host, or a security professional handle these. Nick can refer you out." })));
    return h("section", { class: "cta", "aria-labelledby": "cta-h" },
      h("h2", { id: "cta-h", text: nick.length ? "Want these fixed? Nick can handle it." : "Want to keep it this way? Nick can watch it for you." }),
      h("p", { text: nick.length ? "Nick Castro is a web developer who fixes the everyday configuration gaps this check finds, explained in plain English, with no upsell to things you don't need. Call or text (708) 250-1040, or email " + EMAIL + "." : "No common gaps for Nick to fix right now. A monthly re-scan catches changes, like a certificate that's about to expire." }),
      lists.children.length ? lists : null,
      h("div", { class: "prices" },
        h("div", { class: "price" }, h("h3", { text: "One-time fix" }), h("div", { class: "amt", text: "$250–$500" }), h("p", { text: "Security headers, SSL/HTTPS setup, SPF/DKIM/DMARC email protection, hiding version banners, cookie flags." })),
        h("div", { class: "price" }, h("h3", { text: "Monthly re-scan & watch" }), h("div", { class: "amt", text: "$50–$100/mo" }), h("p", { text: "A fresh check every month and a plain-English note on what changed." })),
        h("div", { class: "price" }, h("h3", { text: "Website package" }), h("div", { class: "amt", text: "Bundled" }), h("p", { text: "Included when Nick builds or refreshes your website." }))),
      contactLinks(rep, nick, "report_bottom", true),
      h("p", { class: "print-contact", text: `Call or text (708) 250-1040 · ${EMAIL}` }),
      h("p", { class: "small", text: SCOPE_NOTE }));
  }

  // Share: the server saves the report for 30 days and returns /r/<id>; if it can't, it returns
  // the no-grade /r?url= link that offers to run the check.
  async function shareLink(rep) {
    try {
      const r = await fetch("/api/share", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: rep.host }), signal: AbortSignal.timeout(8000) });
      const j = await r.json();
      if (j && typeof j.url === "string" && j.url.startsWith("/r")) return { url: location.origin + j.url, saved: Boolean(j.saved) };
    } catch {}
    return { url: `${location.origin}/r?url=${encodeURIComponent(rep.host)}`, saved: false };
  }
  function shareButtons(rep) {
    const status = h("span", { class: "share-status", role: "status", "aria-live": "polite" });
    let link = null;
    const get = async () => (link = link || await shareLink(rep));
    const copyText = async (url) => {
      try { await navigator.clipboard.writeText(url); return true; } catch {
        try { const t = h("textarea", { class: "sr-copy", "aria-hidden": "true" }); t.value = url; document.body.append(t); t.select(); const ok = document.execCommand("copy"); t.remove(); return ok; } catch { return false; }
      }
    };
    const copy = async (method) => {
      status.textContent = "Creating link…";
      const l = await get();
      const ok = await copyText(l.url);
      status.textContent = ok ? (l.saved ? "Link copied. It opens this saved report for 30 days." : "Link copied.") : `Copy this link: ${l.url}`;
      track("share_click", { method, ok, saved: l.saved });
    };
    const kids = [h("button", { type: "button", class: "btn btn-ghost", onclick: () => copy("copy"), text: "Copy link to this report" })];
    kids.push(h("button", { type: "button", class: "btn btn-ghost", onclick: async () => {
      if (navigator.share) {
        const l = await get();
        try { await navigator.share({ title: `Security report for ${rep.host}${l.saved ? `: ${rep.score.grade}` : ""}`, url: l.url }); track("share_click", { method: "web_share", ok: true, saved: l.saved }); }
        catch (e) { if (!e || e.name !== "AbortError") copy("share_fallback"); }
      } else copy("share_fallback");
    }, text: "Share" }));
    return [...kids, status];
  }

  function render(rep, { demo = false, cached = false, pending = false, keepPlace = false } = {}) {
    const s = rep.score;
    const cats = rep.categories.map((c) => {
      const items = rep.findings.filter((f) => f.category === c.id);
      if (!items.length) return null;
      const bad = items.filter((f) => f.status === "fail" || f.status === "warn");
      const plat = items.filter((f) => f.status === "platform");
      const ok = items.filter((f) => !(f.status === "fail" || f.status === "warn" || f.status === "platform"));
      return h("section", { class: "cat", "aria-labelledby": `cat-${c.id}` },
        h("h3", { id: `cat-${c.id}` }, c.title, h("span", { class: "cnt", text: bad.length ? `${bad.length} to review` : plat.length && !ok.some((f) => f.status === "pass") ? `controlled by ${plat[0].controlledBy}` : "no issues found" })),
        bad.map(findingEl),
        plat.map(findingEl),
        ok.length ? h("details", { class: "passed" }, h("summary", { text: `${ok.filter((f) => f.status === "pass").length} passed, ${ok.filter((f) => f.status !== "pass").length} info` }), ok.map(findingEl)) : null);
    });
    const chips = [];
    if (s.counts.high) chips.push(h("span", { class: "chip c-high", text: `${s.counts.high} high` }));
    if (s.counts.medium) chips.push(h("span", { class: "chip c-medium", text: `${s.counts.medium} medium` }));
    if (s.counts.low) chips.push(h("span", { class: "chip c-low", text: `${s.counts.low} low` }));
    chips.push(h("span", { class: "chip c-pass", text: `${s.counts.pass} passed` }));
    const heading = h("h2", { id: "report-h", tabindex: "-1", text: `Security report for ${rep.host}` });
    out.replaceChildren(...[
      demo ? h("p", { class: "banner", text: "EXAMPLE REPORT: a made-up bakery website, created to show what a report looks like. Not a real scan." }) : null,
      h("div", { class: "rhead" },
        h("div", { class: `gradebox g${s.grade}`, role: "img", "aria-label": `Grade ${s.grade}, score ${s.score} out of 100` }, h("span", { class: "g", text: s.grade }), h("span", { class: "s", text: `${s.score}/100` })),
        h("div", {},
          heading,
          h("p", { class: "rmeta", text: `Checked ${fmtDate(rep.createdAt)}${cached ? " (saved result from the last few minutes)" : ""}${rep.meta?.finalUrl ? ` · ${rep.meta.finalUrl}` : ""}${rep.meta?.cms ? ` · ${rep.meta.cms}` : ""}` }),
          pending ? h("p", { class: "aiwait", role: "status" }, h("span", { class: "spin", "aria-hidden": "true" }), "Writing plain-English explanations… The findings below are ready now; the wording will update in a few seconds.") : null,
          rep.meta && rep.meta.platform ? h("p", { class: "platform-line", text: `Your site runs on ${rep.meta.platform}.` }) : null,
          h("p", { class: "summary", text: rep.summary }),
          h("div", { class: "chips" }, chips))),
      ctaTopEl(rep),
      h("div", { class: "ractions noprint" },
        demo || pending ? null : shareButtons(rep),
        h("button", { type: "button", class: "btn btn-dark", onclick: () => window.print(), text: "Print / save as PDF" }),
        h("button", { type: "button", class: "btn btn-ghost", onclick: () => { out.hidden = true; input.value = ""; window.scrollTo({ top: 0 }); input.focus(); }, text: "Check another site" })),
      cats,
      ctaEl(rep),
      scoreTable(rep),
      h("p", { class: "aivis noprint" }, "Does AI recommend your business? ", h("a", { href: "https://doesaiknowmybusiness.com", "data-cta": "aivis", text: "Run a free AI visibility check →" })),
      h("p", { class: "scope", text: `${rep.scope} A passive check can't prove a site is secure; it shows common gaps that are visible from the outside.${rep.ai?.used ? " Explanations were written with help from Google Gemini, based only on the evidence shown." : ""}` })].flat().filter(Boolean));
    out.hidden = false;
    out.setAttribute("aria-busy", pending ? "true" : "false");
    if (keepPlace) return; // AI wording swapped in: don't move focus or scroll
    heading.focus({ preventScroll: true });
    out.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  }
})();
