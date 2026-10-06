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

  const form = $("#scan-form"), input = $("#url"), auth = $("#authorized"), btn = $("#go"), err = $("#form-err");
  const progress = $("#progress"), plist = $("#progress-list"), plive = $("#progress-live"), out = $("#report");
  const STEPS = ["Looking up the domain", "Checking HTTPS and the certificate", "Reading security headers", "Checking email spoofing protection (SPF, DKIM, DMARC)", "Looking for exposed files and version banners", "Writing your plain-English report"];
  let timer = null;

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

  const params = new URLSearchParams(location.search);
  if (params.get("url")) {
    input.value = params.get("url").slice(0, 200);
    try { history.replaceState(null, "", location.pathname + location.hash); } catch {} // keep the domain out of analytics page URLs
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    const url = input.value.trim();
    if (!url) { err.textContent = "Enter your website address, like yourbusiness.com."; input.focus(); return; }
    if (!auth.checked) { err.textContent = "Please confirm you own this website or have permission to check it."; auth.focus(); return; }
    btn.disabled = true; btn.textContent = "Checking…";
    out.hidden = true; out.setAttribute("aria-busy", "true");
    startProgress();
    track("scan_started");
    try {
      const r = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, authorized: true, company_website: $("#company_website").value }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.report) {
        err.textContent = j.message || (r.status === 429 ? "Too many checks right now. Please try again later." : "Something went wrong. Please try again.");
        track("scan_failed", { reason: j.error || String(r.status) });
        input.focus();
        return;
      }
      render(j.report, { cached: j.cached });
      track("scan_completed", { grade: j.report.score.grade, score: j.report.score.score, cached: Boolean(j.cached) });
    } catch {
      err.textContent = "Connection lost. Check your internet and try again.";
    } finally {
      stopProgress();
      btn.disabled = false; btn.textContent = "Run free check";
      out.setAttribute("aria-busy", "false");
    }
  });

  $("#demo").addEventListener("click", async () => {
    err.textContent = "";
    try {
      const r = await fetch("/demo.json");
      render(await r.json(), { demo: true });
      track("example_viewed");
    } catch { err.textContent = "Couldn't load the example. Please try again."; }
  });

  if (params.has("example")) $("#demo").click(); // /?example opens the sample report directly

  document.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest("a[data-cta]");
    if (a) track("cta_click", { method: a.dataset.cta, location: a.closest("#report") ? "report" : "page" });
  });

  // Print: open every collapsed section so nothing is hidden on paper.
  let reopened = [];
  window.addEventListener("beforeprint", () => { reopened = [...document.querySelectorAll("#report details:not([open])")]; reopened.forEach((d) => (d.open = true)); });
  window.addEventListener("afterprint", () => { reopened.forEach((d) => (d.open = false)); reopened = []; });

  const STATUS = { fail: "Needs fixing", warn: "Could be better", pass: "Looks good", info: "Info", error: "Couldn't check" };
  const SEV = { high: "High priority", medium: "Medium", low: "Low" };
  const fmtDate = (iso) => { try { return new Date(iso).toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" }); } catch { return iso; } };

  function findingEl(f) {
    const bad = f.status === "fail" || f.status === "warn";
    const card = h("article", { class: `find s-${f.status} v-${f.severity}` },
      h("div", { class: "fhead" },
        h("h4", { text: f.title }),
        h("span", { class: `tag t-${f.status}`, text: STATUS[f.status] || f.status }),
        bad && SEV[f.severity] ? h("span", { class: "tag t-sev", text: SEV[f.severity] }) : null),
      h("p", { class: "ev", text: f.evidence }));
    if (f.what) card.append(h("p", {}, h("span", { class: "lab", text: bad ? "What this means: " : "" }), f.what));
    if (bad && f.fix) card.append(h("p", {}, h("span", { class: "lab", text: "How to fix: " }), f.fix));
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
      h("p", { text: `Start at ${r.start}. Each failed check subtracts ${r.fail.high} (high), ${r.fail.medium} (medium), or ${r.fail.low} (low) points. Warnings subtract ${r.warn.high}, ${r.warn.medium}, or ${r.warn.low}. Info and "couldn't check" items subtract nothing. Any high-severity failure caps the score at ${r.highCap}. Grades: ${r.grades.map((g) => `${g.grade} ${g.min}+`).join(", ").replace(" 0+", " below 60")}.` }),
      rows.length ? h("table", {}, h("thead", {}, h("tr", {}, h("th", { scope: "col", text: "Check" }), h("th", { scope: "col", text: "Result" }), h("th", { scope: "col", text: "Points" }))), h("tbody", {}, rows),
        h("tfoot", {}, h("tr", {}, h("th", { scope: "row", text: "Score" }), h("td", { text: rep.score.capped ? `capped at ${r.highCap} (high-severity failure)` : "" }), h("td", { text: String(rep.score.score) })))) : h("p", { text: "Nothing was deducted." }));
  }

  function ctaEl(rep, demo) {
    const bad = rep.findings.filter((f) => f.status === "fail" || f.status === "warn");
    const nick = bad.filter((f) => f.fixBy === "nick");
    const refer = bad.filter((f) => f.fixBy === "refer");
    const host = rep.host;
    const body = `Hi Nick,\n\nI ran SiteSafeCheck on ${host} (grade ${rep.score.grade}, ${rep.score.score}/100) and I'd like help with:\n${nick.map((f) => `- ${f.title}`).join("\n") || "- a monthly re-scan"}\n\nName:\nBest phone:\n`;
    const mail = `mailto:${EMAIL}?subject=${encodeURIComponent(`SiteSafeCheck: help with ${host}`)}&body=${encodeURIComponent(body)}`;
    const sms = `sms:${PHONE}?&body=${encodeURIComponent(`Hi Nick, I ran SiteSafeCheck on ${host} (grade ${rep.score.grade}). Can you help fix the issues?`)}`;
    const lists = h("div", { class: "lists" });
    if (nick.length) lists.append(h("div", {}, h("h3", { text: `Nick can fix ${nick.length === 1 ? "this" : `these ${nick.length}`} from your report` }), h("ul", {}, nick.map((f) => h("li", { text: f.title })))));
    if (refer.length) lists.append(h("div", { class: "refer" }, h("h3", { text: "Referred out (handle urgently)" }), h("ul", {}, refer.map((f) => h("li", { text: f.title }))), h("p", { class: "small", text: "Have your developer, host, or a security professional handle these. Nick can refer you out." })));
    return h("section", { class: "cta", "aria-labelledby": "cta-h" },
      h("h2", { id: "cta-h", text: nick.length ? "Want these fixed? Nick can fix the common website security gaps." : "Want to keep it this way? Nick can watch it for you." }),
      h("p", { text: nick.length ? "Nick Castro is a web developer who fixes the everyday configuration gaps this check finds, explained in plain English, with no upsell to things you don't need." : "No common gaps for Nick to fix right now. A monthly re-scan catches changes, like a certificate that's about to expire." }),
      lists.children.length ? lists : null,
      h("div", { class: "prices" },
        h("div", { class: "price" }, h("h3", { text: "One-time fix" }), h("div", { class: "amt", text: "$250–$500" }), h("p", { text: "Security headers, HTTPS/SSL setup, SPF/DKIM/DMARC, version banners, cookie flags." })),
        h("div", { class: "price" }, h("h3", { text: "Monthly re-scan & watch" }), h("div", { class: "amt", text: "$50–$100/mo" }), h("p", { text: "A fresh check every month and a plain-English note on what changed." })),
        h("div", { class: "price" }, h("h3", { text: "Website package" }), h("div", { class: "amt", text: "Bundled" }), h("p", { text: "Included when Nick builds or refreshes your website." }))),
      h("div", { class: "contact" },
        h("a", { class: "btn btn-light", href: `tel:${PHONE}`, "data-cta": "call", text: "Call (708) 250-1040" }),
        h("a", { class: "btn btn-ghost", href: sms, "data-cta": "text", text: "Text Nick" }),
        h("a", { class: "btn btn-ghost", href: mail, "data-cta": "email", text: `Email ${EMAIL}` })),
      h("p", { class: "print-contact", text: `Call or text (708) 250-1040 · ${EMAIL}` }),
      h("p", { class: "small", text: "Nick fixes common configuration gaps. He doesn't do penetration testing, code audits, malware or breach cleanup, or server repairs; for those he'll refer you to a specialist." + (demo ? "" : "") }));
  }

  function render(rep, { demo = false, cached = false } = {}) {
    const s = rep.score;
    const cats = rep.categories.map((c) => {
      const items = rep.findings.filter((f) => f.category === c.id);
      if (!items.length) return null;
      const bad = items.filter((f) => f.status === "fail" || f.status === "warn");
      const ok = items.filter((f) => !(f.status === "fail" || f.status === "warn"));
      return h("section", { class: "cat", "aria-labelledby": `cat-${c.id}` },
        h("h3", { id: `cat-${c.id}` }, c.title, h("span", { class: "cnt", text: bad.length ? `${bad.length} to review` : "no issues found" })),
        bad.map(findingEl),
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
          h("p", { class: "summary", text: rep.summary }),
          h("div", { class: "chips" }, chips))),
      h("div", { class: "ractions noprint" },
        h("button", { type: "button", class: "btn btn-dark", onclick: () => window.print(), text: "Print / save as PDF" }),
        h("button", { type: "button", class: "btn btn-ghost", onclick: () => { out.hidden = true; input.value = ""; window.scrollTo({ top: 0 }); input.focus(); }, text: "Check another site" })),
      cats,
      scoreTable(rep),
      h("p", { class: "scope", text: `${rep.scope} A passive check can't prove a site is secure; it shows common gaps that are visible from the outside.${rep.ai?.used ? " Explanations were written with help from Google Gemini, based only on the evidence shown." : ""}` }),
      ctaEl(rep, demo)].flat().filter(Boolean));
    out.hidden = false;
    heading.focus({ preventScroll: true });
    out.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  }
})();
