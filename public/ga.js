// Google Analytics 4, only included in the page when GA_MEASUREMENT_ID is configured at build time.
// Kept in a file so the site's strict CSP doesn't need 'unsafe-inline'.
(function () {
  var s = document.currentScript, id = s && s.getAttribute("data-ga");
  if (!id || !/^G-[A-Z0-9]{4,15}$/.test(id)) return;
  window.dataLayer = window.dataLayer || [];
  function gtag() { window.dataLayer.push(arguments); }
  window.gtag = gtag;
  gtag("js", new Date());
  gtag("config", id, { anonymize_ip: true });
  var t = document.createElement("script");
  t.async = true;
  t.src = "https://www.googletagmanager.com/gtag/js?id=" + encodeURIComponent(id);
  document.head.appendChild(t);
})();
