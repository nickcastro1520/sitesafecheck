// Shared report page: track the "Run this check" and contact taps.
(() => {
  const track = (n, p) => { try { if (typeof window.gtag === "function") window.gtag("event", n, p || {}); } catch {} };
  document.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest("a");
    if (!a) return;
    if (a.id === "run-shared") track("shared_run_click");
    else if (a.dataset.cta) track("cta_click", { method: a.dataset.cta, location: "shared" });
  });
})();
