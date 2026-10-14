// GET /r?url=...&g=...  (rewritten from /r): the shared report page. noindex, no storage.
import { parseShare, sharePage } from "./_lib/share-page.js";

export async function GET(request) {
  const sh = parseShare(new URL(request.url).searchParams);
  const headers = { "Content-Type": "text/html; charset=utf-8", "X-Robots-Tag": "noindex, nofollow", "Cache-Control": "public, max-age=300" };
  if (!sh) return new Response(null, { status: 302, headers: { Location: "/", "X-Robots-Tag": "noindex" } });
  const ga = String(process.env.GA_MEASUREMENT_ID || "").trim();
  return new Response(sharePage(sh, { ga: /^G-[A-Z0-9]{4,15}$/.test(ga) ? ga : "" }), { status: 200, headers });
}
