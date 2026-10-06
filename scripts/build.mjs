// Build: copy public/ to dist/ and inject optional settings into the HTML pages.
//   GA_MEASUREMENT_ID         -> loads Google Analytics 4 (via /ga.js). Empty = no analytics at all.
//   GOOGLE_SITE_VERIFICATION  -> <meta name="google-site-verification"> for Search Console.
// Env vars win; otherwise site.config.json is used. Both are empty by default.
import { readFile, writeFile, mkdir, cp, rm, readdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export async function loadSettings(env = process.env) {
  let file = {};
  try { file = JSON.parse(await readFile(join(ROOT, "site.config.json"), "utf8")); } catch {}
  const ga = String(env.GA_MEASUREMENT_ID ?? file.gaMeasurementId ?? "").trim();
  const gsc = String(env.GOOGLE_SITE_VERIFICATION ?? file.googleSiteVerification ?? "").trim();
  return {
    ga: /^G-[A-Z0-9]{4,15}$/.test(ga) ? ga : "",
    gsc: /^[A-Za-z0-9_-]{10,100}$/.test(gsc) ? gsc : "",
    gaInvalid: Boolean(ga && !/^G-[A-Z0-9]{4,15}$/.test(ga)),
    gscInvalid: Boolean(gsc && !/^[A-Za-z0-9_-]{10,100}$/.test(gsc)),
  };
}

export function transformHtml(html, { ga, gsc }) {
  return html
    .replace("<!--GA-->", ga ? `<script src="/ga.js" data-ga="${ga}" defer></script>` : "")
    .replace("<!--GSC-->", gsc ? `<meta name="google-site-verification" content="${gsc}">` : "");
}

async function build() {
  const s = await loadSettings();
  if (s.gaInvalid) console.warn("GA_MEASUREMENT_ID ignored: expected something like G-ABC123XYZ");
  if (s.gscInvalid) console.warn("GOOGLE_SITE_VERIFICATION ignored: paste only the content value of the meta tag");
  const out = join(ROOT, "dist");
  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });
  await cp(join(ROOT, "public"), out, { recursive: true });
  for (const f of await readdir(out)) {
    if (!f.endsWith(".html")) continue;
    const p = join(out, f);
    await writeFile(p, transformHtml(await readFile(p, "utf8"), s));
  }
  console.log(`built dist/ (analytics: ${s.ga ? s.ga : "off"}, search console meta: ${s.gsc ? "on" : "off"})`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await build();
