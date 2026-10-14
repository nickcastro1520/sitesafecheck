// Writes public/sitemap.xml with lastmod = the last git commit date of each page's HTML.
// Run before committing page changes: node scripts/sitemap.mjs
import { writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";

export const PAGES = [
  { path: "/", file: "public/index.html", changefreq: "monthly", priority: "1.0" },
  { path: "/about", file: "public/about.html", changefreq: "monthly", priority: "0.6" },
  { path: "/how-i-built-this", file: "public/how-i-built-this.html", changefreq: "monthly", priority: "0.6" },
  { path: "/privacy", file: "public/privacy.html", changefreq: "yearly", priority: "0.3" },
];
const lastmod = (f) => execFileSync("git", ["log", "-1", "--format=%cs", "--", f], { encoding: "utf8" }).trim() || new Date().toISOString().slice(0, 10);

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop())) {
  const rows = PAGES.map((p) => ` <url><loc>https://sitesafecheck.com${p.path}</loc><lastmod>${lastmod(p.file)}</lastmod><changefreq>${p.changefreq}</changefreq><priority>${p.priority}</priority></url>`);
  await writeFile(new URL("../public/sitemap.xml", import.meta.url), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${rows.join("\n")}\n</urlset>\n`);
  console.log("sitemap.xml written");
}
