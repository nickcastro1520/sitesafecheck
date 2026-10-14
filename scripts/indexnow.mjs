// Submit every sitemap URL to IndexNow (Bing, Yandex, Seznam, Naver...). Free, no account.
// Usage: node scripts/indexnow.mjs   (reads the live sitemap; set SITEMAP_FILE to use a local file)
import { readFile, readdir } from "node:fs/promises";

const HOST = "sitesafecheck.com";
const dir = new URL("../public/", import.meta.url);
const keyFile = (await readdir(dir)).find((f) => /^[a-f0-9]{32}\.txt$/.test(f));
if (!keyFile) throw new Error("IndexNow key file missing in public/");
const key = (await readFile(new URL(keyFile, dir), "utf8")).trim();

const xml = process.env.SITEMAP_FILE ? await readFile(process.env.SITEMAP_FILE, "utf8") : await (await fetch(`https://${HOST}/sitemap.xml`)).text();
const urlList = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1].trim()).filter((u) => new URL(u).host === HOST);
if (!urlList.length) throw new Error("no URLs found in sitemap");

const res = await fetch("https://api.indexnow.org/indexnow", {
  method: "POST",
  headers: { "Content-Type": "application/json; charset=utf-8" },
  body: JSON.stringify({ host: HOST, key, keyLocation: `https://${HOST}/${keyFile}`, urlList }),
});
console.log(`IndexNow: HTTP ${res.status} for ${urlList.length} URLs`);
for (const u of urlList) console.log(" ", u);
if (![200, 202].includes(res.status)) { console.error(await res.text().catch(() => "")); process.exit(1); }
