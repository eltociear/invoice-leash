// Every link in the documents and the site that points into this repository resolves: the file exists, and
// an anchor (#…) names a heading or an id in it. Offline. Links to github.com/eltociear/invoice-leash/blob|tree/main
// and to the published site are checked against the files here; other sites are not fetched.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const slug = (s) => s.toLowerCase().replace(/<[^>]+>/g, "").replace(/\[([^\]]*)\]\([^)]*\)/g, "$1").replace(/[`*_]/g, "").replace(/[^\p{L}\p{N}\s-]/gu, "").trim().replace(/\s/g, "-");
const cache = new Map();
function anchors(f) {
  if (cache.has(f)) return cache.get(f);
  const t = readFileSync(f, "utf8"), s = new Set();
  if (f.endsWith(".md")) {
    const seen = {};
    for (const m of t.matchAll(/^#{1,6}\s+(.*)$/gm)) { let a = slug(m[1]); if (seen[a] !== undefined) a = `${a}-${++seen[a]}`; else seen[a] = 0; s.add(a); }
    for (const m of t.matchAll(/<a (?:name|id)="([^"]+)"/g)) s.add(m[1]);
  } else for (const m of t.matchAll(/\bid=["']([^"']+)["']/g)) s.add(m[1]);
  cache.set(f, s); return s;
}
const md = (dir) => readdirSync(join(root, dir)).filter((f) => f.endsWith(".md")).map((f) => join(root, dir, f));
const files = [...md("."), ...readdirSync(join(root, "docs")).filter((f) => f.endsWith(".html")).map((f) => join(root, "docs", f)),
  ...readdirSync(join(root, "runs")).filter((d) => statSync(join(root, "runs", d)).isDirectory()).flatMap((d) => md(`runs/${d}`))];
const bad = [];
let n = 0;
for (const f of files) {
  const t = readFileSync(f, "utf8");
  const links = f.endsWith(".md") ? [...t.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]) : [...t.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
  for (let l of links) {
    l = l.replace(/&amp;/g, "&");
    let base = dirname(f);
    if (l.startsWith("https://eltociear.github.io/invoice-leash/")) { l = l.slice("https://eltociear.github.io/invoice-leash/".length); if (!l || l.startsWith("#")) l = "index.html" + l; base = join(root, "docs"); }
    else if (/^https:\/\/github\.com\/eltociear\/invoice-leash\/(blob|tree)\/main\//.test(l)) { l = l.replace(/^https:\/\/github\.com\/eltociear\/invoice-leash\/(blob|tree)\/main\//, ""); base = root; }
    else if (/^(https?:|mailto:|data:|javascript:)/.test(l) || l.includes("' + ") || l.includes("${")) continue; // other sites; links built by page scripts
    const [p, h] = l.split("#");
    const target = p ? resolve(base, decodeURIComponent(p)) : f;
    n++;
    if (!existsSync(target)) { bad.push(`${f.slice(root.length)} -> ${l}: no such file`); continue; }
    if (h && !statSync(target).isDirectory() && /\.(md|html)$/.test(target) && !anchors(target).has(h)) bad.push(`${f.slice(root.length)} -> ${l}: no such anchor`);
  }
}
if (bad.length) { console.log(bad.join("\n")); console.log(`✗ links: ${bad.length} of ${n} do not resolve`); process.exit(1); }
console.log(`✓ links: ${n} links into this repository and the site resolve (${files.length} files)`);
