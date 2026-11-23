#!/usr/bin/env node
/**
 * Build the GitHub Pages deployable from the source tree.
 *
 *   node scripts/build.mjs pages
 *
 * GitHub Pages serves a project site from /<repo>/, so every asset URL needs
 * that prefix baked in at build time. Next.js can only apply `basePath` during
 * the build, which is why this runs the compiler rather than rewriting paths
 * afterwards.
 *
 * Env:
 *   NEXT_PUBLIC_SITE_URL   canonical origin, e.g. https://izynu.github.io
 *   OC_PAGES_BASE          basePath for the Pages build, default "/ocellus"
 *   OC_PAGES_CNAME         custom domain to write into CNAME, optional
 */

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const dist = join(root, "dist");

const PAGES_BASE = process.env.OC_PAGES_BASE || "/ocellus";

function clean(dir) {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
}

function buildPages() {
  const outDir = join(dist, "pages");
  const origin = (process.env.NEXT_PUBLIC_SITE_URL || "https://izynu.github.io").replace(
    /\/$/,
    ""
  );

  console.log(`\n=== build: basePath=${PAGES_BASE} site=${origin}`);
  // `out/` is Next's fixed export directory; it is moved to dist/pages after.
  rmSync(join(root, "out"), { recursive: true, force: true });
  execFileSync("npx", ["next", "build"], {
    cwd: root,
    stdio: "inherit",
    env: {
      ...process.env,
      OC_BASE_PATH: PAGES_BASE,
      NEXT_PUBLIC_SITE_URL: origin,
    },
  });
  if (!existsSync(join(root, "out"))) {
    throw new Error("next build produced no out/ directory");
  }
  clean(outDir);
  cpSync(join(root, "out"), outDir, { recursive: true });
  rmSync(join(root, "out"), { recursive: true, force: true });

  // GitHub Pages runs Jekyll unless told not to, and Jekyll drops paths that
  // start with an underscore, which breaks Next's _next/ asset directory.
  writeFileSync(join(outDir, ".nojekyll"), "");

  // A custom domain is set by a CNAME file at the root of what Pages serves.
  // Empty or unset OC_PAGES_CNAME means the Pages host stays canonical.
  const cname = (process.env.OC_PAGES_CNAME || "").trim();
  if (cname) {
    writeFileSync(join(outDir, "CNAME"), `${cname}\n`);
    console.log(`pages: custom domain ${cname}`);
  } else if (PAGES_BASE === "") {
    // A base path of "" is only correct when the site is served from an origin
    // root, which on Pages means a custom domain. Building without one and
    // without a prefix produces a site whose own assets 404, so it is a hard
    // error rather than a warning.
    throw new Error(
      "OC_PAGES_BASE is empty but no custom domain was set. A project site must be built with /<repo>."
    );
  }
  console.log(`pages: base path ${PAGES_BASE || "(none, custom domain root)"}`);

  writeFileSync(
    join(dist, "build.json"),
    JSON.stringify(
      {
        builtAt: new Date().toISOString(),
        target: "github-pages",
        dir: "dist/pages",
        basePath: PAGES_BASE,
        siteUrl: origin,
        customDomain: cname || null,
      },
      null,
      2
    )
  );
}

const target = process.argv[2] || "pages";
if (target !== "pages") {
  console.error(`Unknown target "${target}". This repository deploys to GitHub Pages only.`);
  process.exit(1);
}

mkdirSync(dist, { recursive: true });
buildPages();

const dir = join(dist, "pages");
const size = execFileSync("du", ["-sh", dir], { encoding: "utf8" }).split("\t")[0];
const files = execFileSync("sh", ["-c", `find ${JSON.stringify(dir)} -type f | wc -l`], {
  encoding: "utf8",
}).trim();
console.log(`\npages: ${files} files, ${size}`);
