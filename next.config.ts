import type { NextConfig } from "next";

/**
 * Ocellus is a static site. Every check runs in the browser against public
 * APIs, so there is no server component and no API route to deploy. Both hosts
 * that ship it (GitHub Pages and the standalone host) serve the same `out/`.
 *
 * `basePath` is applied at build time by `scripts/build-pages.mjs`, which sets
 * OC_BASE_PATH=/<repo> for the GitHub Pages build and leaves it empty for the
 * standalone build.
 */
const basePath = process.env.OC_BASE_PATH || "";

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  basePath,
  assetPrefix: basePath || undefined,
  images: { unoptimized: true },
  reactStrictMode: true,
  typescript: { ignoreBuildErrors: false },
};

export default nextConfig;
