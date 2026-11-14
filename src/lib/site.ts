/**
 * Every fact about the product that appears in more than one place.
 *
 * Two values change per deployment and live only here:
 *
 *   NEXT_PUBLIC_SITE_URL  the origin, e.g. https://ocellus.zynu.me
 *   OC_BASE_PATH          the path prefix, empty at a document root and
 *                         "/ocellus" for a GitHub project site
 *
 * Next applies the base path to `next/link` and to bundled assets by itself.
 * It does not apply it to literal strings in metadata (icons, manifest,
 * canonical, og:image), so those go through `asset()`.
 */

export const BASE_PATH = (process.env.OC_BASE_PATH || "").replace(/\/$/, "");

const ORIGIN = (process.env.NEXT_PUBLIC_SITE_URL || "https://ocellus.zynu.me").replace(
  /\/$/,
  ""
);

export const SITE = {
  name: "Ocellus",
  /** One line, used as the default meta description and under the wordmark. */
  tagline:
    "A browser-side audit of what a website exposes, and what it asks of the people using it.",
  /** Origin only, no trailing slash and no base path. */
  origin: ORIGIN,
  /** Canonical site URL: origin plus the base path the build was made for. */
  url: ORIGIN + BASE_PATH,
  repo: "https://github.com/izynu/ocellus",
  author: "Zynu",
  authorUrl: "https://zynu.me",
  year: 2026,
  /** Bump when the report schema changes; it is printed on every export. */
  reportVersion: "1.0",
} as const;

/** Prefix a root-relative path with the base path. Passes external URLs through. */
export function asset(path: string): string {
  if (/^[a-z]+:/i.test(path) || path.startsWith("//")) return path;
  return BASE_PATH + (path.startsWith("/") ? path : `/${path}`);
}

/** Absolute URL for a path, including the base path. */
export function absolute(path = "/"): string {
  return SITE.url + (path.startsWith("/") ? path : `/${path}`);
}

/** Primary navigation. The header, footer and sitemap all read this. */
export const ROUTES = [
  { href: "/", label: "Home" },
  { href: "/scan", label: "Scan" },
  { href: "/checks", label: "Checks" },
  { href: "/method", label: "Method" },
  { href: "/about", label: "About" },
] as const;

export const LEGAL_ROUTES = [
  { href: "/privacy", label: "Privacy" },
  { href: "/terms", label: "Terms" },
] as const;
