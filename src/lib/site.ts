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

/**
 * Metadata for one page, with canonical and og:url derived from the same path.
 *
 * Next replaces a parent's `openGraph` object wholesale rather than merging
 * into it, so a page that sets no openGraph inherits the root layout's
 * `url`. Every subpage was therefore advertising the home page as its social
 * identity: sharing /checks/ produced a card that linked to /. Deriving both
 * URLs from `path` here is what keeps them equal, and keeps them right if a
 * route is ever renamed. The description defaults to the site tagline because
 * an og:description that silently goes missing is worse than a generic one.
 */
export function pageMeta({
  title,
  description = SITE.tagline,
  path,
}: {
  title: string;
  description?: string;
  path: string;
}) {
  const fullTitle = `${title} · ${SITE.name}`;
  return {
    // Plain title: the root layout's `title.template` appends the site name to
    // <title>. openGraph gets no such template, so it is written in full.
    title,
    description,
    alternates: { canonical: absolute(path) },
    openGraph: {
      type: "website" as const,
      siteName: SITE.name,
      title: fullTitle,
      description,
      url: absolute(path),
      images: [
        { url: asset("/og.png"), width: 1200, height: 630, alt: `${SITE.name} website audit` },
      ],
    },
    twitter: {
      card: "summary_large_image" as const,
      title: fullTitle,
      description,
      images: [asset("/og.png")],
    },
  };
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
