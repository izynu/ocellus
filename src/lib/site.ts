/**
 * Every fact about the product that appears in more than one place.
 *
 * Two values change per deployment and live only here:
 *
 *   NEXT_PUBLIC_SITE_URL  the origin, e.g. https://izynu.github.io
 *   OC_BASE_PATH          the path prefix, empty at a document root and
 *                         "/ocellus" for this GitHub project site
 *
 * Next applies the base path to `next/link` and to bundled assets by itself.
 * It does not apply it to literal strings in metadata (icons, manifest,
 * canonical, og:image), so those go through `asset()`.
 *
 * A custom domain is wired but not yet claimed: set the repository variables
 * `SITE_URL` and `CUSTOM_DOMAIN`, push, and `scripts/build.mjs` writes the CNAME
 * file and bakes the origin in. Until then the Pages host is canonical, so
 * nothing on the site points at a domain that does not resolve.
 */

export const BASE_PATH = (process.env.OC_BASE_PATH || "").replace(/\/$/, "");

const ORIGIN = (process.env.NEXT_PUBLIC_SITE_URL || "https://izynu.github.io").replace(
  /\/$/,
  ""
);

export const SITE = {
  name: "Ocellus",
  /** One line, used as the default meta description and under the wordmark. */
  tagline:
    "A browser-side website audit and reconnaissance console: DNS, certificates, headers, email, exposure, reputation, privacy, accessibility and performance, plus a catalogue of every scanner that answers the same questions.",
  /** Origin only, no trailing slash and no base path. */
  origin: ORIGIN,
  /** Canonical site URL: origin plus the base path the build was made for. */
  url: ORIGIN + BASE_PATH,
  repo: "https://github.com/izynu/ocellus",
  issues: "https://github.com/izynu/ocellus/issues",
  author: "Zynu",
  authorUrl: "https://zynu.me",
  year: 2026,
  /** Bump when the report schema changes; it is printed on every export. */
  reportVersion: "1.1",
} as const;

/**
 * Search keywords. Kept here so the layout, the manifest and the README draw on
 * one list. These are terms a person types when looking for this kind of tool.
 */
export const KEYWORDS = [
  "website audit",
  "website security scanner",
  "website reconnaissance",
  "recon tool",
  "OSINT tool",
  "security headers checker",
  "HTTP header scanner",
  "Content-Security-Policy",
  "HSTS",
  "security.txt",
  "DNS lookup",
  "DNS records",
  "DNSSEC checker",
  "CAA record",
  "MX record checker",
  "SPF checker",
  "DKIM checker",
  "DMARC checker",
  "MTA-STS",
  "email authentication",
  "email spoofing",
  "certificate transparency",
  "CT logs",
  "certificate revocation",
  "subdomain enumeration",
  "subdomain finder",
  "passive DNS",
  "reverse DNS",
  "reverse IP lookup",
  "whois lookup",
  "RDAP lookup",
  "domain age",
  "domain expiry",
  "IP geolocation",
  "ASN lookup",
  "BGP lookup",
  "open ports",
  "Shodan",
  "Censys",
  "attack surface",
  "URL scanner",
  "malware scanner",
  "phishing check",
  "VirusTotal",
  "Google Safe Browsing",
  "URLhaus",
  "OpenPhish",
  "threat intelligence",
  "AlienVault OTX",
  "blocklist check",
  "spam blocklist",
  "domain reputation",
  "IP reputation",
  "CISA KEV",
  "EPSS",
  "CVE exposure",
  "technology fingerprint",
  "tech stack detector",
  "Wappalyzer",
  "WhatWeb",
  "web archive",
  "Wayback Machine",
  "Google dorks",
  "dork generator",
  "google hacking",
  "shodan dorks",
  "privacy report",
  "tracker detection",
  "cookie audit",
  "consent dark patterns",
  "accessibility audit",
  "WCAG checker",
  "SEO audit",
  "robots.txt checker",
  "sitemap checker",
  "page weight",
  "carbon footprint website",
  "Nuclei",
  "nmap",
  "subfinder",
  "amass",
  "httpx",
  "katana",
  "OWASP",
  "penetration testing recon",
  "bug bounty recon",
  "static site scanner",
  "browser only scanner",
  "no API key scanner",
  "client side security scanner",
] as const;

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
 * into it, so a page that sets no openGraph inherits the root layout's `url`.
 * Deriving both URLs from `path` here keeps them equal, and keeps them right if
 * a route is ever renamed. The description defaults to the site tagline because
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

/**
 * Primary navigation. The header, footer, sitemap and landing page all read
 * this, so a route cannot be published without appearing in the nav.
 *
 * `group` decides where a link sits: the header carries the product surface,
 * the footer adds the reference pages beneath it.
 */
export const ROUTES = [
  { href: "/", label: "Home", group: "product" },
  { href: "/scan", label: "Scan", group: "product" },
  { href: "/url-scan", label: "URL scan", group: "product" },
  { href: "/ports", label: "Nmap", group: "product" },
  { href: "/checks", label: "Checks", group: "product" },
  { href: "/sources", label: "Sources", group: "product" },
  { href: "/dorks", label: "Dorks", group: "product" },
  { href: "/recon", label: "Recon", group: "product" },
  { href: "/method", label: "Method", group: "reference" },
  { href: "/about", label: "About", group: "reference" },
] as const;

export const LEGAL_ROUTES = [
  { href: "/privacy", label: "Privacy", group: "legal" },
  { href: "/terms", label: "Terms", group: "legal" },
] as const;

/** Header links: the product surface only, so the bar stays readable. */
export const NAV_ROUTES = ROUTES.filter(
  (route) => route.href !== "/" && route.group === "product"
);

/** Footer columns, derived so they cannot drift from the route table. */
export const FOOTER_PRODUCT = ROUTES.filter(
  (route) => route.group === "product" && route.href !== "/"
);
export const FOOTER_REFERENCE = ROUTES.filter((route) => route.group === "reference");
