/**
 * Turning what a person typed into a Target.
 *
 * The domain split matters more than it looks: DNS and WHOIS checks need the
 * registrable domain, while the header and content checks need the exact host.
 * `docs.github.com` and `github.com` share WHOIS records but not certificates.
 */

import type { Target } from "./types";

/**
 * Second-level labels under which a country-code TLD is itself registrable.
 * This is the part of the Public Suffix List that actually shows up in web
 * scans. Anything not listed here falls back to "last two labels".
 */
const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
  "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in",
  "gov.in", "res.in", "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  "co.za", "org.za", "net.za", "gov.za", "ac.za",
  "com.br", "net.br", "org.br", "gov.br",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
  "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my",
  "co.kr", "or.kr", "ne.kr", "go.kr",
  "com.pk", "com.bd", "com.np", "com.lk", "com.eg", "com.sa", "com.ng",
  "co.id", "or.id", "web.id", "ac.id", "go.id",
  "co.il", "org.il", "ac.il", "gov.il",
  "com.pl", "net.pl", "org.pl", "com.ua", "org.ua", "co.at", "or.at",
  "com.es", "org.es", "nom.es", "com.pt", "com.gr", "com.ru", "com.vn",
]);

/**
 * Hosted suffixes whose registrable domain is four labels: a customer, then the
 * service's own two or three labels. `user.github.io` is one site, so it must
 * not share a registrable domain with `github.io` itself, which is why these
 * sit in their own set rather than in the suffix set above.
 */
const HOSTED_SUFFIXES = new Set([
  "s3.amazonaws.com",
  "github.io",
  "pages.dev",
  "netlify.app",
  "vercel.app",
  "workers.dev",
  "web.app",
  "firebaseapp.com",
  "herokuapp.com",
  "blogspot.com",
  "azurewebsites.net",
  "cloudfront.net",
]);

export class InvalidTarget extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidTarget";
  }
}

/** Strip a scheme, whitespace and any path, then validate the hostname. */
export function parseTarget(input: string): Target {
  const raw = input.trim();
  if (!raw) throw new InvalidTarget("Enter a web address to scan.");

  let candidate = raw;
  if (!/^https?:\/\//i.test(candidate)) {
    // Bare hosts and hosts with a path both get https by default.
    candidate = "https://" + candidate;
  }

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new InvalidTarget(
      "That is not a valid address. Try a form like example.com or https://example.com/page."
    );
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new InvalidTarget("Only http and https addresses can be scanned.");
  }

  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (!host) throw new InvalidTarget("That address has no hostname.");
  if (host === "localhost" || /^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    throw new InvalidTarget(
      "Ocellus scans public sites. Localhost and bare IP addresses have no DNS, certificate or mail records to read."
    );
  }
  if (!host.includes(".")) {
    throw new InvalidTarget(
      `"${host}" is not a public domain name. Include the ending, for example example.com.`
    );
  }
  if (host.includes("..") || host.startsWith(".") || host.includes(" ")) {
    throw new InvalidTarget("That hostname is malformed.");
  }

  // Keep the path and query: some checks look at the exact URL that was asked
  // for, and the report header should show what was scanned.
  const path = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/$/, "");
  const url = `${parsed.protocol}//${host}${parsed.port ? ":" + parsed.port : ""}${path}${parsed.search}`;

  // The exact host is kept, `www.` included. Stripping it meant a scan of
  // www.example.com fetched headers and DNS for example.com instead, and those
  // two hosts can answer differently: a redirect, a certificate, or a whole
  // separate vhost. The registrable domain is still derived from the full host.
  const domain = registrableDomain(host);
  const subdomain =
    host === domain ? "" : host.slice(0, Math.max(0, host.length - domain.length - 1));

  return {
    input: raw,
    url,
    host,
    domain,
    subdomain,
    scheme: parsed.protocol === "http:" ? "http" : "https",
  };
}

/**
 * True when `host` belongs to the scanned site rather than a third party.
 *
 * Two different questions get asked in the checks and they have different
 * answers. "Same origin" is an exact host match. "Same site" also covers the
 * registrable domain, so www.example.com and cdn.example.com are first-party
 * for a scan of example.com. Both comparisons have to respect the label
 * boundary: a bare `endsWith` calls notexample.com first-party.
 */
export function isSameSite(host: string, target: Target): boolean {
  const h = host.toLowerCase();
  const t = target.domain.toLowerCase();
  return h === t || h.endsWith("." + t);
}

/** eTLD+1, best-effort. Returns the input when it is already short enough. */
export function registrableDomain(host: string): string {
  const labels = host.split(".");
  if (labels.length <= 2) return host;

  const lastThree = labels.slice(-3).join(".");
  if (HOSTED_SUFFIXES.has(lastThree)) {
    // A four-label hosted domain, e.g. user.github.io. The apex itself
    // (github.io) is the suffix, not a site, so it is returned unchanged
    // rather than trimmed to nothing.
    return labels.length >= 4 ? labels.slice(-4).join(".") : host;
  }

  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}
