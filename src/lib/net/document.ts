/**
 * Getting the target's HTML, once, for every content check.
 *
 * A static page cannot read a cross-origin response body directly, and a large
 * share of the web sends no CORS header. So the document comes from a reader
 * service that does send one and returns the page as real HTML, scripts and
 * meta tags included. If the reader fails, we fall back to the metadata
 * endpoint, which gives a thinner but still genuine document.
 *
 * Two invariants the rest of the app depends on:
 *  - `html()` resolves once and is memoised, so forty checks cost one request.
 *  - A consent wall or bot check is detected and flagged, because analysing
 *    Cloudflare's interstitial instead of the page would be a silent lie.
 */

import type { HtmlDocument, HeaderSnapshot, Target } from "../types";
import type { NetClient } from "./client";

const READER = "https://r.jina.ai/";

/** Phrases that mean we were served a gate, not the page. */
const INTERSTITIAL_MARKERS = [
  "checking your browser",
  "verify you are human",
  "just a moment",
  "enable javascript and cookies to continue",
  "attention required",
  "access denied",
  "ddos protection by",
  "please complete the security check",
  "unusual traffic from your computer",
  "before you continue to",
  "we value your privacy",
  "consent to the use of cookies",
  "captcha",
];

function looksLikeInterstitial(source: string): boolean {
  const head = source.slice(0, 4000).toLowerCase();
  const lower = source.toLowerCase();
  // A real page can mention cookies; a gate is short and dominated by the phrase.
  const short = lower.length < 30_000;
  return INTERSTITIAL_MARKERS.some((m) => head.includes(m) || (short && lower.includes(m)));
}

function parse(source: string): Document | null {
  try {
    return new DOMParser().parseFromString(source, "text/html");
  } catch {
    return null;
  }
}

export async function fetchHtml(
  net: NetClient,
  target: Target
): Promise<HtmlDocument> {
  // Direct first, reader second.
  //
  // The reader is not a proxy: it parses the page and serializes it again, which
  // drops the doctype, re-quotes every attribute, and empties every `<svg>` that
  // is not inside a `<template>`. A live fetch of react.dev returned all 123
  // SVG elements self-closed with zero `<path>` children, so a DOM-node count
  // from that route undercounts a page that draws its icons inline by roughly a
  // quarter, and a byte count is the reader's serialization rather than the
  // site's.
  //
  // The site's own bytes are available whenever it sends
  // `Access-Control-Allow-Origin`, which react.dev, nextjs.org and svelte.dev
  // all do. When it does not, the browser throws and the request costs one
  // failed connection. So the direct attempt is free when it works and free
  // when it does not, and it gives byte-faithful markup for the share of sites
  // that permit it.
  const direct = await net.text(target.url, {
    timeoutMs: 15_000,
    // No retry: a CORS refusal is not transient, and a retry would double the
    // wait on the sites that cannot answer at all.
    headers: { Accept: "text/html,application/xhtml+xml" },
    cacheKey: `html-direct:${target.url}`,
  });

  if (direct.ok && direct.text.trim().length > 200) {
    const source = direct.text;
    return {
      finalUrl: direct.url || target.url,
      source,
      doc: parse(source),
      suspectInterstitial: looksLikeInterstitial(source),
      via: "the site's own response",
      byteFaithful: true,
    };
  }

  // The reader returns the rendered document as HTML when asked. It follows
  // redirects and sends CORS headers for any origin. It rate limits at 20
  // requests a minute per IP, and a single scan spends five of those, so a
  // retry here is cheap and a timeout is not: every document-derived check
  // shares this one promise.
  //
  // `x-no-cache` is not an optimisation, it is correctness. The reader keeps a
  // shared cache of every URL it has ever fetched, and a cached entry can be
  // arbitrary: during testing, `https://example.com` came back as a 410-byte
  // placeholder whose title was a string nobody had put there. Every content
  // check then audited that placeholder and reported its properties as the
  // target's. A live audit has to read the live page, so the cache is bypassed.
  // It costs the same tokens either way.
  const readerUrl = `${READER}${target.url}`;
  const res = await net.text(readerUrl, {
    timeoutMs: 35_000,
    retry: true,
    headers: {
      "x-respond-with": "html",
      "x-retain-images": "none",
      "x-no-cache": "true",
    },
    cacheKey: `html:${target.url}`,
  });

  if (res.ok && res.text.trim().length > 200) {
    const source = res.text;
    return {
      finalUrl: target.url,
      source,
      doc: parse(source),
      suspectInterstitial: looksLikeInterstitial(source),
      via: "r.jina.ai reader",
      // Re-serialized, so element and byte counts are not the site's own.
      byteFaithful: false,
    };
  }

  // Fallback: the metadata endpoint returns a small JSON object with title,
  // description and Open Graph fields. Enough for the SEO checks, not enough
  // for markup analysis, and `doc` stays null so callers can tell.
  //
  // This is a last resort, not a second opinion. Its free tier allows five
  // requests a day, so two scans can exhaust it, and a fallback that dies on
  // the first busy day fails silently for every visitor at once. The reader
  // above is the primary for that reason; this path exists only so a reader
  // outage degrades the report to titles and descriptions rather than
  // emptying it.
  const metaUrl = `https://api.microlink.io/?url=${encodeURIComponent(target.url)}&meta=true`;
  const meta = await net.json<{
    status?: string;
    data?: Record<string, unknown>;
  }>(metaUrl, { timeoutMs: 20_000, cacheKey: `meta:${target.url}` });

  if (meta.ok && meta.json && (meta.json as { status?: string }).status === "success") {
    const data = (meta.json as { data: Record<string, unknown> }).data;
    const source = synthesizeFromMeta(data);
    return {
      finalUrl: typeof data.url === "string" ? data.url : target.url,
      source,
      doc: parse(source),
      suspectInterstitial: false,
      via: "api.microlink.io metadata",
      // A handful of tags rebuilt from a metadata object, not the document.
      // Byte and node counts from it would describe this reconstruction.
      byteFaithful: false,
    };
  }

  return {
    finalUrl: target.url,
    source: "",
    doc: null,
    suspectInterstitial: false,
    via: "unavailable",
    byteFaithful: false,
  };
}

/** Build a minimal, honest HTML document from metadata fields. */
function synthesizeFromMeta(data: Record<string, unknown>): string {
  const pick = (k: string): string =>
    typeof data[k] === "string" ? (data[k] as string) : "";
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const tags: string[] = [];
  if (pick("title")) tags.push(`<title>${esc(pick("title"))}</title>`);
  if (pick("description"))
    tags.push(`<meta name="description" content="${esc(pick("description"))}">`);
  const image = (data.image as { url?: string } | undefined)?.url;
  if (image) tags.push(`<meta property="og:image" content="${esc(image)}">`);
  if (pick("author")) tags.push(`<meta name="author" content="${esc(pick("author"))}">`);
  if (pick("lang")) tags.push(`<html lang="${esc(pick("lang"))}">`);
  return `<!doctype html><html><head>${tags.join("")}</head><body></body></html>`;
}

/**
 * Response headers for the target.
 *
 * The header source returns the raw status line and header block of every hop,
 * as text. We parse it here so checks work with a normal header map, and keep
 * the hop list because the redirect check needs it.
 */
export async function fetchHeaders(
  net: NetClient,
  target: Target
): Promise<HeaderSnapshot> {
  const url = `https://api.hackertarget.com/httpheaders/?q=${encodeURIComponent(target.host)}`;
  const res = await net.text(url, {
    timeoutMs: 20_000,
    cacheKey: `headers:${target.host}`,
  });

  if (!res.ok) {
    return {
      status: 0,
      headers: {},
      chain: [],
      finalUrl: target.url,
      via: "unavailable",
    };
  }

  const parsed = parseRawHttp(res.text);
  return { ...parsed, via: "api.hackertarget.com", challenge: isEdgeRefusal(parsed) };
}

/**
 * Whether the header block describes an edge refusing the proxy rather than the
 * site's own response.
 *
 * The header source fetches the target from its own address. When that address
 * is refused, it prints the refusal verbatim and hands it back with a 200 of its
 * own, so nothing upstream can tell the two apart. A live scan of example.com
 * did exactly this: the proxy's fetch hit Cloudflare's managed challenge and the
 * report graded the challenge page's header set as the site's policy, producing
 * "6 of 8 protective headers are missing, Grade F" for a site that serves
 * HSTS and a full CSP to a normal visitor.
 *
 * The signature is a 4xx or 5xx status from an edge, carrying an HTML body. A
 * real page does not answer its own homepage with one of those, and a site that
 * genuinely blocks a region or a bot still is not describing its visitor-facing
 * policy in that response. Either way the headers are not the page's.
 */
function isEdgeRefusal(parsed: { status: number; headers: Record<string, string[]> }): boolean {
  if (parsed.status < 400) return false;
  const contentType = parsed.headers["content-type"]?.[0] ?? "";
  if (contentType && !/text\/html|application\/xhtml/i.test(contentType)) return false;
  const edgeHeaders = ["cf-ray", "x-akamai-request-id", "x-sucuri-id", "x-iinfo", "x-cdn"];
  const hasEdgeHeader = edgeHeaders.some((name) => parsed.headers[name] !== undefined);
  const server = (parsed.headers["server"]?.[0] ?? "").toLowerCase();
  const edgeServer = /cloudflare|akamai|sucuri|imperva|incapsula|fastly|cloudfront/.test(server);
  return hasEdgeHeader || edgeServer;
}

/**
 * Parse one or more concatenated HTTP responses, as returned by a proxy that
 * prints the status line and headers verbatim.
 *
 * Only the final response's headers are returned. Concatenating every hop into
 * one map was a real defect: a Set-Cookie from the first hop appeared as though
 * the final response had set it, and a CSP sent only on the redirect was graded
 * as the policy protecting the page. Each hop's headers belong to that hop, and
 * the only hop that describes the page is the last one.
 */
export function parseRawHttp(raw: string): Omit<HeaderSnapshot, "via"> {
  const lines = raw.replace(/\r/g, "").split("\n");
  const hops: Array<{ status: number; location?: string; headers: Record<string, string[]> }> =
    [];
  let current: (typeof hops)[number] | null = null;

  for (const line of lines) {
    const statusMatch = /^HTTP\/[\d.]+ (\d{3})/.exec(line);
    if (statusMatch) {
      if (current) hops.push(current);
      current = { status: Number(statusMatch[1]), headers: {} };
      continue;
    }
    if (!current) continue;
    if (line.trim() === "") continue;
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (!current.headers[name]) current.headers[name] = [];
    current.headers[name].push(value);
    if (name === "location") current.location = value;
  }
  if (current) hops.push(current);

  if (hops.length === 0) {
    return { status: 0, headers: {}, chain: [], finalUrl: "" };
  }

  const last = hops[hops.length - 1];
  return {
    status: last.status,
    headers: last.headers,
    chain: hops.map((h) => ({ status: h.status, location: h.location })),
    finalUrl: last.location ?? "",
  };
}

/** First value for a header, or undefined. Header names are lowercase. */
export function header(
  snapshot: HeaderSnapshot,
  name: string
): string | undefined {
  return snapshot.headers[name.toLowerCase()]?.[0];
}
/** Every value for a header, joined with ", " where the spec allows it. */
export function headerAll(snapshot: HeaderSnapshot, name: string): string[] {
  return snapshot.headers[name.toLowerCase()] ?? [];
}
