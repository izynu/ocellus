/**
 * The URL scanner: one function that answers "is this URL safe to open".
 *
 * It runs five questions at once, all from the browser, and returns one result
 * the page can render. Nothing is proxied through this site.
 *
 *  1. Google Safe Browsing, through the keyless transparency report. The body is
 *     an XSSI-prefixed JSON tuple; a reply with no per-URL verdict is "no answer",
 *     never "clean".
 *  2. OpenPhish, a live plain-text feed, matched by hostname.
 *  3. The page itself, through the reader, for the final URL, server, title and
 *     link count, because most sites send no cross-origin header.
 *
 * A feed that did not answer is reported as "unknown" and is never folded into
 * a clean verdict, for the same reason the scan never treats a failed source as
 * a pass.
 */

const SAFE_BROWSING =
  "https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status";
const OPENPHISH = "https://openphish.com/feed.txt";
const READER = "https://r.jina.ai/";

export type FeedVerdict = "clean" | "listed" | "unknown";

export type FeedAnswer = {
  verdict: FeedVerdict;
  /** A sentence stating what the source said, or why it said nothing. */
  detail: string;
};

export type SanitisedResult = {
  input: string;
  host: string;
  finalUrl: string;
  server: string;
  status: string;
  title: string;
  redirects: string[];
  links: number;
  reachable: boolean;
  via: string;
  headline: string;
  safeBrowsing: FeedAnswer;
  openPhish: FeedAnswer;
};

/** Reduce whatever was typed to an absolute https URL. */
export function normaliseUrl(raw: string): { url: string; host: string } {
  const value = raw.trim();
  if (!value) throw new Error("Enter a URL or hostname to check.");
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : "https://" + value;
  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    throw new Error("That is not a usable URL. Try a form like example.com or https://example.com/page.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http and https URLs can be checked.");
  }
  return { url: parsed.toString(), host: parsed.hostname.toLowerCase() };
}

/**
 * Ask Google for a per-URL verdict.
 *
 * The body begins with `)]}'` and is then a JSON array of tuples of the form
 * `["sb.ssr", name, <malware>, <phishing>, ...]`. A tuple whose boolean slots
 * are absent is not an answer and is reported as unknown.
 */
export async function checkSafeBrowsing(url: string): Promise<FeedAnswer> {
  let text: string;
  try {
    const res = await fetch(`${SAFE_BROWSING}?site=${encodeURIComponent(url)}`, {
      credentials: "omit",
      mode: "cors",
    });
    if (!res.ok) {
      return { verdict: "unknown", detail: `Google answered ${res.status}, so no verdict was read.` };
    }
    text = await res.text();
  } catch {
    return {
      verdict: "unknown",
      detail: "Google's report could not be read from the browser. That is a gap, not a clean result.",
    };
  }

  const start = text.indexOf("[");
  if (start < 0) {
    return { verdict: "unknown", detail: "Google returned a body that was not a verdict." };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.slice(start));
  } catch {
    return { verdict: "unknown", detail: "Google's reply could not be parsed into a verdict." };
  }
  const tuple = Array.isArray(parsed) && Array.isArray(parsed[0]) ? (parsed[0] as unknown[]) : null;
  if (!tuple) {
    return { verdict: "unknown", detail: "Google's reply carried no status tuple." };
  }
  const malware = tuple[2] === true;
  const phishing = tuple[3] === true;
  if (malware || phishing) {
    const kinds = [malware ? "malware" : "", phishing ? "phishing" : ""].filter(Boolean).join(" and ");
    return { verdict: "listed", detail: `Google flags this URL for ${kinds}.` };
  }
  if (tuple.length < 4) {
    return { verdict: "unknown", detail: "Google's reply was too short to carry a verdict." };
  }
  return { verdict: "clean", detail: "Google holds no malware or phishing flag for this URL." };
}

/** Match a host against the live OpenPhish feed. */
export async function checkOpenPhish(host: string): Promise<FeedAnswer> {
  let text: string;
  try {
    const res = await fetch(OPENPHISH, { credentials: "omit", mode: "cors" });
    if (!res.ok) {
      return { verdict: "unknown", detail: `The OpenPhish feed answered ${res.status}.` };
    }
    text = await res.text();
  } catch {
    return {
      verdict: "unknown",
      detail: "The OpenPhish feed could not be read from the browser. That is a gap, not a clean result.",
    };
  }
  const listed = text.split(/\r?\n/).some((line) => {
    try {
      return new URL(line.trim()).hostname.toLowerCase() === host;
    } catch {
      return false;
    }
  });
  return listed
    ? { verdict: "listed", detail: "This host serves a URL on the live OpenPhish phishing feed." }
    : { verdict: "clean", detail: "This host is not on the current OpenPhish feed." };
}

/** Read the page through the reader for its final URL, server and title. */
export async function fetchPage(url: string): Promise<{
  ok: boolean;
  finalUrl: string;
  server: string;
  status: string;
  title: string;
  links: number;
  via: string;
}> {
  const res = await fetch(READER + url, {
    headers: { "x-respond-with": "html", "x-retain-images": "none", "x-no-cache": "true" },
    credentials: "omit",
    mode: "cors",
  }).catch(() => null);

  if (!res || !res.ok) {
    return { ok: false, finalUrl: "", server: "", status: "", title: "", links: 0, via: "unavailable" };
  }
  const html = await res.text();
  let doc: Document | null = null;
  try {
    doc = new DOMParser().parseFromString(html, "text/html");
  } catch {
    doc = null;
  }
  const title = doc?.querySelector("title")?.textContent?.trim() ?? "";
  const head = html.slice(0, 400);
  const server = head.match(/server:\s*([^\n\]]+)/i)?.[1]?.trim() ?? "";
  const finalUrl = head.match(/Final URL:\s*(\S+)/i)?.[1] ?? url;
  const status = head.match(/Status Code:\s*(\d{3})/i)?.[1] ?? "";
  const links = doc ? doc.querySelectorAll("a[href]").length : 0;
  return { ok: true, finalUrl, server, status, title, links, via: "r.jina.ai reader" };
}

/** The whole check, in one call. */
export async function scanUrl(raw: string): Promise<SanitisedResult> {
  const { url, host } = normaliseUrl(raw);

  const [safeBrowsing, openPhish, page] = await Promise.all([
    checkSafeBrowsing(url),
    checkOpenPhish(host),
    fetchPage(url),
  ]);

  const listed = safeBrowsing.verdict === "listed" || openPhish.verdict === "listed";
  const headline = listed
    ? `${host} is listed by at least one reputation feed. Treat it as unsafe until you have read the listing.`
    : safeBrowsing.verdict === "clean" && openPhish.verdict === "clean"
      ? `${host} is not listed by either feed that answered. That is not a guarantee it is safe.`
      : `${host} could not be fully checked: one or more feeds gave no answer.`;

  return {
    input: raw,
    host,
    finalUrl: page.ok ? page.finalUrl : url,
    server: page.server,
    status: page.status,
    title: page.title,
    redirects: [],
    links: page.links,
    reachable: page.ok,
    via: page.via,
    headline,
    safeBrowsing,
    openPhish,
  };
}
