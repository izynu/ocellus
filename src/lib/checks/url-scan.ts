/**
 * The URL and address scanners, asked from the browser.
 *
 * Two questions that a person scanning a host usually asks next: "has this URL
 * been seen live, and what did it contact" and "who is this address, and what
 * else has been hosted on it". Both have a keyless answer that a page can read:
 *
 *  - urlscan.io's search index, read through the reader because the endpoint
 *    sends no CORS header. It returns prior scans of the domain with the page's
 *    own title, address, server and country, which is the closest thing to a
 *    live look at the rendered page a static tool can get.
 *  - HackerTarget's reverse DNS and reverse IP lookups, which do send CORS and
 *    answer in plain text. Reverse IP names the other hosts recorded on the same
 *    address, which is the "shared hosting neighbour" view.
 *
 * This is context, not a verdict. A prior urlscan capture is a record of
 * somebody else's request at another moment, and a reverse IP list is what one
 * index knows rather than an inventory. Neither is scored; the check reports
 * what it read and says what it is.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";

export type UrlScanData = {
  /** Address the host resolves to, when reverse DNS named one. */
  ip: string | null;
  reverseNames: string[];
  /** Other hostnames HackerTarget records on the same address. */
  neighbours: string[];
  /** Prior urlscan captures of the domain, most recent first. */
  captures: Array<{
    url: string;
    title: string;
    server: string | null;
    country: string | null;
    time: string | null;
    result: string | null;
  }>;
  captureCount: number;
  /** Which lookups answered, so a partial answer is not read as complete. */
  sourcesAnswered: string[];
};

type UrlscanResult = {
  task?: { url?: string; time?: string };
  page?: { url?: string; title?: string; server?: string; country?: string };
  _id?: string;
};

type UrlscanResponse = { results?: UrlscanResult[]; total?: number };

/** How many captures to keep for display. */
const CAPTURE_CAP = 8;

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Parse urlscan's JSON out of the reader's text wrapper. */
function parseUrlscan(text: string): UrlscanResponse | null {
  const start = text.indexOf("{");
  if (start < 0) return null;
  try {
    const parsed: unknown = JSON.parse(text.slice(start));
    if (parsed && typeof parsed === "object" && Array.isArray((parsed as UrlscanResponse).results)) {
      return parsed as UrlscanResponse;
    }
  } catch {
    // Fall through: a body that does not parse is treated as no answer.
  }
  return null;
}

function nonEmpty(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

export const urlScan: CheckDefinition = {
  id: "url-scan",
  title: "URL and address lookups",
  question: "Who is this address, what else shares it, and what has a public scanner seen at this URL?",
  group: "recon",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;
    const host = ctx.target.host;

    // The A record is resolved before anything else, because the reverse
    // lookups are keyed by address. The urlscan search does not depend on it,
    // so it starts alongside the DNS call rather than after it.
    const [aRes, scanRes] = await Promise.all([
      ctx.dns.query(host, "A"),
      ctx.net.text(
        `https://r.jina.ai/https://urlscan.io/api/v1/search/?q=domain%3A${encodeURIComponent(domain)}&size=20`,
        { timeoutMs: 35_000, cacheKey: `urlscan:${domain}` }
      ),
    ]);

    const sourcesAnswered: string[] = [];
    const ip = aRes.answers.find((r) => r.type === 1)?.data ?? null;

    // Reverse DNS is a PTR lookup, so it is asked with the address, not the
    // hostname. Asking with the hostname returned the A record's targets as
    // "0.example.com,198.54.14.52,..." and displayed them as reverse names,
    // which is a different fact reported under the wrong label.
    let reverseNames: string[] = [];
    if (ip && IPV4.test(ip)) {
      const ptr = await ctx.net.text(
        `https://api.hackertarget.com/reversedns/?q=${encodeURIComponent(ip)}`,
        { timeoutMs: 20_000, cacheKey: `ht-reversedns:${ip}` }
      );
      if (ptr.ok && !/no PTR record|error|API count exceeded/i.test(ptr.text)) {
        reverseNames = ptr.text
          .split(/\r?\n/)
          .map((line) => line.trim().toLowerCase())
          .filter((line) => Boolean(line) && line.includes(".") && !IPV4.test(line));
        sourcesAnswered.push("reverse DNS");
      }
    }

    let neighbours: string[] = [];
    if (ip && IPV4.test(ip)) {
      const rev = await ctx.net.text(
        `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`,
        { timeoutMs: 25_000, cacheKey: `ht-reverseip:${ip}` }
      );
      if (rev.ok && !/no DNS results found|error|API count exceeded/i.test(rev.text)) {
        const names = rev.text
          .split(/\r?\n/)
          .map((line) => line.trim().toLowerCase())
          .filter((line) => Boolean(line) && line.includes(".") && !IPV4.test(line));
        neighbours = [...new Set(names)].sort();
        sourcesAnswered.push("reverse IP");
      }
    }

    const scanBody = scanRes.ok ? parseUrlscan(scanRes.text) : null;
    const results = scanBody?.results ?? [];
    if (scanBody) sourcesAnswered.push("urlscan.io");

    const captures = results
      .slice(0, CAPTURE_CAP)
      .map((entry) => ({
        url: nonEmpty(entry.page?.url) ?? nonEmpty(entry.task?.url) ?? "",
        title: nonEmpty(entry.page?.title) ?? "(no title)",
        server: nonEmpty(entry.page?.server),
        country: nonEmpty(entry.page?.country),
        time: nonEmpty(entry.task?.time),
        result: nonEmpty(entry._id) ? `https://urlscan.io/result/${entry._id}/` : null,
      }))
      .filter((entry) => entry.url);

    if (sourcesAnswered.length === 0) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "None of the address or URL scanners answered, so nothing could be reported.",
        findings: [],
        data: {
          ip,
          reverseNames,
          neighbours,
          captures,
          captureCount: 0,
          sourcesAnswered: [],
        } satisfies UrlScanData,
        ms: Math.round(performance.now() - started),
        source: "urlscan.io, HackerTarget reverse DNS and reverse IP",
        note: [
          aRes.failed
            ? "The DNS resolver did not answer, so no address could be read and the reverse lookups were skipped."
            : "",
          scanRes.ok ? "" : describeFailure(scanRes, "urlscan.io"),
        ]
          .filter(Boolean)
          .join(" "),
      };
    }

    const findings: Finding[] = [];

    // A shared address is not a defect, so it is reported as context and never
    // as a finding. The count is what matters: a handful of neighbours is a
    // small box, a long list is a CDN or a busy host, and neither is a problem
    // in itself.
    if (neighbours.length > 0 && neighbours.length <= 3) {
      findings.push({
        id: "url-scan-neighbours",
        title: `The address is shared with ${neighbours.length} other hostname${neighbours.length === 1 ? "" : "s"}`,
        detail: `${ip} also carries ${neighbours.join(", ")}. On a small address rather than a CDN edge, a compromised neighbour can sometimes be used against the others, which is why the names are listed.`,
        severity: "info",
        evidence: neighbours.slice(0, 10).map((name) => ({ label: "Host", value: name })),
      });
    }

    const headline =
      ip === null
        ? `No address was resolved, so only the URL scanner could be read${results.length > 0 ? `: ${results.length} prior capture${results.length === 1 ? "" : "s"} of ${domain}` : ""}.`
        : `${ip}${neighbours.length > 0 ? ` shares its address with ${neighbours.length} other hostname${neighbours.length === 1 ? "" : "s"}` : " is not shared with any hostname this index knows"}${results.length > 0 ? `, and ${results.length} public scan${results.length === 1 ? "" : "s"} of ${domain} exist` : ""}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status: "info",
      headline,
      findings,
      data: {
        ip,
        reverseNames: reverseNames.slice(0, 10),
        neighbours: neighbours.slice(0, 50),
        captures,
        captureCount: results.length,
        sourcesAnswered,
      } satisfies UrlScanData,
      ms: Math.round(performance.now() - started),
      source: "urlscan.io, HackerTarget reverse DNS and reverse IP",
      note: "A urlscan capture is another party's request at another moment, and a reverse IP list is what one index knows rather than a live inventory. Neither is a verdict, so this check is not scored.",
    };
  },
};
