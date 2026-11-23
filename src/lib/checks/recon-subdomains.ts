/**
 * Subdomain enumeration from the passive sources a browser can reach.
 *
 * The published methodology is passive first, then active, then permutation.
 * A page can only do the first, and only from indexes that send CORS headers,
 * so this check merges the two keyless passive sources and says plainly that
 * the result is a lower bound:
 *
 *  - `api.subdomain.center` returns a JSON array of hostnames it has collected.
 *    It sends no CORS header, so the request goes through the reader, which
 *    returns the array as text for this check to parse.
 *  - HackerTarget's host search returns `host,address` lines over a plain HTTP
 *    endpoint that does send `Access-Control-Allow-Origin: *`.
 *
 * Neither is a certificate list, which is what the `subdomains` check already
 * reads. That check answers "which names has a publicly trusted certificate
 * named"; this one answers "which names have passive DNS observations of". They
 * overlap and they disagree, and the union is closer to the real surface than
 * either alone.
 *
 * The finding that matters is not the count. It is a name that looks like it
 * was never meant to be public, because a hostname that only appears in passive
 * DNS is often a host that nobody wrote down.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";

export type ReconSubdomainsData = {
  /** Every hostname seen across both passive sources, sorted. */
  hostnames: string[];
  /** Hosts whose name suggests they were meant to be internal. */
  sensitive: string[];
  /** How many each source contributed before deduplication. */
  fromCenter: number;
  fromHackerTarget: number;
  /** Which sources answered, so a partial answer is not read as full. */
  sourcesAnswered: string[];
  /** Hostnames that resolved to an address in the host-search answer. */
  withAddress: Array<{ host: string; address: string }>;
};

/** Names that suggest a host was never meant to be reachable from the internet. */
const SENSITIVE_NAME =
  /(^|\.)(dev|staging|stage|test|uat|qa|internal|intranet|admin|jenkins|gitlab|grafana|kibana|vpn|phpmyadmin|jira|confluence|ldap|sso|corp|db|database|redis|mongo)([.-]|$)/i;

/** Keep the payload a sane size for rendering; the totals stay exact. */
const DISPLAY_CAP = 150;

/** How many hostnames the headline may count before saying "at least". */
const HEADLINE_CAP = 1000;

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * A hostname, cleaned, or null.
 *
 * Passive DNS answers carry a mix of real names, wildcards and bare addresses.
 * A wildcard is not a name that resolves, a bare address is not a name, and a
 * single label cannot resolve from the public internet, so all three are
 * dropped before anything is counted.
 */
function normaliseHost(raw: string, domain: string): string | null {
  const host = raw.trim().toLowerCase().replace(/\.$/, "");
  if (!host) return null;
  if (host.startsWith("*.")) return null;
  if (host.startsWith(".") || host.includes("..") || /\s/.test(host)) return null;
  if (!host.includes(".")) return null;
  if (IPV4.test(host) || host.includes(":")) return null;
  // Keep only names that belong to the domain being scanned, so a shared index
  // cannot slip an unrelated host into this site's surface.
  if (host !== domain && !host.endsWith("." + domain)) return null;
  return host;
}

/** Parse the reader's text for the `subdomain.center` array. */
function parseCenter(text: string): string[] | null {
  // The reader wraps the body after a "Markdown Content:" line. Find the first
  // `[` so a heading or an error line above the array does not defeat parsing,
  // and fall back to a line-per-name read if the array is not on one line.
  const start = text.indexOf("[");
  if (start >= 0) {
    try {
      const parsed: unknown = JSON.parse(text.slice(start));
      if (Array.isArray(parsed)) {
        return parsed.filter((item): item is string => typeof item === "string");
      }
    } catch {
      // Fall through to the line reader.
    }
  }
  // A truncated or re-serialized answer: one quoted name per line, without the
  // brackets, is still readable.
  const names = text
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/^"|",?$/g, ""))
    .filter((line) => line.includes(".") && !line.startsWith("{"));
  return names.length > 0 ? names : null;
}

/** Parse HackerTarget's `host,address` CSV, one pair per line. */
function parseHostSearch(text: string): Array<{ host: string; address: string }> {
  if (/error/i.test(text) && !text.includes(",")) return [];
  const rows: Array<{ host: string; address: string }> = [];
  for (const line of text.split(/\r?\n/)) {
    const comma = line.indexOf(",");
    if (comma <= 0) continue;
    const host = line.slice(0, comma).trim();
    const address = line.slice(comma + 1).trim();
    if (host && address && !/\s/.test(host)) rows.push({ host, address });
  }
  return rows;
}

export const reconSubdomains: CheckDefinition = {
  id: "recon-subdomains",
  title: "Subdomain enumeration",
  question: "Which hostnames have passive DNS recorded under this domain?",
  group: "recon",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    // Two sources, asked at once. The center call goes through the reader
    // because its endpoint sends no CORS header; the host search is fetched
    // directly because it does.
    const [centerRes, hostSearchRes] = await Promise.all([
      ctx.net.text(
        `https://r.jina.ai/https://api.subdomain.center/?domain=${encodeURIComponent(domain)}`,
        { timeoutMs: 40_000, retry: true, cacheKey: `sdcenter:${domain}` }
      ),
      ctx.net.text(
        `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
        { timeoutMs: 20_000, cacheKey: `ht-hostsearch:${domain}` }
      ),
    ]);

    const sourcesAnswered: string[] = [];
    const hostSet = new Set<string>();
    const withAddress: Array<{ host: string; address: string }> = [];
    let fromCenter = 0;
    let fromHackerTarget = 0;

    if (centerRes.ok) {
      const names = parseCenter(centerRes.text);
      if (names) {
        sourcesAnswered.push("subdomain.center");
        for (const raw of names) {
          const host = normaliseHost(raw, domain);
          if (!host) continue;
          fromCenter++;
          hostSet.add(host);
        }
      }
    }

    if (hostSearchRes.ok) {
      const rows = parseHostSearch(hostSearchRes.text);
      // HackerTarget answers "error check your search parameter" with a 200, so
      // an empty parse means it answered nothing, not that the domain is empty.
      if (rows.length > 0) {
        sourcesAnswered.push("HackerTarget host search");
        for (const row of rows) {
          const host = normaliseHost(row.host, domain);
          if (!host) continue;
          fromHackerTarget++;
          hostSet.add(host);
          if (!withAddress.some((entry) => entry.host === host)) {
            withAddress.push({ host, address: row.address });
          }
        }
      }
    }

    if (sourcesAnswered.length === 0) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "Neither passive source answered, so no hostnames could be listed.",
        findings: [],
        data: {
          hostnames: [],
          sensitive: [],
          fromCenter: 0,
          fromHackerTarget: 0,
          sourcesAnswered: [],
          withAddress: [],
        } satisfies ReconSubdomainsData,
        ms: Math.round(performance.now() - started),
        source: "api.subdomain.center and HackerTarget host search",
        note: [
          centerRes.ok ? "" : describeFailure(centerRes, "subdomain.center"),
          hostSearchRes.ok ? "" : describeFailure(hostSearchRes, "HackerTarget"),
        ]
          .filter(Boolean)
          .join(" "),
      };
    }

    const hostnames = [...hostSet].sort();
    const sensitive = hostnames.filter((host) => SENSITIVE_NAME.test(host));

    const findings: Finding[] = [];

    if (sensitive.length > 0) {
      findings.push({
        id: "recon-subdomains-sensitive",
        title: `${sensitive.length} hostname${sensitive.length === 1 ? " looks" : "s look"} internal but ${sensitive.length === 1 ? "is" : "are"} public`,
        detail: `Passive DNS has recorded ${sensitive.length} hostname${sensitive.length === 1 ? "" : "s"} under ${domain} whose name suggests it was meant to be internal: ${sensitive.slice(0, 8).join(", ")}${sensitive.length > 8 ? " and others" : ""}. A record here means the name has resolved from the public internet at some point.`,
        severity: "high",
        remediation:
          "Confirm each host is meant to be public. If it is not, remove the DNS record and reach it over a VPN or an internal-only name. A passive DNS record does not prove the service is exposed now, but it does show the host existed on the public internet and is worth probing.",
        reference: {
          label: "CISA: Known Exploited Vulnerabilities catalog",
          url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        },
        evidence: sensitive.slice(0, 12).map((host) => ({
          label: "Host",
          value: host,
          tone: "bad" as const,
        })),
      });
    }

    if (hostnames.length >= 100) {
      findings.push({
        id: "recon-subdomains-large",
        title: `${hostnames.length} hostnames recorded in passive DNS`,
        detail: `Passive sources have seen ${hostnames.length} distinct hostnames under ${domain}. Each is a separate surface with its own certificate, patch level and access rules, and a surface this wide is hard to keep patched uniformly.`,
        severity: "info",
      });
    }

    const serious = findings.some((f) => f.severity === "high" || f.severity === "critical");
    const status: CheckResult["status"] = serious ? "fail" : findings.length > 0 ? "info" : "pass";

    // The reader service truncates a very long answer, and subdomain.center
    // returns exactly 500 for a domain the size of example.com. A capped list
    // read as an exact total would understate the surface, so the count is
    // labelled as a floor once it reaches the cap the reader is known to apply.
    const atLeast = hostnames.length >= HEADLINE_CAP ? "at least " : "";
    const headline =
      hostnames.length === 0
        ? `Passive DNS recorded no hostname under ${domain} from ${sourcesAnswered.join(" and ")}.`
        : `${atLeast}${hostnames.length} hostname${hostnames.length === 1 ? "" : "s"} recorded under ${domain}: ${atLeast}${fromCenter} from subdomain.center, ${fromHackerTarget} from HackerTarget${sensitive.length > 0 ? `, ${sensitive.length} of them looking internal` : ""}.`;

    const partial = sourcesAnswered.length < 2;
    const notes = [
      "This is passive DNS: a record of names that have resolved at some point, not an inventory of what resolves now. It is a lower bound.",
      "A certificate list and a passive DNS list disagree, so the subdomain surface check on this same scan reads a different source and may report a different set.",
    ];
    if (partial) {
      notes.push(
        `Only ${sourcesAnswered.join(" and ")} answered, so the real surface is likely wider than this list.`
      );
    }

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        hostnames: hostnames.slice(0, DISPLAY_CAP),
        sensitive,
        fromCenter,
        fromHackerTarget,
        sourcesAnswered,
        withAddress: withAddress.slice(0, DISPLAY_CAP),
      } satisfies ReconSubdomainsData,
      ms: Math.round(performance.now() - started),
      source: "api.subdomain.center and HackerTarget host search",
      note: notes.join(" "),
    };
  },
};
