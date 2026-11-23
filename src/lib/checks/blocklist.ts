/**
 * Whether public filtering resolvers refuse to answer for this domain.
 *
 * A malware blocklist is a different kind of evidence from a threat feed. OTX
 * tells you that somebody wrote about the domain; a filtering resolver tells you
 * that a vendor's classifier decided the domain should not resolve at all. The
 * second is a decision, made on traffic the vendor observed, and it is the
 * closest thing to a maliciousness verdict that a browser can read without an
 * API key.
 *
 * The method is to ask a resolver that filters and read the answer. Cloudflare's
 * security resolver answers a blocked name with a sinkhole address (0.0.0.0 or
 * ::) and appends an extended DNS error of code 16, "Censored". A clean name
 * resolves normally. Both cases are visible in the JSON form of DNS over HTTPS,
 * which is why this check asks for `application/dns-json` specifically: the same
 * endpoint without that Accept header answers 405 and sends no CORS header.
 *
 * Two things this cannot tell you. It cannot distinguish a block for malware
 * from a block for adult content, because the EDE code is the same. And it says
 * nothing about the domain's real reputation: a resolver's classifier is a
 * vendor's opinion, published without a reason, and it is wrong in both
 * directions. So a block is reported as a signal to investigate, never as proof.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";

type DohResponse = {
  Status?: number;
  Answer?: Array<{ name?: string; type?: number; TTL?: number; data?: string }>;
  Comment?: string[];
  Authority?: Array<{ name?: string; type?: number; data?: string }>;
};

/** A resolver that is configured to filter, and how to read its verdict. */
type FilterResolver = {
  name: string;
  url: (domain: string) => string;
  /** What the resolver's vendor says it filters. */
  filters: string;
};

const RESOLVERS: FilterResolver[] = [
  {
    name: "Cloudflare 1.1.1.2",
    url: (domain) =>
      `https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
    filters: "malware and phishing",
  },
];

export type BlocklistData = {
  /** One row per resolver that answered, with what it said. */
  resolvers: Array<{
    name: string;
    filters: string;
    /** "blocked" when the answer was a sinkhole or carried a censored EDE. */
    verdict: "blocked" | "resolved" | "no-answer";
    addresses: string[];
    /** Extended DNS errors the resolver attached, verbatim. */
    comments: string[];
  }>;
  /** True when at least one resolver refused to resolve the name. */
  blocked: boolean;
};

/**
 * The addresses a filtering resolver substitutes for a name it refuses. Some
 * vendors use a loopback range, some use a single wildcard address; all of them
 * are addresses no real origin serves from.
 */
const SINKHOLES = new Set([
  "0.0.0.0",
  "::",
  "127.0.0.1",
  "::1",
  "0.0.0.0.",
]);

function isSinkhole(address: string): boolean {
  return SINKHOLES.has(address.trim());
}

/** EDE code 16 is "Censored", which is how a filtered answer identifies itself. */
function isCensored(comments: string[]): boolean {
  return comments.some((comment) => /EDE\(16\)/i.test(comment) || /censored/i.test(comment));
}

export const blocklist: CheckDefinition = {
  id: "blocklist",
  title: "Filtering resolvers",
  question: "Do resolvers that filter malware and phishing refuse to answer for this domain?",
  group: "threat",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    const answers = await Promise.all(
      RESOLVERS.map(async (resolver) => {
        // The Accept header is not optional. The JSON form of DNS over HTTPS is
        // a separate representation, and this endpoint sends no CORS header on
        // the wire-format response, so a browser cannot read the default one.
        //
        // The timeout is generous because the first request to this host pays
        // for a cold TLS handshake and a DoH connection setup, which was
        // measured at 21 seconds in Chromium while a warm request took under
        // 100 ms. A tight timeout reports a working resolver as unreachable.
        const res = await ctx.net.json<DohResponse>(resolver.url(domain), {
          timeoutMs: 30_000,
          retry: true,
          headers: { Accept: "application/dns-json" },
          cacheKey: `blocklist:${resolver.name}:${domain}`,
        });
        return { resolver, res };
      })
    );

    const failed = answers.filter(({ res }) => !res.ok);
    if (failed.length === answers.length) {
      const first = failed[0].res;
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: first.ok
          ? "The filtering resolver answered with a body that is not a DNS response."
          : describeFailure(first, "The filtering resolver"),
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Cloudflare security resolver, DNS over HTTPS",
        note: "A resolver that cannot be reached says nothing about the domain. This is a gap in the check, not a clean result.",
      };
    }

    const rows: BlocklistData["resolvers"] = [];

    for (const { resolver, res } of answers) {
      if (!res.ok || !res.json) continue;

      // A DoH answer carries its own status. SERVFAIL/REFUSED (2/5) are not
      // "no record": the resolver failed to answer, and grading that as a clean
      // resolution is the exact false pass this tool exists to avoid. Only
      // NOERROR (0) and NXDOMAIN (3) describe a real outcome.
      const dnsStatus = typeof res.json.Status === "number" ? res.json.Status : -1;
      if (dnsStatus !== 0 && dnsStatus !== 3) {
        rows.push({
          name: resolver.name,
          filters: resolver.filters,
          verdict: "no-answer",
          addresses: [],
          comments: [`the resolver returned DNS status ${dnsStatus}, not an answer`],
        });
        continue;
      }

      const addresses = (res.json.Answer ?? [])
        .filter((record) => record.type === 1 || record.type === 28)
        .map((record) => record.data ?? "")
        .filter(Boolean);
      const comments = res.json.Comment ?? [];

      const verdict: BlocklistData["resolvers"][number]["verdict"] =
        addresses.some(isSinkhole) || isCensored(comments)
          ? "blocked"
          : addresses.length > 0
            ? "resolved"
            : "no-answer";

      rows.push({ name: resolver.name, filters: resolver.filters, verdict, addresses, comments });
    }

    const blocked = rows.filter((row) => row.verdict === "blocked");
    const findings: Finding[] = [];

    if (blocked.length > 0) {
      findings.push({
        id: "blocklist-refused",
        title: "A filtering resolver refuses to resolve this domain",
        detail: `${blocked
          .map((row) => `${row.name} answered ${row.addresses.join(", ") || "with no address"}`)
          .join("; ")}. That resolver filters ${blocked[0].filters}, and it decided the name should not resolve. The answer is a sinkhole address rather than the site's real one, so a visitor using that resolver cannot reach the site at all. A block is a vendor classifier's decision and it is not always right, but it is the strongest maliciousness signal available without an API key, and it is worth finding out why.`,
        severity: "high",
        remediation:
          "Look the domain up in the resolver vendor's blocklist feedback form, and in VirusTotal or URLhaus, to see what triggered it. If the domain is yours and the block is wrong, submit a false-positive report to the vendor. Until it is cleared, anyone on that resolver cannot reach you.",
        reference: {
          label: "RFC 8914, extended DNS errors",
          url: "https://datatracker.ietf.org/doc/html/rfc8914",
        },
        evidence: blocked.map((row) => ({
          label: row.name,
          value: row.addresses.join(", ") || "no address returned",
          tone: "bad" as const,
          detail: row.comments.length > 0 ? row.comments.join("; ") : undefined,
        })),
      });
    }

    // A resolver that failed to answer is not a resolver that approved the
    // domain. When none of them produced a real verdict, the check is
    // unavailable rather than a pass.
    const answered = rows.filter((row) => row.verdict !== "no-answer");
    const status: CheckResult["status"] =
      blocked.length > 0 ? "warn" : answered.length === 0 ? "unavailable" : "pass";

    const headline =
      blocked.length > 0
        ? `${blocked.length} of ${rows.length} filtering resolver${rows.length === 1 ? "" : "s"} refused to resolve ${domain}.`
        : answered.length === 0
          ? "No filtering resolver returned a usable verdict, so nothing can be said about whether this domain is blocked."
          : `${answered.length === 1 ? "The filtering resolver" : "Every filtering resolver"} answered normally for ${domain}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: { resolvers: rows, blocked: blocked.length > 0 } satisfies BlocklistData,
      ms: Math.round(performance.now() - started),
      source: "Cloudflare security resolver, DNS over HTTPS",
      note: "A resolver's block is a vendor's opinion, published without a reason. It cannot distinguish malware from adult content, because both use the same extended error code. A clean answer here means one vendor has no objection, not that the domain is trustworthy.",
    };
  },
};
