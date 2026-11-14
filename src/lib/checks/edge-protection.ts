/**
 * Edge protection: which CDN, web application firewall or reverse proxy is in
 * front of the origin, judged from response headers alone.
 *
 * The headers are the right source because they are the only evidence a static
 * page can read without touching the origin again. Every product here stamps
 * its own request identifiers or cache state onto the response as it passes
 * through, and those stamps survive to the client. Each detection keeps the
 * literal header and value that produced it, so the claim can be checked
 * against the response rather than taken on trust.
 *
 * What a header proves is narrow: that the edge handled this response. It does
 * not prove a WAF rule set is switched on, that the rules are tuned, or that
 * the origin refuses connections from anywhere else. The check reports presence
 * and says so, because a report that reads "protected" from a `cf-ray` header
 * would be claiming more than the data supports.
 *
 * No network call is made here. The snapshot is shared with the header checks
 * and is already fetched once per scan.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import type { HeaderSnapshot } from "../types";
import { header, headerAll } from "../net/document";

export type EdgeCategory = "CDN" | "WAF" | "Reverse proxy" | "Hosting edge";

export type EdgeEvidence = {
  /** The literal header name, lowercased as the snapshot stores it. */
  header: string;
  /** The literal value that matched. */
  value: string;
};

export type EdgeDetection = {
  name: string;
  category: EdgeCategory;
  evidence: EdgeEvidence[];
};

export type EdgeProtectionData = {
  detections: EdgeDetection[];
  /** The cache-state header for this response, when one was sent. */
  cache: { header: string; value: string } | null;
  /** Every `via` value, which names the proxies in the path. */
  via: string[];
  status: number;
};

type Probe = {
  header: string;
  /** Required substring or pattern; absence means presence alone is enough. */
  match?: RegExp;
};

type Signature = {
  name: string;
  category: EdgeCategory;
  probes: Probe[];
};

/**
 * One signature per product. A product matches when any one of its probes
 * matches, and the evidence lists every probe that fired, because two
 * independent stamps are stronger than one.
 */
const SIGNATURES: Signature[] = [
  {
    name: "Cloudflare",
    category: "CDN",
    probes: [
      { header: "cf-ray" },
      { header: "server", match: /cloudflare/i },
      { header: "cf-cache-status" },
    ],
  },
  {
    name: "Akamai",
    category: "CDN",
    probes: [
      { header: "x-akamai-transformed" },
      { header: "akamai-grn" },
      { header: "x-akamai-request-id" },
    ],
  },
  {
    name: "Fastly",
    category: "CDN",
    probes: [
      { header: "x-fastly-request-id" },
      { header: "x-served-by", match: /cache-/i },
      { header: "x-cache", match: /fastly/i },
    ],
  },
  {
    name: "Amazon CloudFront",
    category: "CDN",
    probes: [{ header: "x-amz-cf-id" }, { header: "x-amz-cf-pop" }],
  },
  {
    name: "Sucuri",
    category: "WAF",
    probes: [{ header: "x-sucuri-id" }, { header: "x-sucuri-cache" }],
  },
  {
    name: "Imperva",
    category: "WAF",
    probes: [{ header: "x-iinfo" }, { header: "x-cdn", match: /incapsula/i }],
  },
  {
    name: "Azure Front Door",
    category: "CDN",
    probes: [{ header: "x-azure-ref" }, { header: "x-fd-int-roxy-purgeid" }],
  },
  {
    name: "Vercel",
    category: "Hosting edge",
    probes: [{ header: "x-vercel-id" }, { header: "x-vercel-cache" }],
  },
  {
    name: "Netlify",
    category: "Hosting edge",
    probes: [{ header: "x-nf-request-id" }],
  },
  {
    name: "Bunny",
    category: "CDN",
    probes: [{ header: "server", match: /bunnycdn/i }, { header: "cdn-requestid" }],
  },
  {
    name: "Google Cloud CDN",
    category: "CDN",
    probes: [{ header: "via", match: /1\.1 google/i }, { header: "x-cloud-trace-context" }],
  },
  {
    name: "F5 BIG-IP",
    category: "Reverse proxy",
    probes: [
      { header: "x-wa-info" },
      // The BIG-IP persistence cookie is the only stamp the appliance leaves
      // when the profile is not adding a header of its own.
      { header: "set-cookie", match: /bigipserver/i },
    ],
  },
  {
    name: "Barracuda",
    category: "WAF",
    probes: [{ header: "set-cookie", match: /barra_counter_session/i }],
  },
  {
    name: "AWS WAF",
    category: "WAF",
    probes: [{ header: "x-amzn-waf-action" }],
  },
  {
    // ModSecurity can run without stamping anything, and a 406 or 501 is also
    // what a misconfigured origin returns. Only the product name in the server
    // header is treated as evidence; a block response alone is not.
    name: "ModSecurity",
    category: "WAF",
    probes: [{ header: "server", match: /modsecurity/i }],
  },
];

/** Cache-state headers, in the order worth reporting when more than one exists. */
const CACHE_HEADERS = ["cf-cache-status", "x-cache", "x-vercel-cache"];

const EVIDENCE_LIMIT = 90;

function clip(value: string): string {
  const trimmed = value.trim();
  return trimmed.length > EVIDENCE_LIMIT ? trimmed.slice(0, EVIDENCE_LIMIT - 3) + "..." : trimmed;
}

/**
 * Turn a cache-state header into a phrase. A value the code does not recognise
 * is quoted rather than interpreted, so an unfamiliar token is reported as
 * itself instead of being rounded to a hit or a miss.
 */
/** "Cloudflare", or "Cloudflare and Fastly", or "A, B and C". */
function joinNames(names: string[]): string {
  if (names.length <= 1) return names[0] ?? "";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

function cachePhrase(cache: { header: string; value: string }): string {
  if (/hit/i.test(cache.value)) return "a cache hit reported for this request";
  if (/miss/i.test(cache.value)) return "a cache miss reported for this request";
  return `${cache.header} reporting ${cache.value}`;
}

export const edgeProtection: CheckDefinition = {
  id: "edge-protection",
  title: "Edge protection",
  question: "Which CDN, web application firewall or reverse proxy sits in front of the origin?",
  group: "headers",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const snapshot: HeaderSnapshot = await ctx.headers();

    // The header source is a public proxy, and a scan that never got a status
    // line has no header set to read. Treating that as "no edge" would state a
    // fact about the site from a response the site never sent.
    if (snapshot.via === "unavailable" || snapshot.status === 0) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "Response headers could not be retrieved for this host.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "api.hackertarget.com",
        note: "No response headers were read, so this says nothing about whether a CDN or web application firewall is in front of the origin. The header source rate limits by IP; re-running usually works.",
      };
    }

    const detections: EdgeDetection[] = [];

    for (const signature of SIGNATURES) {
      const evidence: EdgeEvidence[] = [];
      for (const probe of signature.probes) {
        const values = headerAll(snapshot, probe.header);
        for (const value of values) {
          if (probe.match && !probe.match.test(value)) continue;
          evidence.push({ header: probe.header, value: clip(value) });
        }
      }
      if (evidence.length > 0) {
        detections.push({ name: signature.name, category: signature.category, evidence });
      }
    }

    let cache: { header: string; value: string } | null = null;
    for (const name of CACHE_HEADERS) {
      const value = header(snapshot, name);
      if (value) {
        cache = { header: name, value: clip(value) };
        break;
      }
    }

    const via = headerAll(snapshot, "via");

    const findings: Finding[] = [];

    if (detections.length === 0) {
      findings.push({
        id: "edge-protection-none",
        title: "No CDN or web application firewall could be identified",
        detail:
          "No response header names a CDN, WAF or reverse proxy, so the origin answers directly. Its address is exposed, and it absorbs every request and every flood itself.",
        severity: "low",
        remediation:
          "Put a CDN or WAF in front of the origin, such as Cloudflare, Fastly or Amazon CloudFront, and restrict the origin's firewall to the edge provider's published address ranges so the origin cannot be reached around it.",
        reference: {
          label: "OWASP: Web application firewall",
          url: "https://owasp.org/www-community/Web_Application_Firewall",
        },
      });
    } else {
      const found = detections.map((d) => d.name);
      findings.push({
        id: "edge-protection-present",
        title: "An edge service is in front of the origin",
        detail: `${joinNames(found)} ${found.length === 1 ? "is" : "are"} in the path for this response. A header proves the edge handled the request; it does not prove that a WAF rule set is enabled or that the origin is unreachable directly.`,
        severity: "info",
        evidence: detections.flatMap((d) =>
          d.evidence.slice(0, 2).map((e) => ({
            label: e.header,
            value: e.value,
            tone: "neutral" as const,
          }))
        ),
      });
    }

    const names = detections.map((d) => d.name);
    const verb = names.length === 1 ? "is" : "are";
    const cacheTail = cache ? `, with ${cachePhrase(cache)}` : "";

    const headline =
      detections.length === 0
        ? "No CDN or web application firewall could be identified from the response headers."
        : `${joinNames(names)} ${verb} in front of the origin${cacheTail}.`;

    const status: CheckResult["status"] = detections.length === 0 ? "warn" : "pass";

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        detections,
        cache,
        via,
        status: snapshot.status,
      } satisfies EdgeProtectionData,
      ms: Math.round(performance.now() - started),
      source: "Response headers",
      note:
        "An edge header proves the edge is in the path for this response, not that a WAF rule set is enabled or that the origin refuses connections from anywhere else. The list is also a lower bound: an edge that strips its own headers leaves no trace here.",
    };
  },
};
