/**
 * Certificate transparency: every certificate ever issued for a domain is
 * published to public CT logs. This check reads a CT aggregator a browser can
 * actually reach, and answers two questions at once:
 *
 *  - Certificate hygiene: which CAs issued, how long certs last, whether any
 *    were issued for names nobody advertised.
 *  - Subdomain discovery: every hostname that has ever had a certificate,
 *    which is usually more than the site links to.
 *
 * The source is Cert Spotter rather than crt.sh. crt.sh is the better known
 * index and needs no key, but it sends no `Access-Control-Allow-Origin` header
 * and, verified on 23 November 2026, answered both 502 and 429 to a plain
 * request. A browser therefore cannot read it at all, and a check built on it
 * reported "unavailable" on every scan without ever measuring anything. Cert
 * Spotter answers the same log set over a CORS-open JSON endpoint, so this check
 * measures something on every run.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";

/**
 * One issuance from the Cert Spotter v1 API (`/v1/issuances`).
 *
 * The base response carries `id`, `not_before`, `not_after` and a `revoked`
 * boolean. `dns_names` and `issuer` are added by `expand=`; a field not
 * requested is simply absent, which is why every one here is optional except
 * the cursor id. Verified against a live response on 23 November 2026.
 */
type CertSpotterIssuance = {
  id: string;
  tbs_sha256?: string;
  dns_names?: string[];
  not_before?: string;
  not_after?: string;
  revoked?: boolean;
  issuer?: {
    name?: string;
    friendly_name?: string;
    o?: string;
    cn?: string;
    id?: number;
  };
};

export type CtData = {
  certificates: number;
  issuers: Array<{ name: string; count: number }>;
  hostnames: string[];
  /** In-domain hostnames other than the apex, for display. */
  notableHosts: string[];
  newest: string | null;
  oldest: string | null;
  /**
   * Longest validity, in days, among certificates from a trusted issuer that
   * were issued after the 398-day cap took effect. This is the same population
   * the long-validity finding judges, so the number and the finding always
   * agree. Reporting the raw maximum showed "3650 days" from a test
   * intermediate next to no finding at all.
   */
  longestValidityDays: number;
  wildcards: string[];
  /**
   * True when a full page came back, so the index holds more issuances than the
   * one page read here and every count is a floor rather than a total.
   * Optional so a reader that predates the field still type-checks.
   */
  truncated?: boolean;
};

/** Turn a Cert Spotter issuer object into a short label. */
function caLabel(issuer: CertSpotterIssuance["issuer"]): string {
  if (!issuer) return "Unknown issuer";
  if (issuer.friendly_name) return issuer.friendly_name.trim();
  const o = issuer.o?.trim();
  const cn = issuer.cn?.trim();
  if (o && cn && cn !== o) return `${o} ${cn}`;
  if (cn || o) return cn || o || "Unknown issuer";
  const name = issuer.name ?? "";
  const parsedO = /O=([^,]+)/.exec(name)?.[1]?.trim();
  const parsedCn = /CN=([^,]+)/.exec(name)?.[1]?.trim();
  if (parsedO && parsedCn && parsedCn !== parsedO) return `${parsedO} ${parsedCn}`;
  return parsedCn || parsedO || name || "Unknown issuer";
}

function validityDays(notBefore: string, notAfter: string): number {
  const start = Date.parse(notBefore);
  const end = Date.parse(notAfter);
  if (Number.isNaN(start) || Number.isNaN(end)) return 0;
  return Math.round((end - start) / 86_400_000);
}

/**
 * Whether an issuer is a CA a browser could trust, which is the only kind worth
 * judging against the validity cap.
 *
 * A live scan of example.com once found two 3,650-day certificates that no
 * browser trusts and that the site does not serve: one whose issuer name was
 * the literal "Issuer Not Found" and one from a test intermediate. The finding
 * built on them was a true statement about a junk log entry and a false
 * implication about the site, so it is judged only on entries that survive this.
 */
function isRealIssuer(label: string): boolean {
  const raw = (label ?? "").trim();
  if (!raw) return false;
  if (/unknown issuer/i.test(raw)) return false;
  if (/issuer not found/i.test(raw)) return false;
  if (/test|certificate authority of|localhost|self.?signed/i.test(raw)) return false;
  return true;
}

/**
 * The one issuance query the certificate checks share.
 *
 * Exported so `subdomains` requests the identical URL and cache key, so the
 * shared fetch layer serves both checks from one request.
 */
export function certificateIndexUrl(domain: string): string {
  return (
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
    `&include_subdomains=true&expand=dns_names&expand=issuer&expand=not_before` +
    `&expand=not_after&expand=cert`
  );
}

/**
 * Fetch the certificate index, surviving the cold-cache timeout.
 *
 * Cert Spotter answers a 504 with `{"code":"timeout"}` when a large domain's
 * query runs past its ten-second budget while the index warms. On 23 November
 * 2026 a cold query for cloudflare.com returned 504 twice in a row, and a
 * single-host query for the same name answered 200 in under two seconds. One
 * delayed retry costs little and sometimes recovers the measurement; if it also
 * times out the check reports unavailable, which is the honest outcome.
 */
export async function fetchCertificateIndex(
  net: import("../net/client").NetClient,
  domain: string
): Promise<import("../net/client").FetchResult<unknown>> {
  const key = `certspotter:${domain}`;
  const first = await net.json<unknown>(certificateIndexUrl(domain), {
    timeoutMs: 30_000,
    cacheKey: key,
  });
  if (first.ok) return first;

  // Only a gateway timeout is worth retrying. A 403 or a rate limit means the
  // query will not succeed in a second, and retrying would just burn the budget.
  const isWarmupTimeout =
    first.status === 504 || /timeout/i.test(first.message ?? "");
  if (!isWarmupTimeout) return first;

  await new Promise((resolve) => setTimeout(resolve, 4_000));
  // The retry needs a different cache key. The fetch layer caches by key, not by
  // URL, so re-requesting with the same key hands back the cached 504 and the
  // retry can never succeed. `forget` also cannot help here: it matches keys
  // that contain the URL, and this key is `certspotter:<domain>`.
  return net.json<unknown>(certificateIndexUrl(domain), {
    timeoutMs: 30_000,
    cacheKey: `${key}:retry`,
  });
}

/**
 * Labels that suggest a host was never meant to be reachable from the internet.
 *
 * Matching is by whole label, not by substring. A substring test read `s1`
 * inside a DKIM selector and `dev` inside an unrelated word as "internal", which
 * raised a finding and a failing status for a domain whose only sin was having a
 * certificate for a host with a short name. `dev.example.com` is a signal;
 * `s1.example.com` is not.
 */
const INTERNAL_LABELS = new Set([
  "dev",
  "staging",
  "stage",
  "test",
  "uat",
  "qa",
  "internal",
  "intranet",
  "admin",
  "jenkins",
  "gitlab",
  "grafana",
  "kibana",
  "vpn",
  "phpmyadmin",
  "jira",
  "confluence",
  "ldap",
  "sso",
  "corp",
]);

/** True when any label of a hostname equals an internal term exactly. */
export function looksInternal(host: string): boolean {
  return host
    .split(".")
    .some((label) => label.split("-").some((part) => INTERNAL_LABELS.has(part)));
}

export const ctLogs: CheckDefinition = {
  id: "ct-logs",
  title: "Certificate transparency",
  question:
    "What certificates have been issued for this domain, and for which hostnames?",
  group: "transport",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    const res = await fetchCertificateIndex(ctx.net, domain);

    if (!res.ok) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: describeFailure(res, "The certificate index"),
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Cert Spotter certificate index",
        note: "The certificate index did not answer, so no claim is made about which certificates exist. This is not evidence that none do.",
      };
    }

    if (!Array.isArray(res.json)) {
      // The endpoint answers an error object rather than a list when a domain
      // is outside its free tier or a query is malformed. Reading that as "no
      // certificates exist" would state a fact from a response that carried no
      // certificate data.
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The certificate index returned a response that was not a list of issuances.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Cert Spotter certificate index",
        note: "The response named an error rather than listing certificates. This is not evidence that no certificates exist for the domain.",
      };
    }

    const entries = res.json as CertSpotterIssuance[];

    if (entries.length === 0) {
      // The index lists unexpired issuances only, so an empty list is a real
      // answer about the last 100 results, but it is not "no certificate was
      // ever issued". The wording separates the two.
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "info",
        headline: `Cert Spotter lists no unexpired issuance for ${domain}.`,
        findings: [],
        data: {
          certificates: 0,
          issuers: [],
          hostnames: [],
          notableHosts: [],
          newest: null,
          oldest: null,
          longestValidityDays: 0,
          wildcards: [],
          truncated: false,
        } satisfies CtData,
        ms: Math.round(performance.now() - started),
        source: "Cert Spotter certificate index",
        note: "Cert Spotter lists unexpired issuances from public certificate transparency logs. An empty list means the index holds no live certificate for the name, which can mean none was ever logged or that every one logged has expired. It is not a verdict that the site has no certificate.",
      };
    }

    const issuerCounts = new Map<string, number>();
    const hostSet = new Set<string>();
    let newest: string | null = null;
    let oldest: string | null = null;
    let longestSinceCutoff = 0;
    let longestSinceCutoffEntry: CertSpotterIssuance | null = null;

    const CUTOFF = Date.UTC(2020, 8, 1);

    // A suffix test alone would accept a lookalike such as notexample.com for
    // example.com, so a name counts only at the apex or past a dot boundary.
    const inDomain = (host: string): boolean => host === domain || host.endsWith("." + domain);

    for (const e of entries) {
      const label = caLabel(e.issuer);
      issuerCounts.set(label, (issuerCounts.get(label) ?? 0) + 1);

      for (const name of e.dns_names ?? []) {
        const n = String(name).trim().toLowerCase().replace(/\.$/, "");
        if (!n) continue;
        // A certificate can carry names outside this domain: example.com's
        // certificate also covers example.edu and example.net. Those names are
        // not part of this site's surface, and counting them inflated the
        // hostname total with unrelated registrations.
        const bare = n.startsWith("*.") ? n.slice(2) : n;
        if (inDomain(bare)) hostSet.add(n);
      }

      const notBefore = e.not_before ?? "";
      const notAfter = e.not_after ?? "";
      const issued = notBefore ? Date.parse(notBefore) : NaN;
      if (!Number.isNaN(issued)) {
        const iso = new Date(issued).toISOString();
        if (!newest || iso > newest) newest = iso;
        if (!oldest || iso < oldest) oldest = iso;
      }

      const v = validityDays(notBefore, notAfter);
      if (
        v > longestSinceCutoff &&
        !Number.isNaN(issued) &&
        issued >= CUTOFF &&
        isRealIssuer(label)
      ) {
        longestSinceCutoff = v;
        longestSinceCutoffEntry = e;
      }
    }

    const hostnames = [...hostSet].sort();
    const wildcards = hostnames.filter((h) => h.startsWith("*."));
    const issuers = [...issuerCounts.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);

    const findings: Finding[] = [];

    // The 398-day cap only applies to certificates issued on or after
    // 1 September 2020. A 10-year certificate from 2015 is history, not a
    // current defect, so the rule is judged against the issue date.
    if (longestSinceCutoff > 398 && longestSinceCutoffEntry) {
      const issued = longestSinceCutoffEntry.not_before?.slice(0, 10) ?? "an unknown date";
      const expires = longestSinceCutoffEntry.not_after?.slice(0, 10) ?? "an unknown date";
      findings.push({
        id: "ct-long-validity",
        title: "A certificate was issued with a validity longer than 398 days",
        detail: `The longest validity issued after the cap took effect runs ${longestSinceCutoff} days, from ${issued} to ${expires}. Certificates issued after 1 September 2020 are limited to 398 days by the CA/Browser Forum baseline requirements.`,
        severity: "medium",
        remediation:
          "Reissue with a current CA. Long-lived certificates cannot be revoked at the speed a compromise demands.",
        reference: {
          label: "CA/Browser Forum baseline requirements",
          url: "https://cabforum.org/working-groups/server/baseline-requirements/",
        },
      });
    }

    // Wildcards are reported by the subdomain-surface check, which owns the
    // hostname view. Repeating it here produced the same finding twice in one
    // report, so this check keeps the data and stays quiet about it.

    const apex = domain;
    const inDomainHosts = hostnames.filter(
      (h) => !h.startsWith("*.") && h !== apex && h.endsWith("." + apex)
    );

    // The endpoint returns at most 100 issuances per page and the browser cannot
    // read its Link header, so a full page is a floor. Every count in the
    // headline and data is then a minimum, and both say so.
    const truncated = entries.length >= 100;

    const status: CheckResult["status"] = findings.length > 0 ? "warn" : "info";

    const headline =
      truncated
        ? `At least ${entries.length} unexpired certificate${entries.length === 1 ? "" : "s"} from ${issuers.length} issuer${issuers.length === 1 ? "" : "s"}, covering at least ${hostnames.length} distinct hostname${hostnames.length === 1 ? "" : "s"}. More exist than this page lists.`
        : `${entries.length} unexpired certificate${entries.length === 1 ? "" : "s"} from ${issuers.length} issuer${issuers.length === 1 ? "" : "s"}, covering ${hostnames.length} distinct hostname${hostnames.length === 1 ? "" : "s"}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        certificates: entries.length,
        issuers,
        hostnames,
        notableHosts: inDomainHosts.slice(0, 40),
        newest,
        oldest,
        longestValidityDays: longestSinceCutoff,
        wildcards,
        truncated,
      } satisfies CtData,
      ms: Math.round(performance.now() - started),
      source: "Cert Spotter certificate index (public certificate transparency logs)",
      note: truncated
        ? "Cert Spotter lists unexpired issuances from public certificate transparency logs, at most 100 per page. This page was full and the browser cannot follow its pagination header, so every count here is a floor and more issuances may exist."
        : "Cert Spotter lists unexpired issuances from public certificate transparency logs, with the issuer each certificate named. It is an index of what was logged, so a certificate logged after the query is not reflected here, and a certificate that has expired is not returned at all.",
    };
  },
};
