/**
 * Certificate transparency: every certificate ever issued for a domain is
 * published to public CT logs, and crt.sh indexes them. That index answers two
 * questions at once:
 *
 *  - Certificate hygiene: which CAs issued, how long certs last, whether any
 *    were issued for names nobody advertised.
 *  - Subdomain discovery: every hostname that has ever had a certificate,
 *    which is usually more than the site links to.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";

type CtEntry = {
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  id: number;
  entry_timestamp: string;
  not_before: string;
  not_after: string;
  serial_number: string;
};

export type CtData = {
  certificates: number;
  issuers: Array<{ name: string; count: number }>;
  hostnames: string[];
  /** In-domain hostnames other than the apex, for display. */
  notableHosts: string[];
  newest: string | null;
  oldest: string | null;
  /** Longest validity period seen, in days. */
  longestValidityDays: number;
  wildcards: string[];
};

function caLabel(issuer: string): string {
  // "C=US, O=Let's Encrypt, CN=R3" -> "Let's Encrypt R3"
  const o = /O=([^,]+)/.exec(issuer)?.[1]?.trim();
  const cn = /CN=([^,]+)/.exec(issuer)?.[1]?.trim();
  if (o && cn && cn !== o) return `${o} ${cn}`;
  return cn || o || issuer;
}

function validityDays(notBefore: string, notAfter: string): number {
  const start = Date.parse(notBefore);
  const end = Date.parse(notAfter);
  if (Number.isNaN(start) || Number.isNaN(end)) return 0;
  return Math.round((end - start) / 86_400_000);
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
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;

    // crt.sh is a single-instance database with no CDN in front of it. A cold
    // query for a busy domain routinely takes 20 to 30 seconds, and a timeout
    // here costs the whole check, so the ceiling is generous and the call
    // retries once.
    const res = await ctx.net.text(url, {
      timeoutMs: 45_000,
      retry: true,
      cacheKey: `crtsh:${domain}`,
    });

    if (!res.ok) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: describeFailure(res, "The CT log index"),
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "crt.sh",
        note: "crt.sh is occasionally slow under load. Re-running the scan usually succeeds.",
      };
    }

    let entries: CtEntry[];
    try {
      entries = JSON.parse(res.text) as CtEntry[];
    } catch {
      // crt.sh answers an unparseable body under load, and sometimes an HTML
      // error page with a 200. Reporting that as "no certificates exist" would
      // state a fact about the domain from a response that said nothing about
      // it, so the check declines to answer instead.
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The CT log index returned a response that could not be read as JSON.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "crt.sh",
        note: "crt.sh is occasionally slow under load and answers with an error page. This is not evidence that no certificates exist for the domain.",
      };
    }

    if (!Array.isArray(entries) || entries.length === 0) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "info",
        headline: "No certificates were found in public CT logs for this domain.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "crt.sh",
      };
    }

    const issuerCounts = new Map<string, number>();
    const hostSet = new Set<string>();
    let newest: string | null = null;
    let oldest: string | null = null;
    let longest = 0;
    /**
     * The longest-lived certificate issued on or after the 398-day cap took
     * effect, with its dates. Tracking only the global maximum missed the real
     * defect: a 2015 ten-year certificate outranked a 500-day certificate from
     * last year, so the one that actually violates the cap was never cited.
     */
    const CUTOFF = Date.UTC(2020, 8, 1);
    let longestSinceCutoff = 0;
    let longestSinceCutoffEntry: CtEntry | null = null;

    for (const e of entries) {
      const label = caLabel(e.issuer_name);
      issuerCounts.set(label, (issuerCounts.get(label) ?? 0) + 1);
      for (const name of (e.name_value || "").split("\n")) {
        const n = name.trim().toLowerCase();
        if (n) hostSet.add(n);
      }
      if (e.entry_timestamp) {
        const ts = Date.parse(e.entry_timestamp);
        if (!Number.isNaN(ts)) {
          const iso = new Date(ts).toISOString();
          if (!newest || iso > newest) newest = iso;
          if (!oldest || iso < oldest) oldest = iso;
        }
      }
      const v = validityDays(e.not_before, e.not_after);
      if (v > longest) {
        longest = v;
      }
      const issued = e.not_before ? Date.parse(e.not_before) : NaN;
      if (v > longestSinceCutoff && !Number.isNaN(issued) && issued >= CUTOFF) {
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
    const inDomain = hostnames.filter(
      (h) => !h.startsWith("*.") && h !== apex && h.endsWith(apex)
    );

    const status: CheckResult["status"] = findings.length > 0 ? "warn" : "info";

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline: `${entries.length} certificates from ${issuers.length} issuer${issuers.length === 1 ? "" : "s"}, covering ${hostnames.length} distinct hostname${hostnames.length === 1 ? "" : "s"}.`,
      findings,
      data: {
        certificates: entries.length,
        issuers,
        hostnames,
        notableHosts: inDomain.slice(0, 40),
        newest,
        oldest,
        longestValidityDays: longest,
        wildcards,
      } satisfies CtData,
      ms: Math.round(performance.now() - started),
      source: "crt.sh Certificate Transparency index",
    };
  },
};
