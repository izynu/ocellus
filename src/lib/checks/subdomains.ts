/**
 * The hostname surface, from certificate transparency and from the page itself.
 *
 * Every certificate ever issued for a name is public, so CT logs are the widest
 * honest view of which hosts exist without touching the target. The document
 * adds the subset the site actually links to.
 *
 * The finding that matters is not the count. It is a certificate for a host
 * whose name says internal: a staging, admin or corp hostname only appears in a
 * public log because someone obtained a publicly trusted certificate for it,
 * which means the host resolves from the internet.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";

type CtEntry = {
  name_value?: string;
  common_name?: string;
};

export type SubdomainsData = {
  certificateHosts: string[];
  linkedHosts: string[];
  wildcards: string[];
  total: number;
};

/** Names that suggest a host was never meant to be reachable from the internet. */
const SENSITIVE_NAME =
  /dev|staging|test|uat|qa|internal|admin|jenkins|gitlab|grafana|kibana|phpmyadmin|\.corp|\.local/i;

/** Keep the payload a sane size for rendering; `total` stays exact. */
const DISPLAY_CAP = 100;

export const subdomains: CheckDefinition = {
  id: "subdomains",
  title: "Subdomain surface",
  question: "Which hostnames under this domain are public, and does any of them look internal?",
  group: "infrastructure",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;
    // The leading %25 is a percent-encoded "%", which crt.sh reads as a
    // wildcard, so the query matches every subdomain rather than the apex only.
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;

    const [ctRes, page] = await Promise.all([
      ctx.net.text(url, { timeoutMs: 45_000, retry: true, cacheKey: `crtsh-sub:${domain}` }),
      ctx.html(),
    ]);

    if (!ctRes.ok) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: describeFailure(ctRes, "The CT log index"),
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "crt.sh",
        note: "crt.sh is occasionally slow under load and rate limits by IP. Re-running the scan usually succeeds.",
      };
    }

    // crt.sh answers 200 with an HTML error page under load, and an unparseable
    // body is not "no subdomains". Reading it as an empty list produced a clean
    // pass for a domain whose certificate search had actually failed.
    let entries: CtEntry[];
    try {
      const parsed: unknown = JSON.parse(ctRes.text);
      if (!Array.isArray(parsed)) throw new Error("not an array");
      entries = parsed as CtEntry[];
    } catch {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The CT log index answered, but not with a readable certificate list.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "crt.sh",
        note: "crt.sh returns an HTML error page or a truncated response when it is overloaded. Neither is an empty certificate list, so no subdomain verdict is claimed. Re-running the scan usually succeeds.",
      };
    }

    const hostSet = new Set<string>();
    const wildcardSet = new Set<string>();

    // A suffix test alone would accept a lookalike such as notexample.com for
    // example.com, so require either the apex itself or a dot boundary.
    const inDomain = (host: string): boolean => host === domain || host.endsWith("." + domain);

    const absorb = (raw: string) => {
      for (const line of raw.split("\n")) {
        const name = line.trim().toLowerCase().replace(/\.$/, "");
        if (!name) continue;
        if (name.startsWith("*.")) {
          // A wildcard is only this domain's business when its parent is in
          // scope. crt.sh returns shared-hosting certificates whose CN names
          // someone else's wildcard, and counting those overstated the surface.
          const bare = name.slice(2);
          if (!inDomain(bare)) continue;
          wildcardSet.add(name);
          // The wildcard's parent is still a real host worth counting.
          hostSet.add(bare);
          continue;
        }
        if (inDomain(name)) hostSet.add(name);
      }
    };

    if (Array.isArray(entries)) {
      for (const entry of entries) {
        if (typeof entry?.name_value === "string") absorb(entry.name_value);
        // common_name is one name, not a newline list, but a CN can also be a
        // subject identity ("user@example.com") that is not a hostname at all.
        // The domain test inside absorb drops those.
        if (typeof entry?.common_name === "string") absorb(entry.common_name);
      }
    }

    // Hostnames the page itself points at. This is the part of the surface the
    // site advertises, and it is often a different set from the certificates.
    const linkedSet = new Set<string>();
    const doc = page.doc;
    if (doc) {
      for (const el of Array.from(doc.querySelectorAll("a[href]"))) {
        const href = el.getAttribute("href") ?? "";
        try {
          const host = new URL(href, ctx.target.url).hostname.toLowerCase().replace(/\.$/, "");
          if (host && inDomain(host)) linkedSet.add(host);
        } catch {
          // A malformed href is not a hostname; skip it.
        }
      }
    }

    const certificateHosts = [...hostSet].sort();
    const linkedHosts = [...linkedSet].sort();
    const wildcards = [...wildcardSet].sort();
    // Distinct hosts across both sources, so the count is the real surface.
    const union = new Set<string>([...certificateHosts, ...linkedHosts]);

    const findings: Finding[] = [];

    if (union.size > 30) {
      findings.push({
        id: "subdomains-large-surface",
        title: `${union.size} distinct hostnames under ${domain}`,
        detail: `Public certificates and page links name ${union.size} hosts. Each one is a separate surface with its own certificate, patch level and access rules.`,
        severity: "info",
      });
    }

    const sensitive = [...union].filter((host) => SENSITIVE_NAME.test(host)).sort();
    if (sensitive.length > 0) {
      findings.push({
        id: "subdomains-sensitive-name",
        title: `${sensitive.length} hostname${sensitive.length === 1 ? " looks" : "s look"} internal but ${sensitive.length === 1 ? "is" : "are"} public`,
        detail: `These names appear in public certificate transparency logs, which means a publicly trusted certificate was issued for them and they resolve from the internet: ${sensitive.slice(0, 6).join(", ")}${sensitive.length > 6 ? " and others" : ""}.`,
        severity: "high",
        remediation:
          "Confirm each host is meant to be public. If it is not, remove the DNS record and the certificate, and reach it over a VPN or an internal-only name instead. A public certificate alone does not expose the service, but it does publish that the host exists and is worth probing.",
        reference: {
          label: "RFC 6962: Certificate Transparency",
          url: "https://www.rfc-editor.org/rfc/rfc6962.html",
        },
        evidence: sensitive.slice(0, 12).map((host) => ({ label: "Host", value: host, tone: "bad" as const })),
      });
    }

    if (wildcards.length > 0) {
      findings.push({
        id: "subdomains-wildcard",
        title: `${wildcards.length} wildcard certificate${wildcards.length === 1 ? "" : "s"} in use`,
        detail: `A wildcard covers every name at one level at once: ${wildcards.slice(0, 3).join(", ")}${wildcards.length > 3 ? " and others" : ""}. One leaked private key is then valid for every host it covers.`,
        severity: "low",
        remediation:
          "Prefer per-host certificates where operationally possible, and keep wildcard keys in a tightly scoped secret store.",
        reference: {
          label: "RFC 6125 §6.4.3",
          url: "https://www.rfc-editor.org/rfc/rfc6125.html#section-6.4.3",
        },
        evidence: wildcards.slice(0, 10).map((w) => ({ label: "Wildcard", value: w })),
      });
    }

    const serious = findings.some((f) => f.severity === "high" || f.severity === "critical");
    const actionable = findings.some((f) => f.severity !== "info");
    const status: CheckResult["status"] = serious ? "fail" : actionable ? "warn" : findings.length > 0 ? "info" : "pass";

    const headline =
      union.size === 0
        ? `No hostnames under ${domain} were found in CT logs or in the page's links.`
        : `${union.size} distinct hostname${union.size === 1 ? "" : "s"} under ${domain}: ${certificateHosts.length} from certificate transparency, ${linkedHosts.length} linked from the page, ${wildcards.length} wildcard${wildcards.length === 1 ? "" : "s"}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        certificateHosts: certificateHosts.slice(0, DISPLAY_CAP),
        linkedHosts: linkedHosts.slice(0, DISPLAY_CAP),
        wildcards: wildcards.slice(0, DISPLAY_CAP),
        total: union.size,
      } satisfies SubdomainsData,
      ms: Math.round(performance.now() - started),
      source: "crt.sh Certificate Transparency index and the page's own links",
      note:
        certificateHosts.length > DISPLAY_CAP || linkedHosts.length > DISPLAY_CAP
          ? `The display lists are capped at ${DISPLAY_CAP} entries each. The total is the full count.`
          : "CT logs list every hostname that has ever had a publicly trusted certificate. A name in the log may no longer resolve.",
    };
  },
};
