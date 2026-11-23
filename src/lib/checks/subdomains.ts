/**
 * The hostname surface, from certificate transparency and from the page itself.
 *
 * Every certificate ever issued for a name is public, so CT logs are the widest
 * honest view of which hosts exist without touching the target. The document
 * adds the subset the site actually links to.
 *
 * The finding that matters is not the count. It is a certificate for a host
 * whose name says internal: a staging, admin or corp hostname in a public index
 * means someone obtained a publicly trusted certificate for it, which is why it
 * is worth confirming the host is meant to be reachable. A certificate is not
 * proof the service is exposed now, and the finding says so.
 *
 * The source is Cert Spotter, for the same reason `ct-logs` uses it: crt.sh
 * sends no cross-origin header and answers errors under load, so a browser
 * cannot read it. The URL here is identical to the one `ct-logs` requests, so
 * the shared fetch layer serves both checks from one request.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";
import { fetchCertificateIndex, looksInternal } from "./ct-logs";
type CertSpotterIssuance = {
  dns_names?: string[];
};

export type SubdomainsData = {
  certificateHosts: string[];
  linkedHosts: string[];
  wildcards: string[];
  total: number;
};

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

    const [ctRes, page] = await Promise.all([
      fetchCertificateIndex(ctx.net, domain),
      ctx.html(),
    ]);

    if (!ctRes.ok) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: describeFailure(ctRes, "The certificate index"),
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Cert Spotter certificate index",
        note: "The certificate index did not answer, so no claim is made about which hostnames have certificates. This is not evidence that none exist.",
      };
    }

    if (!Array.isArray(ctRes.json)) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The certificate index answered, but not with a readable certificate list.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Cert Spotter certificate index",
        note: "The response named an error rather than listing certificates. That is not an empty list, so no subdomain verdict is claimed.",
      };
    }

    const entries = ctRes.json as CertSpotterIssuance[];

    const hostSet = new Set<string>();
    const wildcardSet = new Set<string>();

    // A suffix test alone would accept a lookalike such as notexample.com for
    // example.com, so require either the apex itself or a dot boundary.
    const inDomain = (host: string): boolean => host === domain || host.endsWith("." + domain);

    const absorb = (raw: string) => {
      for (const line of String(raw).split(/[\n,]/)) {
        const name = line.trim().toLowerCase().replace(/\.$/, "");
        if (!name) continue;
        if (name.startsWith("*.")) {
          // A wildcard is only this domain's business when its parent is in
          // scope. A shared-hosting certificate can name someone else's
          // wildcard, and counting those overstated the surface.
          const bare = name.slice(2);
          if (!inDomain(bare)) continue;
          wildcardSet.add(name);
          // The wildcard's parent is still a real host worth counting.
          hostSet.add(bare);
          continue;
        }
        // A CN can be a subject identity ("user@example.com") rather than a
        // hostname; the domain test drops those.
        if (inDomain(name)) hostSet.add(name);
      }
    };

    for (const entry of entries) {
      for (const name of entry?.dns_names ?? []) absorb(name);
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

    // The index returns at most 100 issuances per page and a browser cannot read
    // its pagination header, so a full page means the certificate side of this
    // count is a floor rather than a total.
    const certificateListTruncated = entries.length >= 100;

    const findings: Finding[] = [];

    if (union.size > 30) {
      findings.push({
        id: "subdomains-large-surface",
        title: `${certificateListTruncated ? "At least " : ""}${union.size} distinct hostnames under ${domain}`,
        detail: `Public certificates and page links name ${union.size} hosts${certificateListTruncated ? ", and the certificate page was full so more may exist" : ""}. Each one is a separate surface with its own certificate, patch level and access rules.`,
        severity: "info",
      });
    }

    const sensitive = [...union].filter(looksInternal).sort();
    if (sensitive.length > 0) {
      findings.push({
        id: "subdomains-sensitive-name",
        title: `${sensitive.length} hostname${sensitive.length === 1 ? " looks" : "s look"} internal but ${sensitive.length === 1 ? "is" : "are"} public`,
        detail: `These names appear on public certificate transparency entries or in the page's links: ${sensitive.slice(0, 6).join(", ")}${sensitive.length > 6 ? " and others" : ""}. A name like this is a lead, not proof that a service is reachable: a certificate is only evidence that a publicly trusted certificate was once issued for the name, and the check does not resolve it.`,
        severity: "medium",
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
          label: "RFC 6125 section 6.4.3",
          url: "https://www.rfc-editor.org/rfc/rfc6125.html#section-6.4.3",
        },
        evidence: wildcards.slice(0, 10).map((w) => ({ label: "Wildcard", value: w })),
      });
    }

    // "Looks internal" is a lead, not proof of exposure, so it is a warning
    // rather than a failure. Only a name confirmed to resolve would justify a
    // failing status, and this check does not resolve names.
    const actionable = findings.some((f) => f.severity !== "info");
    const status: CheckResult["status"] = actionable
      ? "warn"
      : findings.length > 0
        ? "info"
        : "pass";

    const headline =
      union.size === 0
        ? `No hostnames under ${domain} were found in CT logs or in the page's links.`
        : `${certificateListTruncated ? "At least " : ""}${union.size} distinct hostname${union.size === 1 ? "" : "s"} under ${domain}: ${certificateHosts.length} from certificate transparency, ${linkedHosts.length} linked from the page, ${wildcards.length} wildcard${wildcards.length === 1 ? "" : "s"}.`;

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
      source: "Cert Spotter certificate index and the page's own links",
      note:
        certificateHosts.length > DISPLAY_CAP || linkedHosts.length > DISPLAY_CAP
          ? `The display lists are capped at ${DISPLAY_CAP} entries each. The total is the full count. Cert Spotter lists unexpired issuances only, so a name whose only certificate has expired will not appear.`
          : "Cert Spotter lists unexpired issuances from public certificate transparency logs, so a name whose only certificate has expired will not appear. A name in the log may no longer resolve, and a name absent from it may still exist.",
    };
  },
};
