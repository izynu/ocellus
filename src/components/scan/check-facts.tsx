"use client";

/**
 * The measured values behind a check, as a short fact list inside its box.
 *
 * Every check returns a structured payload alongside its verdict. Without this
 * layer that payload is only visible in the exported JSON, so a reader sees the
 * sentence and has to take the number on trust. The list here is the number:
 * a registrar and an expiry date, a rank and the day it was measured, the ports
 * a host exposes. It is deliberately short. A box that lists thirty values is a
 * table again, and the point of the box is that it can be read at a glance.
 *
 * Each entry is written for one check id, so the shape of the payload is known
 * and the cast is total. A check with no entry simply shows its headline, which
 * is what the report did before this file existed.
 */

import type { CheckResult } from "@/lib/types";

import type { DnsData } from "@/lib/checks/dns-records";
import type { DnssecData } from "@/lib/checks/dnssec";
import type { WhoisData } from "@/lib/checks/whois";
import type { DnsHygieneData } from "@/lib/checks/dns-hygiene";
import type { CtData } from "@/lib/checks/ct-logs";
import type { CertificateRevocationData } from "@/lib/checks/certificate-revocation";
import type { RedirectsData } from "@/lib/checks/redirects";
import type { HeadersData } from "@/lib/checks/security-headers";
import type { EdgeProtectionData } from "@/lib/checks/edge-protection";
import type { EmailData } from "@/lib/checks/email-auth";
import type { SecurityTxtData } from "@/lib/checks/security-txt";
import type { ExposureData } from "@/lib/checks/infrastructure";
import type { VulnExposureData } from "@/lib/checks/vulnerability-exposure";
import type { SubdomainsData } from "@/lib/checks/subdomains";
import type { TechStackData } from "@/lib/checks/tech-stack";
import type { ThreatIntelData } from "@/lib/checks/threat-intel";
import type { BlocklistData } from "@/lib/checks/blocklist";
import type { BreachData } from "@/lib/checks/breach-history";
import type { ArchiveData } from "@/lib/checks/archive-history";
import type { PopularityData } from "@/lib/checks/popularity";
import type { PrivacyData } from "@/lib/checks/privacy";
import type { MarkupData } from "@/lib/checks/markup";
import type { SeoData } from "@/lib/checks/seo";
import type { PerformanceData } from "@/lib/checks/performance";
import type { DarkPatternData } from "@/lib/checks/dark-patterns";

type Fact = {
  label: string;
  value: React.ReactNode;
  /** A tone class when the value is itself a verdict. */
  tone?: string;
};

/** Stated rather than left blank, so a missing value is not read as a zero. */
const NONE = "not reported";

/** A list cut to a readable length, with the remainder counted rather than hidden. */
function list(items: Array<string | null | undefined>, max = 3): string {
  const clean = items.filter((item): item is string => Boolean(item && item.trim()));
  if (clean.length === 0) return "none";
  if (clean.length <= max) return clean.join(", ");
  return `${clean.slice(0, max).join(", ")} and ${clean.length - max} more`;
}

function yesNo(value: boolean | null | undefined): string {
  if (value === null || value === undefined) return NONE;
  return value ? "yes" : "no";
}

function date(iso: string | null | undefined): string {
  if (!iso) return NONE;
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso.slice(0, 10);
  return parsed.toISOString().slice(0, 10);
}

function bytes(count: number): string {
  if (count < 1024) return `${count} B`;
  if (count < 1024 * 1024) return `${(count / 1024).toFixed(1)} kB`;
  return `${(count / (1024 * 1024)).toFixed(1)} MB`;
}

function duration(days: number): string {
  if (days < 1) return "under a day";
  if (days < 365) return `${days} days`;
  return `${(days / 365).toFixed(1)} years`;
}

/* ------------------------------------------------------------------ cases -- */

function factsFor(id: string, data: unknown): Fact[] {
  switch (id) {
    case "dns-records": {
      const d = data as DnsData;
      const counts = Object.entries(d.counts ?? {})
        .filter(([, n]) => n > 0)
        .map(([type, n]) => `${type} ${n}`);
      return [
        { label: "Nameservers", value: list(d.nameservers, 2) },
        { label: "Addresses", value: list(d.addresses, 3) },
        {
          label: "Mail exchangers",
          value:
            d.mailServers.length > 0
              ? list(
                  d.mailServers.map((m) => m.host),
                  2
                )
              : "none published",
        },
        { label: "Records", value: list(counts, 5) },
        { label: "DNSSEC validated", value: yesNo(d.dnssecValidated) },
      ];
    }

    case "dnssec": {
      const d = data as DnssecData;
      return [
        {
          label: "Delegation",
          value: d.ds.length > 0 ? `${d.ds.length} DS record${d.ds.length === 1 ? "" : "s"}` : "no DS record",
        },
        {
          label: "Keys",
          value: d.dnskey.length > 0 ? `${d.dnskey.length} DNSKEY` : "none published",
        },
        {
          label: "Algorithms",
          value: list(
            Array.from(new Set(d.ds.map((r) => r.algorithmName))),
            3
          ),
        },
        { label: "Validation answered", value: yesNo(d.authenticated) },
      ];
    }

    case "whois": {
      const d = data as WhoisData;
      return [
        { label: "Registrar", value: d.registrar ?? NONE },
        { label: "Registered", value: date(d.registered) },
        { label: "Expires", value: date(d.expires) },
        {
          label: "Age",
          value: d.ageDays === null ? NONE : duration(d.ageDays),
        },
        {
          label: "Registry status",
          value: list(d.statuses, 2),
        },
      ];
    }

    case "dns-hygiene": {
      const d = data as DnsHygieneData;
      const consistent = d.mailHosts.filter((h) => h.consistent).length;
      return [
        {
          label: "Wildcard",
          value: d.wildcard.resolves ? "answers any name" : "none",
          tone: d.wildcard.resolves ? "tone-warn" : undefined,
        },
        { label: "HTTPS record", value: d.httpsRecord ? "published" : "none" },
        {
          label: "Mail host reverse",
          value:
            d.mailHosts.length === 0
              ? "no mail hosts"
              : `${consistent} of ${d.mailHosts.length} match`,
          tone: consistent === d.mailHosts.length ? "tone-pass" : "tone-warn",
        },
        { label: "TLS reporting", value: d.tlsRpt ? "published" : "none" },
      ];
    }

    case "ct-logs": {
      const d = data as CtData;
      return [
        { label: "Certificates", value: d.certificates.toLocaleString("en-US") },
        {
          label: "Issuers",
          value: list(
            d.issuers.map((i) => `${i.name} (${i.count})`),
            2
          ),
        },
        { label: "Newest", value: date(d.newest) },
        { label: "Oldest", value: date(d.oldest) },
        {
          label: "Longest validity",
          value: d.longestValidityDays > 0 ? `${d.longestValidityDays} days` : NONE,
        },
        { label: "Hostnames seen", value: d.hostnames.length.toLocaleString("en-US") },
      ];
    }

    case "redirects": {
      const d = data as RedirectsData;
      return [
        { label: "Hops", value: String(d.hops) },
        { label: "Final URL", value: <span className="mono">{d.finalUrl}</span> },
        { label: "Final status", value: String(d.finalStatus) },
        {
          label: "Downgraded",
          value: yesNo(d.downgraded),
          tone: d.downgraded ? "tone-fail" : undefined,
        },
      ];
    }

    case "certificate-revocation": {
      const d = data as CertificateRevocationData;
      return [
        { label: "Issuances listed", value: d.listed.toLocaleString("en-US") },
        {
          label: "Revoked",
          value: `${d.revoked}${d.revokedLive > 0 ? `, ${d.revokedLive} still in date` : ""}`,
          tone: d.revokedLive > 0 ? "tone-fail" : undefined,
        },
        { label: "Earliest", value: date(d.earliest) },
        { label: "Latest", value: date(d.latest) },
      ];
    }

    case "edge-protection": {
      const d = data as EdgeProtectionData;
      return [
        {
          label: "Detected",
          value:
            d.detections.length > 0
              ? list(
                  d.detections.map((entry) => entry.name),
                  3
                )
              : "no signature matched",
        },
        {
          label: "Category",
          value: list(
            Array.from(new Set(d.detections.map((entry) => entry.category))),
            2
          ),
        },
        { label: "Cache", value: d.cache ? `${d.cache.header}: ${d.cache.value}` : "none sent" },
        { label: "Via", value: d.via.length > 0 ? list(d.via, 2) : "none" },
      ];
    }

    case "security-headers": {
      const d = data as HeadersData;
      const good = d.rules.filter((r) => r.verdict === "good").length;
      return [
        { label: "Grade", value: d.grade },
        { label: "Headers correct", value: `${good} of ${d.rules.length}` },
        {
          label: "Discloses",
          value: list(
            d.disclosure.map((row) => row.header),
            3
          ),
        },
        { label: "HTTP status", value: String(d.status) },
      ];
    }

    case "email-auth": {
      const d = data as EmailData;
      const dkim = d.dkim.filter((s) => s.present).map((s) => s.selector);
      return [
        {
          label: "SPF",
          value: d.spf
            ? `${d.spf.all ? `all: ${d.spf.all}` : "no all mechanism"}, ${d.spf.lookupCount} lookups`
            : "not published",
        },
        {
          label: "DMARC",
          value: d.dmarc
            ? `p=${d.dmarc.p ?? "none"}${d.dmarc.pct !== null ? `, ${d.dmarc.pct}% of mail` : ""}`
            : "not published",
        },
        {
          label: "DKIM selectors",
          value: dkim.length > 0 ? list(dkim, 3) : "none found",
        },
        {
          label: "MTA-STS",
          value: d.mtaSts?.fileMode ?? (d.mtaSts?.dns ? "announced, no policy file" : "none"),
        },
      ];
    }

    case "security-txt": {
      const d = data as SecurityTxtData;
      return [
        { label: "Published", value: yesNo(d.found) },
        { label: "Expires", value: d.expires ? date(d.expires) : NONE },
        {
          label: "Expired",
          value: d.found ? yesNo(d.expired) : NONE,
          tone: d.expired ? "tone-fail" : undefined,
        },
        { label: "Fields", value: list(Object.keys(d.fields ?? {}), 4) },
      ];
    }

    case "infrastructure": {
      const d = data as ExposureData;
      return [
        { label: "Address", value: <span className="mono">{d.geo.ip ?? NONE}</span> },
        { label: "Network", value: d.geo.asn ?? NONE },
        { label: "Organisation", value: d.geo.org ?? NONE },
        {
          label: "Location",
          value: [d.geo.city, d.geo.country].filter(Boolean).join(", ") || NONE,
        },
        {
          label: "Open ports",
          value:
            d.internetdb.available && d.internetdb.ports.length > 0
              ? list(
                  d.internetdb.ports.map(String),
                  8
                )
              : d.internetdb.available
                ? "none reported"
                : "not scanned",
        },
      ];
    }

    case "vulnerability-exposure": {
      const d = data as VulnExposureData;
      const top = d.epss[0];
      return [
        {
          label: "Product named",
          value: list(
            d.products.map((p) => `${p.name}${p.version ? ` ${p.version}` : ""}`),
            2
          ),
        },
        {
          label: "In the catalogue",
          value: `${d.kevMatches.length} entr${d.kevMatches.length === 1 ? "y" : "ies"}`,
          tone: d.kevMatches.length > 0 ? "tone-warn" : undefined,
        },
        {
          label: "Highest EPSS",
          value: top
            ? `${top.cve} at ${(top.probability * 100).toFixed(1)}%`
            : "no score",
        },
        {
          label: "Catalogue",
          value: d.catalogSize ? d.catalogSize.toLocaleString("en-US") + " entries" : NONE,
        },
      ];
    }

    case "subdomains": {
      const d = data as SubdomainsData;
      return [
        { label: "Hostnames", value: d.total.toLocaleString("en-US") },
        { label: "From certificates", value: d.certificateHosts.length.toLocaleString("en-US") },
        { label: "Linked from the page", value: d.linkedHosts.length.toLocaleString("en-US") },
        { label: "Wildcards", value: d.wildcards.length > 0 ? list(d.wildcards, 2) : "none" },
      ];
    }

    case "tech-stack": {
      const d = data as TechStackData;
      return [
        { label: "Detected", value: `${d.items.length} technologies` },
        { label: "Server", value: d.server ?? NONE },
        { label: "Powered by", value: d.poweredBy ?? NONE },
        {
          label: "Notable",
          value: list(
            d.items.map((i) => i.name),
            4
          ),
        },
      ];
    }

    case "threat-intel": {
      const d = data as ThreatIntelData;
      return [
        { label: "Pulses", value: String(d.pulses) },
        { label: "Tags", value: list(d.tags, 3) },
        { label: "Whitelisted", value: yesNo(d.whitelisted) },
        {
          label: "Corroborated by",
          value: d.validations.length > 0 ? list(d.validations.map((v) => v.name), 3) : "no one",
        },
      ];
    }

    case "blocklist": {
      const d = data as BlocklistData;
      return [
        {
          label: "Verdict",
          value: d.blocked ? "refused to resolve" : "answered normally",
          tone: d.blocked ? "tone-fail" : "tone-pass",
        },
        {
          label: "Resolvers",
          value: list(
            d.resolvers.map((row) => `${row.name}: ${row.verdict}`),
            2
          ),
        },
        {
          label: "Answered with",
          value: list(
            d.resolvers.flatMap((row) => row.addresses),
            2
          ),
        },
      ];
    }

    case "breach-history": {
      const d = data as BreachData;
      const real = d.breaches.filter((entry) => entry.excluded === null);
      return [
        {
          label: "Disclosed breaches",
          value: String(real.length),
          tone: real.length > 0 ? "tone-warn" : undefined,
        },
        {
          label: "Accounts exposed",
          value: d.accountsExposed.toLocaleString("en-US"),
        },
        {
          label: "Most recent",
          value:
            real.length > 0
              ? date(
                  real
                    .slice()
                    .sort((a, b) => (b.date ?? "").localeCompare(a.date ?? ""))[0].date
                )
              : NONE,
        },
        {
          label: "Data exposed",
          value: list(
            Array.from(new Set(real.flatMap((entry) => entry.dataClasses))),
            3
          ),
        },
      ];
    }

    case "archive-history": {
      const d = data as ArchiveData;
      return [
        { label: "First capture", value: date(d.firstCapture) },
        { label: "Latest capture", value: date(d.lastCapture) },
        {
          label: "Archived for",
          value: d.spanYears === null ? NONE : `${d.spanYears.toFixed(1)} years`,
        },
        { label: "Latest status", value: d.lastStatus ?? NONE },
      ];
    }

    case "popularity": {
      const d = data as PopularityData;
      return [
        {
          label: "Rank",
          value: d.rank === null ? "not ranked" : d.rank.toLocaleString("en-US"),
        },
        { label: "Bucket", value: d.bucket },
        { label: "Measured", value: date(d.rankDate) },
      ];
    }

    case "privacy": {
      const d = data as PrivacyData;
      return [
        { label: "Cookies set", value: String(d.cookies.length) },
        {
          label: "Trackers",
          value:
            d.trackers.length > 0
              ? list(
                  d.trackers.map((t) => t.vendor),
                  3
                )
              : "none recognised",
        },
        { label: "Third-party hosts", value: String(d.thirdPartyHosts.length) },
        {
          label: "Mixed content",
          value: String(d.mixedContent.length),
          tone: d.mixedContent.length > 0 ? "tone-fail" : undefined,
        },
        { label: "Scripts without SRI", value: String(d.missingSri) },
      ];
    }

    case "markup": {
      const d = data as MarkupData;
      return [
        {
          label: "Title",
          value: d.title ? `${d.title} (${d.titleLength})` : "missing",
        },
        {
          label: "Description",
          value: d.description ? `${d.descriptionLength} characters` : "missing",
        },
        { label: "Language", value: d.lang ?? "not declared" },
        {
          label: "Headings",
          value: list(
            Object.entries(d.headingCounts ?? {}).map(([level, n]) => `h${level} ${n}`),
            3
          ),
        },
        {
          label: "Images without alt",
          value: `${d.images.missingAlt} of ${d.images.total}`,
          tone: d.images.missingAlt > 0 ? "tone-warn" : undefined,
        },
      ];
    }

    case "seo": {
      const d = data as SeoData;
      return [
        {
          label: "robots.txt",
          value: d.robotsTxt.found
            ? `${d.robotsTxt.status}${d.robotsTxt.disallowAll ? ", blocks everything" : ""}`
            : "not found",
        },
        {
          label: "Sitemap",
          value: d.sitemap.found
            ? `${d.sitemap.urlCount.toLocaleString("en-US")} URLs${d.sitemap.isIndex ? ", as an index" : ""}`
            : "not found",
        },
        { label: "Canonical matches", value: yesNo(d.canonicalMatches) },
        { label: "Open Graph", value: `${Object.keys(d.og ?? {}).length} tags` },
        {
          label: "Structured data",
          value: d.hasStructuredData ? list(d.structuredTypes, 2) : "none",
        },
      ];
    }

    case "performance": {
      const d = data as PerformanceData;
      return [
        { label: "Document", value: bytes(d.documentBytes) },
        {
          label: "Resources",
          value: `${d.requests.scripts} scripts, ${d.requests.stylesheets} styles, ${d.requests.images} images`,
        },
        {
          label: "Render blocking",
          value: `${d.renderBlocking.scripts} scripts, ${d.renderBlocking.stylesheets} styles`,
          tone:
            d.renderBlocking.scripts + d.renderBlocking.stylesheets > 0 ? "tone-warn" : undefined,
        },
        { label: "Compression", value: d.encoding ?? "none advertised" },
        { label: "DOM nodes", value: d.domNodes.toLocaleString("en-US") },
      ];
    }

    case "dark-patterns": {
      const d = data as DarkPatternData;
      return [
        {
          label: "Rules triggered",
          value: d.detected.length > 0 ? list(d.detected.map((r) => r.rule), 3) : "none",
        },
        { label: "Pre-checked boxes", value: String(d.checkedBoxes) },
        { label: "Forms", value: String(d.forms) },
        { label: "Dialogs", value: String(d.dialogs) },
      ];
    }

    default:
      return [];
  }
}

/* ------------------------------------------------------------------ entry -- */

/**
 * Rendered inside a check's box. Returns nothing when the check has no payload,
 * so a caller can place it unconditionally.
 */
export function CheckFacts({ result }: { result: CheckResult }) {
  if (!result.data) return null;
  const rows = factsFor(result.id, result.data);
  if (rows.length === 0) return null;

  return (
    <dl className="facts">
      {rows.map((row, index) => (
        <div key={`${row.label}-${index}`} style={{ display: "contents" }}>
          <dt>{row.label}</dt>
          <dd className={row.tone}>{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}
