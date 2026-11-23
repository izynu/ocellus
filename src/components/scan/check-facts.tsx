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
import type { DnsAliasesData } from "@/lib/checks/dns-aliases";
import type { NameserversData } from "@/lib/checks/nameservers";
import type { CtData } from "@/lib/checks/ct-logs";
import type { CertificateRevocationData } from "@/lib/checks/certificate-revocation";
import type { RedirectsData } from "@/lib/checks/redirects";
import type { HeadersData } from "@/lib/checks/security-headers";
import type { EdgeProtectionData } from "@/lib/checks/edge-protection";
import type { EmailData } from "@/lib/checks/email-auth";
import type { SecurityTxtData } from "@/lib/checks/security-txt";
import type { ExposureData } from "@/lib/checks/infrastructure";
import type { CohostedData } from "@/lib/checks/cohosted";
import type { VulnExposureData } from "@/lib/checks/vulnerability-exposure";
import type { SubdomainsData } from "@/lib/checks/subdomains";
import type { TechStackData } from "@/lib/checks/tech-stack";
import type { ThreatIntelData } from "@/lib/checks/threat-intel";
import type { MalwareListingsData } from "@/lib/checks/malware-listings";
import type { BlocklistData } from "@/lib/checks/blocklist";
import type { BreachData } from "@/lib/checks/breach-history";
import type { ArchiveData } from "@/lib/checks/archive-history";
import type { PopularityData } from "@/lib/checks/popularity";
import type { PrivacyData } from "@/lib/checks/privacy";
import type { MarkupData } from "@/lib/checks/markup";
import type { SeoData } from "@/lib/checks/seo";
import type { PerformanceData } from "@/lib/checks/performance";
import type { CarbonData } from "@/lib/checks/carbon";
import type { DarkPatternData } from "@/lib/checks/dark-patterns";
import type { ReconSubdomainsData } from "@/lib/checks/recon-subdomains";
import type { UrlScanData } from "@/lib/checks/url-scan";

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

/** "1 script", "3 scripts". A bare number reads as a bug when it is a one. */
function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
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

    case "dns-aliases": {
      const d = data as DnsAliasesData;
      const internal = d.srv.filter((r) => r.internalLooking).length;
      return [
        {
          label: "CNAME",
          // The target is the fact worth showing, not just "yes". Where the
          // host is really served from is the whole answer to the first
          // question, and a reader who sees only "yes" has to open the
          // evidence list to learn it.
          value: d.cname.target ?? "none, served from its own name",
        },
        {
          label: "Leaves the domain",
          // A host with no CNAME has nothing to leave, so the row says that
          // rather than "not reported". The two read completely differently:
          // one is a fact about the host, the other looks like a gap in the
          // scan, and a reader has no way to tell them apart from the word
          // alone.
          value: d.cname.present ? yesNo(d.cname.leavesDomain) : "no alias to leave",
        },
        {
          label: "Service records",
          value:
            d.srv.length === 0
              ? "none"
              : `${d.srv.length}${internal > 0 ? `, ${internal} to an internal name` : ""}`,
          tone: internal > 0 ? "tone-warn" : undefined,
        },
      ];
    }

    case "nameservers": {
      const d = data as NameserversData;
      // The networks are the point of this check, so they get a row rather
      // than being left to the evidence list. A zone delegated to two servers
      // on one AS is a different fact from two on separate ASes, and only the
      // ASN column shows which it is.
      const networks = [...new Set(d.nameservers.map((n) => n.asn).filter((a): a is string => Boolean(a)))];
      return [
        { label: "Nameservers", value: plural(d.count, "server") },
        {
          label: "Networks",
          value:
            networks.length === 0
              ? "none identified"
              : networks.length <= 2
                ? networks.join(", ")
                : `${networks.slice(0, 2).join(", ")} and ${networks.length - 2} more`,
        },
        {
          label: "DNS separate from site",
          // Three outcomes, not two: independent, shared, and not determinable.
          // A "no" here would read as a defect when it often means the
          // provider simply hosts both, so the undetermined case says so.
          value:
            d.independentDns
              ? "yes"
              : d.siteAsn === null
                ? "not determinable"
                : "shared network",
          tone: d.independentDns ? "tone-pass" : undefined,
        },
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
          // Only certificates issued after the 2020 cap are eligible, so the
          // label names that population. A bare "Longest validity" invited the
          // reader to compare it against a 2015 ten-year certificate.
          label: "Longest since 2020",
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
          // A wildcard under _domainkey makes every selector resolve, so the
          // selector list carries no information: it is one record echoed back
          // for names nobody uses. Printing "none found" would be wrong too,
          // because the zone does answer, so the row states what is actually
          // there and why the per-selector list is empty.
          value: d.wildcard
            ? "wildcard, no per-selector key"
            : dkim.length > 0
              ? list(dkim, 3)
              : "none found",
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
      const located = Boolean(d.geo.asn || d.geo.org || d.geo.city || d.geo.country);
      const location = [d.geo.city, d.geo.country].filter(Boolean).join(", ");
      // The geolocation source rate limits by IP, so a null here is usually a
      // 429 rather than an address with no owner. Saying so is better than
      // printing four empty rows, which read as though the address is unknown.
      return [
        { label: "Address", value: <span className="mono">{d.geo.ip ?? NONE}</span> },
        located
          ? { label: "Network", value: d.geo.asn ?? NONE }
          : { label: "Network", value: "the geolocation source did not answer" },
        ...(located
          ? [
              { label: "Organisation", value: d.geo.org ?? NONE },
              { label: "Location", value: location || NONE },
            ]
          : []),
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

    case "cohosted": {
      const d = data as CohostedData;
      // "1 domains" beside "10 hostnames" makes a reader doubt both numbers.
      const domains = (n: number): string => `${n} domain${n === 1 ? "" : "s"}`;
      return [
        { label: "Address", value: <span className="mono">{d.ip ?? NONE}</span> },
        {
          label: "Other hostnames",
          // The record count and the deduplicated count differ, and only the
          // second is the number of names. Printing the raw count would inflate
          // it, so the cap is shown as the reason rather than as the value.
          value:
            d.totalHostnames === 0
              ? "none recorded"
              : d.cappedAt500
                ? `${d.totalHostnames} or more, at the cap`
                : String(d.totalHostnames),
        },
        {
          label: "Unrelated to this site",
          // A shared edge and a small box both have unrelated neighbours, so the
          // verdict is what separates them. Saying only the count invites the
          // reader to treat a CDN edge as a cluster of compromised neighbours.
          // Neither case carries a warning tone: the check itself reports no
          // finding, because sharing an address is not a defect, and a colour
          // here would contradict the sentence the check wrote.
          value:
            d.unrelatedCount === 0
              ? "none"
              : d.sharedAddress
                ? `${domains(d.unrelatedDomains)}, on a shared edge`
                : d.cdnTagged
                  ? `${domains(d.unrelatedDomains)}, on a CDN edge`
                  : `${domains(d.unrelatedDomains)}, on a small address`,
        },
        { label: "Network", value: d.network ?? NONE },
        {
          // Which sources actually answered changes how much the list above can
          // be trusted, so it is a row rather than a footnote.
          label: "Sources",
          value: d.otxAnswered ? (d.fromInternetDb > 0 ? "OTX and Shodan" : "OTX") : "Shodan only",
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
          value: d.catalogSize
            ? `${d.catalogSize.toLocaleString("en-US")} entr${d.catalogSize === 1 ? "y" : "ies"}`
            : NONE,
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
      const count = d.items.length;
      return [
        {
          label: "Detected",
          // "1 technologies" was shipped, which is the kind of thing a reader
          // notices immediately and then distrusts the rest of the page for.
          value: `${count} ${count === 1 ? "technology" : "technologies"}`,
        },
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
      const validations = Array.from(new Set(d.validations.map((v) => v.name)));
      return [
        { label: "Pulses", value: String(d.pulses) },
        {
          label: "Tags",
          // The tags are free text and most of them are ingestion noise: dates,
          // street addresses, file-format words. Taking the first three after a
          // sort prints exactly that noise, so this row reports how many there
          // are and leaves the ranking to the finding, which filters first.
          value:
            d.tags.length === 0
              ? "none"
              : `${d.tags.length.toLocaleString("en-US")} distinct, ranked in the finding`,
        },
        { label: "Whitelisted", value: yesNo(d.whitelisted) },
        {
          label: "Corroborated by",
          value: validations.length > 0 ? list(validations, 3) : "no one",
        },
      ];
    }

    case "malware-listings": {
      const d = data as MalwareListingsData;
      const listed = d.sources.filter((s) => s.outcome === "listed");
      return [
        {
          label: "Feeds answered",
          // The denominator is the point. "1 of 3" and "3 of 3" are a partial
          // and a complete answer to the same question, and a bare count of
          // listings would not distinguish them.
          value: `${d.answeredCount} of ${d.totalSources}`,
          tone: d.answeredCount === d.totalSources ? undefined : "tone-warn",
        },
        {
          label: "Listing this site",
          value: listed.length === 0 ? "none" : list(listed.map((s) => s.name), 2),
          tone: listed.length > 0 ? "tone-warn" : undefined,
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
      // "not reported" for a first capture reads as a fact about the archive.
      // When the query itself failed the archive never said anything, and the
      // row has to distinguish that from a site that genuinely has one capture.
      return [
        {
          label: "First capture",
          value: d.firstQueryFailed ? "the archive did not answer" : date(d.firstCapture),
        },
        {
          label: "Latest capture",
          value: d.lastQueryFailed ? "the archive did not answer" : date(d.lastCapture),
        },
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
        {
          // Distinct hosts, not link count. A nav bar repeats one host many
          // times, so the count says nothing about where the page points.
          label: "Links out to",
          value:
            d.linkedHosts && d.linkedHosts.externalCount > 0
              ? list(d.linkedHosts.external, 3)
              : "no other host",
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
          value: plural(d.requests.scripts, "script") + ", " + plural(d.requests.stylesheets, "stylesheet") + ", " + plural(d.requests.images, "image"),
        },
        {
          label: "Render blocking",
          value: plural(d.renderBlocking.scripts, "script") + ", " + plural(d.renderBlocking.stylesheets, "stylesheet"),
          tone:
            d.renderBlocking.scripts + d.renderBlocking.stylesheets > 0 ? "tone-warn" : undefined,
        },
        { label: "Compression", value: d.encoding ?? "none advertised" },
        { label: "DOM nodes", value: d.domNodes.toLocaleString("en-US") },
      ];
    }

    case "carbon": {
      const d = data as CarbonData;
      return [
        {
          // "0 g" on its own reads as a measurement. The model's zero is its
          // floor for a page light enough to round down, so the value says so
          // rather than letting the reader take it literally.
          label: "CO2 per view",
          value:
            d.gramsPerView === null
              ? NONE
              : d.belowFloor
                ? "0 g, at the model's floor"
                : `${d.gramsPerView.toFixed(2)} g`,
        },
        {
          // The percentile counts pages that are dirtier, so 99 is good. A
          // bare "99" beside a defect list would be read as a near-fail, so
          // the label carries the direction instead of the number alone.
          label: "Cleaner than",
          value:
            d.cleanerThanPercent === null
              ? NONE
              : `${d.cleanerThanPercent.toFixed(0)}% of pages measured`,
        },
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

    case "recon-subdomains": {
      const d = data as ReconSubdomainsData;
      return [
        { label: "Hostnames", value: d.hostnames.length.toLocaleString("en-US") },
        {
          label: "Sources",
          // Both source names must show, not just the first two of a list: a
          // reader needs to know whether one answered or both, because one
          // answer is a partial surface and the check's note says so.
          value: d.sourcesAnswered.length > 0 ? d.sourcesAnswered.join(", ") : "none answered",
        },
        {
          label: "Look internal",
          value: d.sensitive.length > 0 ? list(d.sensitive, 3) : "none",
          tone: d.sensitive.length > 0 ? "tone-warn" : undefined,
        },
        { label: "With an address", value: String(d.withAddress.length) },
      ];
    }

    case "url-scan": {
      const d = data as UrlScanData;
      const latest = d.captures[0];
      return [
        { label: "Address", value: <span className="mono">{d.ip ?? NONE}</span> },
        {
          label: "Reverse name",
          value: d.reverseNames.length > 0 ? list(d.reverseNames, 2) : "none published",
        },
        {
          label: "Shares the address",
          value:
            d.neighbours.length > 0
              ? `${d.neighbours.length} hostname${d.neighbours.length === 1 ? "" : "s"}`
              : "none recorded",
        },
        {
          label: "Prior urlscan captures",
          value: d.captureCount > 0 ? d.captureCount.toLocaleString("en-US") : "none",
        },
        ...(latest
          ? [
              { label: "Latest capture", value: date(latest.time) },
              { label: "Latest title", value: latest.title },
            ]
          : []),
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
 *
 * The payload is cast per check id, which is sound when the report was produced
 * by this build. It is not sound when the report was restored from
 * `sessionStorage`, where a report written by an older build can carry a
 * payload whose fields have since been renamed or dropped. One missing array
 * would throw during render and blank the whole report, so a failed projection
 * degrades to no fact list rather than to no report.
 */
export function CheckFacts({ result }: { result: CheckResult }) {
  if (!result.data) return null;

  let rows: Fact[];
  try {
    rows = factsFor(result.id, result.data);
  } catch {
    return null;
  }
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
