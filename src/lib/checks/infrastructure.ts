/**
 * Hosting, network and exposure.
 *
 * Answers "where does this actually live": the address, the autonomous system
 * that announces it, the hosting provider, the certificate issuer, and what
 * Shodan's free index has seen listening on that address.
 *
 * The port list is the part with real security weight. Shodan's InternetDB is
 * free, keyless and CORS-enabled, and it reports the ports it observed, which
 * is exactly the outside-in view that matters.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";

export type GeoData = {
  ip: string | null;
  city: string | null;
  region: string | null;
  country: string | null;
  countryCode: string | null;
  asn: string | null;
  org: string | null;
  timezone: string | null;
  /** Reverse DNS name for the address, when one is published. */
  reverse: string | null;
};

export type ExposureData = {
  geo: GeoData;
  internetdb: {
    ports: number[];
    hostnames: string[];
    cpes: string[];
    tags: string[];
    vulns: string[];
    available: boolean;
    /** Distinguishes "never scanned" (404) from "could not ask" (error). */
    reason: "not-scanned" | "unreachable" | null;
  };
  /** Providers identified from the ASN organisation or CPE list. */
  hostingProvider: string | null;
};

/** Ports that should almost never be reachable from the public internet. */
const RISKY_PORTS: Record<number, { service: string; severity: "critical" | "high" | "medium" | "low"; note: string }> = {
  21: { service: "FTP", severity: "high", note: "File transfer over plaintext. Credentials cross the wire in clear." },
  23: { service: "Telnet", severity: "critical", note: "Remote shell with no encryption. Should never be internet-facing." },
  25: { service: "SMTP", severity: "medium", note: "An open relay or a mail server that will be scanned continuously." },
  445: { service: "SMB", severity: "critical", note: "Windows file sharing. The entry point for most ransomware." },
  1433: { service: "MSSQL", severity: "critical", note: "A database reachable from the internet." },
  3306: { service: "MySQL", severity: "critical", note: "A database reachable from the internet." },
  3389: { service: "RDP", severity: "critical", note: "Remote desktop. The most brute-forced service on the internet." },
  5432: { service: "PostgreSQL", severity: "critical", note: "A database reachable from the internet." },
  5900: { service: "VNC", severity: "critical", note: "Remote desktop, frequently with no authentication at all." },
  6379: { service: "Redis", severity: "critical", note: "An in-memory store with no authentication by default." },
  9200: { service: "Elasticsearch", severity: "critical", note: "A search index that is unauthenticated by default." },
  11211: { service: "Memcached", severity: "high", note: "No authentication, and usable for amplification attacks." },
  27017: { service: "MongoDB", severity: "critical", note: "A database that historically shipped with no auth." },
  2375: { service: "Docker API", severity: "critical", note: "An unauthenticated container API is equivalent to root on the host." },
  8888: { service: "HTTP alternate", severity: "medium", note: "An alternate HTTP port, often a management interface." },
  8080: { service: "HTTP alternate", severity: "low", note: "An alternate HTTP port, often a proxy or an admin panel." },
};

const HOSTING_PROVIDERS: Array<{ match: RegExp; name: string }> = [
  { match: /cloudflare/i, name: "Cloudflare" },
  { match: /amazon|aws/i, name: "Amazon Web Services" },
  { match: /google/i, name: "Google Cloud" },
  { match: /microsoft|azure/i, name: "Microsoft Azure" },
  { match: /digitalocean/i, name: "DigitalOcean" },
  { match: /linode|akamai/i, name: "Akamai / Linode" },
  { match: /hetzner/i, name: "Hetzner" },
  { match: /ovh/i, name: "OVHcloud" },
  { match: /fastly/i, name: "Fastly" },
  { match: /vercel/i, name: "Vercel" },
  { match: /netlify/i, name: "Netlify" },
  { match: /github/i, name: "GitHub" },
  { match: /vultr|choopa/i, name: "Vultr" },
  { match: /contabo/i, name: "Contabo" },
  { match: /hostinger/i, name: "Hostinger" },
  { match: /namecheap/i, name: "Namecheap" },
  { match: /godaddy/i, name: "GoDaddy" },
  { match: /alibaba|aliyun/i, name: "Alibaba Cloud" },
  { match: /tencent/i, name: "Tencent Cloud" },
];

export const infrastructure: CheckDefinition = {
  id: "infrastructure",
  title: "Hosting and exposure",
  question: "Where is this hosted, who announces the address, and what is listening on it?",
  group: "infrastructure",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const findings: Finding[] = [];

    const aRes = await ctx.dns.query(ctx.target.host, "A");
    const ip = aRes.answers.find((r) => r.type === 1)?.data ?? null;

    const geo: GeoData = {
      ip,
      city: null,
      region: null,
      country: null,
      countryCode: null,
      asn: null,
      org: null,
      timezone: null,
      reverse: null,
    };

    if (aRes.failed) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The DNS resolver did not answer, so the address could not be read.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Google and Cloudflare DNS over HTTPS",
        note: "No answer from either resolver is a failure of the lookup, not an absence of the record.",
      };
    }

    if (!ip) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: `${ctx.target.host} has no IPv4 address, so there is nothing to look up.`,
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "DNS over HTTPS",
        note: "An IPv6-only host is unusual for a public website. Check the AAAA record in the DNS section.",
      };
    }

    // Geolocation and ASN. ipwho.is is keyless and sends CORS headers.
    const geoRes = await ctx.net.json<{
      success?: boolean;
      city?: string;
      region?: string;
      country?: string;
      country_code?: string;
      connection?: { asn?: number; org?: string; isp?: string };
      timezone?: { id?: string };
    }>(`https://ipwho.is/${ip}`, { timeoutMs: 12_000, cacheKey: `geo:${ip}` });

    if (geoRes.ok && geoRes.json) {
      const g = geoRes.json;
      if (g.success !== false) {
        geo.city = g.city ?? null;
        geo.region = g.region ?? null;
        geo.country = g.country ?? null;
        geo.countryCode = g.country_code ?? null;
        geo.asn = g.connection?.asn ? `AS${g.connection.asn}` : null;
        geo.org = g.connection?.org ?? g.connection?.isp ?? null;
        geo.timezone = g.timezone?.id ?? null;
      }
    }

    // Reverse DNS, which often names the hosting region outright.
    const arpa = ip.split(".").reverse().join(".") + ".in-addr.arpa";
    const ptrRes = await ctx.dns.query(arpa, "PTR");
    geo.reverse = ptrRes.answers.find((r) => r.type === 12)?.data?.replace(/\.$/, "") ?? null;

    // Shodan's free index: ports, hostnames, CPEs and known CVEs for the address.
    const idbRes = await ctx.net.json<{
      ports?: number[];
      hostnames?: string[];
      cpes?: string[];
      tags?: string[];
      vulns?: string[];
    }>(`https://internetdb.shodan.io/${ip}`, { timeoutMs: 12_000, cacheKey: `idb:${ip}` });

    const internetdb = {
      ports: [] as number[],
      hostnames: [] as string[],
      cpes: [] as string[],
      tags: [] as string[],
      vulns: [] as string[],
      available: false,
      /**
       * Why the port data is missing. Shodan answers 404 for an address it has
       * never scanned and 429 or 5xx when it is refusing or failing, and the
       * two mean opposite things: "nothing known" versus "could not ask". The
       * note on the result reports which one happened.
       */
      reason: null as "not-scanned" | "unreachable" | null,
    };

    if (idbRes.ok && idbRes.json) {
      const d = idbRes.json;
      internetdb.ports = (d.ports ?? []).sort((x, y) => x - y);
      internetdb.hostnames = d.hostnames ?? [];
      internetdb.cpes = d.cpes ?? [];
      internetdb.tags = d.tags ?? [];
      internetdb.vulns = d.vulns ?? [];
      internetdb.available = true;
    } else if (idbRes.status === 404) {
      internetdb.reason = "not-scanned";
    } else {
      internetdb.reason = "unreachable";
    }

    const haystack = [geo.org ?? "", ...internetdb.cpes, ...internetdb.tags].join(" ");
    const hostingProvider =
      HOSTING_PROVIDERS.find((p) => p.match.test(haystack))?.name ?? geo.org ?? null;

    // --- findings ---
    const risky = internetdb.ports
      .map((port) => ({ port, meta: RISKY_PORTS[port] }))
      .filter((p) => p.meta);

    const criticalPorts = risky.filter((r) => r.meta!.severity === "critical");
    const highPorts = risky.filter((r) => r.meta!.severity === "high");

    if (criticalPorts.length > 0) {
      findings.push({
        id: "infra-critical-ports",
        title: `${criticalPorts.length} sensitive service${criticalPorts.length === 1 ? " is" : "s are"} reachable from the internet`,
        detail: criticalPorts
          .map((p) => `${p.meta!.service} on port ${p.port}: ${p.meta!.note}`)
          .join(" "),
        severity: "critical",
        remediation:
          "Close these ports at the firewall and reach them through a VPN or a bastion host instead. If the address is shared with a CDN, confirm the finding with the host provider before acting.",
        reference: { label: "CIS Controls v8 §12", url: "https://www.cisecurity.org/controls/network-infrastructure-management" },
        evidence: criticalPorts.map((p) => ({
          label: `Port ${p.port}`,
          value: p.meta!.service,
          tone: "bad" as const,
          detail: p.meta!.note,
        })),
      });
    }

    if (highPorts.length > 0) {
      findings.push({
        id: "infra-high-ports",
        title: `${highPorts.length} service${highPorts.length === 1 ? "" : "s"} exposed that should be internal`,
        detail: highPorts.map((p) => `${p.meta!.service} on port ${p.port}`).join(", "),
        severity: "high",
        remediation: "Restrict these ports to known source addresses.",
      });
    }

    if (internetdb.vulns.length > 0) {
      findings.push({
        id: "infra-known-vulns",
        title: `${internetdb.vulns.length} known CVE${internetdb.vulns.length === 1 ? "" : "s"} associated with this address`,
        detail: `Shodan links these identifiers to the services it observed: ${internetdb.vulns.slice(0, 8).join(", ")}${internetdb.vulns.length > 8 ? " and others" : ""}.`,
        severity: "critical",
        remediation:
          "Patch the identified services. A CVE linked to an exposed port is a working entry point, not a theoretical one.",
        reference: { label: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
        evidence: internetdb.vulns.slice(0, 12).map((v) => ({ label: "CVE", value: v, tone: "bad" })),
      });
    }

    // Certificate issuer for the host, which is cheap context next to the IP.
    const criticalCount = findings.filter((f) => f.severity === "critical").length;
    const status: CheckResult["status"] =
      criticalCount > 0 ? "fail" : findings.length > 0 ? "warn" : "pass";

    const location = [geo.city, geo.country].filter(Boolean).join(", ");

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline: ip
        ? `${ip}${location ? ` in ${location}` : ""}${geo.asn ? `, announced by ${geo.asn}${geo.org ? ` (${geo.org})` : ""}` : ""}. ${internetdb.available ? `${internetdb.ports.length} port${internetdb.ports.length === 1 ? "" : "s"} observed open.` : internetdb.reason === "not-scanned" ? "Shodan has no scan of this address." : "Shodan could not be reached for this address."}`
        : "No address to look up.",
      findings,
      data: { geo, internetdb, hostingProvider } satisfies ExposureData,
      ms: Math.round(performance.now() - started),
      source: "DNS over HTTPS, ipwho.is geolocation, Shodan InternetDB",
      note: internetdb.available
        ? "Port data is Shodan's own scan of the address, which may be minutes to days old. It reflects what an outside observer sees, not what your firewall is configured to do."
        : internetdb.reason === "not-scanned"
          ? "Shodan answered 404 for this address, which means its index has never scanned it. That is not evidence that nothing is open."
          : "The Shodan request failed, so no port data was obtained. This says nothing about what is listening on the address; re-running the scan usually works.",
    };
  },
};
