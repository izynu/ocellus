/**
 * Shodan, for the visitor who brought a key.
 *
 * The keyless Shodan InternetDB index (the `infrastructure` check) answers
 * about ports and CVE ids only. The full host record is much richer: product
 * and version banners, the organisation, the operating system, hostnames and
 * tags. That endpoint requires a key, which a static page cannot ship, so this
 * check runs only when the visitor has stored one.
 *
 * `api.shodan.io` sends `Access-Control-Allow-Origin: *`, verified with a
 * preflight on 23 November 2026, so the browser can read the response directly.
 * The key travels as a query parameter in the service's own documented form.
 * It is never logged, returned in the payload, or written into the report.
 *
 * With no key the check reports `unavailable` and says exactly that. It does
 * not skip, because a skipped check and a passing check look identical in a
 * summary that does not explain itself.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";
import { readKey } from "../scan/keys";

type ShodanHost = {
  ip_str?: string;
  org?: string;
  isp?: string;
  os?: string | null;
  asn?: string;
  country_name?: string;
  city?: string;
  hostnames?: string[];
  domains?: string[];
  ports?: number[];
  tags?: string[];
  vulns?: string[];
  data?: Array<{
    port?: number;
    transport?: string;
    product?: string;
    version?: string;
    cpe?: string[];
    banner?: string;
    http?: { title?: string; server?: string };
  }>;
};

export type ShodanHostData = {
  ip: string | null;
  org: string | null;
  isp: string | null;
  os: string | null;
  asn: string | null;
  location: string | null;
  ports: number[];
  banners: Array<{ port: number; product: string; version: string; title: string | null }>;
  tags: string[];
  vulns: string[];
  hostnames: string[];
};

/** Products whose presence on the public internet is worth a specific warning. */
const SENSITIVE_PORTS: Record<number, string> = {
  22: "SSH",
  23: "Telnet",
  445: "SMB",
  1433: "Microsoft SQL Server",
  1521: "Oracle database",
  2375: "an unauthenticated Docker daemon",
  3306: "MySQL",
  3389: "Remote Desktop",
  5432: "PostgreSQL",
  5900: "VNC",
  6379: "Redis",
  9200: "Elasticsearch",
  11211: "Memcached",
  27017: "MongoDB",
};

export const shodanHost: CheckDefinition = {
  id: "shodan-host",
  title: "Shodan host record",
  question: "What does the full Shodan record say about the address, beyond the free index?",
  group: "infrastructure",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const empty: ShodanHostData = {
      ip: null,
      org: null,
      isp: null,
      os: null,
      asn: null,
      location: null,
      ports: [],
      banners: [],
      tags: [],
      vulns: [],
      hostnames: [],
    };

    const key = readKey("shodan");
    if (!key) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "No Shodan key is stored, so the full host record was not queried.",
        findings: [],
        data: empty,
        ms: Math.round(performance.now() - started),
        source: "api.shodan.io (key required)",
        note: "Add a Shodan key in the key panel to read the full host record. The keyless InternetDB index still answers the port question in the Hosting and exposure check.",
      };
    }

    const aRes = await ctx.dns.query(ctx.target.host, "A");
    const ip = aRes.answers.find((r) => r.type === 1)?.data ?? null;
    if (!ip) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The host did not resolve to an address, so there was nothing to look up.",
        findings: [],
        data: empty,
        ms: Math.round(performance.now() - started),
        source: "api.shodan.io (key required)",
        note: aRes.failed
          ? "The DNS resolver did not answer, so no address could be read. This is not evidence that the host has no address."
          : "The name resolved to no A record.",
      };
    }

    const res = await ctx.net.json<ShodanHost>(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`,
      { timeoutMs: 25_000, cacheKey: `shodan-host:${ip}` }
    );

    if (!res.ok) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: describeFailure(res, "Shodan"),
        findings: [],
        data: { ...empty, ip },
        ms: Math.round(performance.now() - started),
        source: "api.shodan.io (key required)",
        note:
          res.status === 401
            ? "Shodan rejected the stored key. Replace it in the key panel."
            : "Shodan did not answer, so no claim is made about the address. This is not a clean result.",
      };
    }

    const body = res.json as ShodanHost;
    const ports = [...new Set(body.ports ?? [])].sort((a, b) => a - b);
    const banners = (body.data ?? [])
      .filter((d) => typeof d.port === "number")
      .map((d) => ({
        port: d.port as number,
        product: d.product ?? "",
        version: d.version ?? "",
        title: d.http?.title ?? null,
      }))
      .filter((d) => d.product || d.title);

    const data: ShodanHostData = {
      ip: body.ip_str ?? ip,
      org: body.org ?? null,
      isp: body.isp ?? null,
      os: body.os ?? null,
      asn: body.asn ?? null,
      location: [body.city, body.country_name].filter(Boolean).join(", ") || null,
      ports,
      banners: banners.slice(0, 30),
      tags: body.tags ?? [],
      vulns: body.vulns ?? [],
      hostnames: (body.hostnames ?? []).slice(0, 40),
    };

    const findings: Finding[] = [];

    const exposed = ports.filter((p) => SENSITIVE_PORTS[p] !== undefined);
    if (exposed.length > 0) {
      findings.push({
        id: "shodan-sensitive-port",
        title: `${exposed.length} port${exposed.length === 1 ? "" : "s"} on the public internet serve a service that is usually internal`,
        detail: `${exposed.map((p) => `${p} (${SENSITIVE_PORTS[p]})`).join(", ")} ${exposed.length === 1 ? "is" : "are"} reachable according to Shodan. A database, a remote shell or a container API on a public address is a direct target.`,
        severity: "high",
        remediation:
          "Bind the service to localhost or an internal interface, or put it behind a VPN and a firewall rule. If it must be public, restrict it by source address and require authentication.",
        reference: {
          label: "OWASP: Security Misconfiguration",
          url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        },
        evidence: exposed.map((p) => ({ label: `Port ${p}`, value: SENSITIVE_PORTS[p], tone: "bad" as const })),
      });
    }

    if (data.vulns.length > 0) {
      findings.push({
        id: "shodan-vulns",
        title: `Shodan associates ${data.vulns.length} CVE${data.vulns.length === 1 ? "" : "s"} with the services it saw`,
        detail: `The index lists ${data.vulns.slice(0, 6).join(", ")}${data.vulns.length > 6 ? " and others" : ""} against the banners it recorded. These are matches on a version string, not a confirmed exploit, so they rank what to patch first rather than proving the host is vulnerable.`,
        severity: "medium",
        remediation:
          "Read each CVE against the exact product and version from the banner, patch what applies, and re-check after the upgrade.",
        reference: {
          label: "CISA: Known Exploited Vulnerabilities catalog",
          url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        },
        evidence: data.vulns.slice(0, 10).map((cve) => ({ label: "CVE", value: cve })),
      });
    }

    const status: CheckResult["status"] =
      findings.some((f) => f.severity === "critical" || f.severity === "high")
        ? "fail"
        : findings.length > 0
          ? "warn"
          : "pass";

    const headline =
      ports.length === 0
        ? `Shodan holds no port record for ${ip}.`
        : `${ip} exposes ${ports.length} port${ports.length === 1 ? "" : "s"}${data.org ? ` in ${data.org}` : ""}${banners.length > 0 ? `; ${banners.length} service banner${banners.length === 1 ? "" : "s"} readable` : ""}${data.vulns.length > 0 ? `, and ${data.vulns.length} CVE${data.vulns.length === 1 ? "" : "s"} matched` : ""}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data,
      ms: Math.round(performance.now() - started),
      source: "api.shodan.io (key required)",
      note: "Shodan records a crawl at an earlier moment, not a scan of the host now. A port listed here may have closed since, and one opened since may be missing.",
    };
  },
};
