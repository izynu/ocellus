/**
 * The DNS record set for a domain, read over DoH.
 *
 * This is the parent check for everything name-shaped: the email checks read
 * its TXT records, the infrastructure check reads its A record, and the report
 * shows the whole zone as a table.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { DNS_NXDOMAIN, unquoteTxt } from "../net/dns";

export type DnsRecord = {
  type: string;
  name: string;
  value: string;
  ttl: number;
};

export type DnsData = {
  records: DnsRecord[];
  counts: Record<string, number>;
  nameservers: string[];
  mailServers: Array<{ priority: number; host: string }>;
  addresses: string[];
  soa: { primary: string; admin: string; serial: string } | null;
  /** True when the zone answers DNSSEC validation (AD flag set). */
  dnssecValidated: boolean;
  provider: string;
};

export const dnsRecords: CheckDefinition = {
  id: "dns-records",
  title: "DNS records",
  question: "Which address, mail, name-server and text records does the zone publish?",
  group: "dns",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    const [a, aaaa, mx, ns, txt, soa, caa] = await Promise.all([
      ctx.dns.query(domain, "A"),
      ctx.dns.query(domain, "AAAA"),
      ctx.dns.query(domain, "MX"),
      ctx.dns.query(domain, "NS"),
      ctx.dns.query(domain, "TXT"),
      ctx.dns.query(domain, "SOA"),
      ctx.dns.query(domain, "CAA"),
    ]);

    if (a.status === DNS_NXDOMAIN) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "fail",
        headline: `${domain} does not resolve. The domain is not registered or has no DNS records.`,
        findings: [
          {
            id: "dns-nxdomain",
            title: "The domain does not exist in DNS",
            detail: `${domain} returned NXDOMAIN from the resolver, which means no records exist for it at all.`,
            severity: "critical",
            remediation: "Check the spelling, or register the domain before scanning it.",
          },
        ],
        ms: Math.round(performance.now() - started),
        source: a.provider,
      };
    }

    const records: DnsRecord[] = [];
    const push = (type: string, name: string, value: string, ttl: number) =>
      records.push({ type, name, value, ttl });

    for (const r of a.answers) if (r.type === 1) push("A", r.name, r.data, r.ttl);
    for (const r of aaaa.answers) if (r.type === 28) push("AAAA", r.name, r.data, r.ttl);
    for (const r of ns.answers) if (r.type === 2) push("NS", r.name, r.data, r.ttl);
    for (const r of caa.answers) if (r.type === 257) push("CAA", r.name, r.data, r.ttl);
    for (const r of txt.answers) if (r.type === 16) push("TXT", r.name, unquoteTxt(r.data), r.ttl);

    const mailServers: Array<{ priority: number; host: string }> = [];
    for (const r of mx.answers) {
      if (r.type !== 15) continue;
      // "10 mail.example.com."
      const [prio, host] = r.data.split(/\s+/);
      const clean = (host ?? "").replace(/\.$/, "");
      if (clean) {
        mailServers.push({ priority: Number(prio) || 0, host: clean });
        push("MX", r.name, `${prio} ${clean}`, r.ttl);
      }
    }

    const soaRecord = soa.answers.find((r) => r.type === 6);
    let soaValue: DnsData["soa"] = null;
    if (soaRecord) {
      // "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600"
      const parts = soaRecord.data.split(/\s+/);
      soaValue = {
        primary: (parts[0] ?? "").replace(/\.$/, ""),
        admin: (parts[1] ?? "").replace(/\.$/, ""),
        serial: parts[2] ?? "",
      };
      push("SOA", soaRecord.name, soaRecord.data, soaRecord.ttl);
    }

    const nameservers = ns.answers
      .filter((r) => r.type === 2)
      .map((r) => r.data.replace(/\.$/, ""))
      .sort();
    const addresses = a.answers.filter((r) => r.type === 1).map((r) => r.data);

    const counts: Record<string, number> = {};
    for (const r of records) counts[r.type] = (counts[r.type] ?? 0) + 1;

    const findings: Finding[] = [];

    if (nameservers.length === 1) {
      findings.push({
        id: "dns-single-ns",
        title: "Only one name server answers for the zone",
        detail: `${nameservers[0]} is the sole NS record. A single name server is a single point of failure for every record the domain publishes.`,
        severity: "high",
        remediation: "Publish at least two NS records, ideally with two different network providers.",
        reference: {
          label: "RFC 1034 §4.2.2",
          url: "https://datatracker.ietf.org/doc/html/rfc1034#section-4.2.2",
        },
      });
    }

    if (addresses.length === 0) {
      findings.push({
        id: "dns-no-a",
        title: "No A record on the apex",
        detail: `${domain} has no IPv4 address record. Browsers reaching the apex directly will fail unless a CNAME or redirect handles it.`,
        severity: "high",
        remediation: "Add an A record, or a CNAME where the apex allows it.",
      });
    }

    if (caa.answers.filter((r) => r.type === 257).length === 0) {
      findings.push({
        id: "dns-no-caa",
        title: "No CAA record",
        detail: `${domain} does not restrict which certificate authorities may issue for it. Any CA can issue a certificate that browsers will trust.`,
        severity: "medium",
        remediation:
          'Publish a CAA record naming your CA, for example: example.com. CAA 0 issue "letsencrypt.org"',
        reference: {
          label: "RFC 8659",
          url: "https://datatracker.ietf.org/doc/html/rfc8659",
        },
      });
    }

    const status: CheckResult["status"] =
      findings.some((f) => f.severity === "high" || f.severity === "critical")
        ? "fail"
        : findings.length
          ? "warn"
          : "pass";

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline: `${records.length} records across ${Object.keys(counts).length} types, served by ${nameservers.length} name server${nameservers.length === 1 ? "" : "s"}.`,
      findings,
      data: {
        records,
        counts,
        nameservers,
        mailServers: mailServers.sort((x, y) => x.priority - y.priority),
        addresses,
        soa: soaValue,
        dnssecValidated: a.authenticated,
        provider: a.provider,
      } satisfies DnsData,
      ms: Math.round(performance.now() - started),
      source: a.provider + " over DNS-over-HTTPS",
    };
  },
};
