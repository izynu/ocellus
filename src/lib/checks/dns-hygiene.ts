/**
 * The zone hygiene checks that sit next to the record set but are not the
 * record set.
 *
 * Three questions, all answerable from DoH with no extra service:
 *
 *  - Is there a wildcard A record, so every name under the domain resolves
 *    including the ones nobody registered?
 *  - Does the apex have an HTTPS or SVCB record that pins the protocol, and do
 *    the MX hosts advertise STARTTLS?
 *  - Are the mail exchangers' own forward and reverse records consistent, which
 *    is what a receiving mail server checks before it accepts a message?
 *
 * The last one is the one with real weight. A mismatch between the name an MX
 * resolves to and the name its address resolves back to is a textbook reason
 * for mail to be throttled or rejected, and it is invisible from the website
 * itself.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";

export type DnsHygieneData = {
  /** True when a random label under the domain resolves. */
  wildcard: { resolves: boolean; addresses: string[] };
  /** The apex HTTPS or SVCB record, when published. */
  httpsRecord: string | null;
  /** MX host to its forward addresses and its reverse name. */
  mailHosts: Array<{
    host: string;
    addresses: string[];
    reverse: string | null;
    /** True when the reverse name is the host itself or a name under the domain. */
    consistent: boolean;
  }>;
  /** STARTTLS advertisement from the MX hosts, as an _smtp._tls record would show. */
  tlsRpt: string | null;
};

/**
 * A label no one would register. If it resolves, the zone has a wildcard, and
 * that is a fact about the zone rather than about this particular name.
 */
const PROBE_LABEL = "ocellus-wildcard-probe";

export const dnsHygiene: CheckDefinition = {
  id: "dns-hygiene",
  title: "Zone hygiene",
  question: "Does the zone answer for names that do not exist, pin the protocol, and keep mail host records consistent?",
  group: "dns",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    // Every query below is for a different name or type, so they run together.
    const [wildA, wildAaaa, wildTxt, httpsRes, mxRes, tlsRptRes] = await Promise.all([
      ctx.dns.query(`${PROBE_LABEL}.${domain}`, "A"),
      ctx.dns.query(`${PROBE_LABEL}.${domain}`, "AAAA"),
      ctx.dns.query(`${PROBE_LABEL}.${domain}`, "TXT"),
      ctx.dns.query(domain, "HTTPS"),
      ctx.dns.query(domain, "MX"),
      ctx.dns.query(`_smtp._tls.${domain}`, "TXT"),
    ]);

    const failed = [wildA, wildAaaa, wildTxt, httpsRes, mxRes, tlsRptRes].some((r) => r.failed);
    if (failed) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The DNS resolver did not answer, so zone hygiene could not be judged.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Google and Cloudflare DNS over HTTPS",
        note: "No answer from either resolver is a failure of the lookup. It says nothing about whether the zone publishes a wildcard, an HTTPS record or consistent mail records.",
      };
    }

    // A wildcard is detected by an address or text answer for a label that was
    // never registered. A CNAME chain counts too, and DoH returns the CNAME in
    // the answer section alongside its target.
    const wildAddresses = [...wildA.answers, ...wildAaaa.answers]
      .filter((r) => r.type === 1 || r.type === 28)
      .map((r) => r.data);
    const wildcardResolves =
      wildAddresses.length > 0 || wildTxt.answers.some((r) => r.type === 16);

    const httpsRecord =
      httpsRes.answers.find((r) => r.type === 65)?.data ??
      null;

    // STARTTLS reporting: _smtp._tls is the TLS-RPT record. Its presence means
    // the domain wants reports about failed TLS to its mail hosts.
    const tlsRpt =
      tlsRptRes.answers
        .filter((r) => r.type === 16)
        .map((r) => r.data.replace(/^"|"$/g, ""))
        .find((v) => /^v=TLSRPTv1/i.test(v.trim())) ?? null;

    const mxHosts = mxRes.answers
      .filter((r) => r.type === 15)
      .map((r) => (r.data.split(/\s+/)[1] ?? "").replace(/\.$/, "").toLowerCase())
      .filter(Boolean);

    // Forward then reverse, for each mail host. This is the pair a receiving
    // server compares, and the queries are cheap because the resolver caches.
    const mailHosts: DnsHygieneData["mailHosts"] = [];
    for (const host of mxHosts.slice(0, 4)) {
      const fwd = await ctx.dns.query(host, "A");
      const addresses = fwd.answers.filter((r) => r.type === 1).map((r) => r.data);
      let reverse: string | null = null;
      if (addresses[0]) {
        const arpa = addresses[0].split(".").reverse().join(".") + ".in-addr.arpa";
        const ptr = await ctx.dns.query(arpa, "PTR");
        reverse = ptr.answers.find((r) => r.type === 12)?.data?.replace(/\.$/, "").toLowerCase() ?? null;
      }
      const consistent =
        reverse !== null &&
        (reverse === host || reverse.endsWith(`.${domain}`) || host.endsWith(`.${reverse}`));
      mailHosts.push({ host, addresses, reverse, consistent });
    }

    const findings: Finding[] = [];

    if (wildcardResolves) {
      findings.push({
        id: "dns-wildcard",
        title: "A wildcard record answers for names that were never registered",
        detail: `A query for ${PROBE_LABEL}.${domain} returned ${wildAddresses.length > 0 ? wildAddresses.slice(0, 3).join(", ") : "a text record"}. Every name under ${domain} therefore resolves, whether or not anyone created it. That is a legitimate design for a catch-all service and it is also how a typo-squatted subdomain or a credential-harvesting host on your domain starts working without anyone adding a record.`,
        severity: "low",
        remediation:
          "If the wildcard is deliberate, keep it. If it is not, remove it and add the specific names you need. Either way, a wildcard means the subdomain surface cannot be enumerated by trying names.",
      });
    }

    if (httpsRecord === null && ctx.target.scheme === "https") {
      findings.push({
        id: "dns-no-https-record",
        title: "The apex publishes no HTTPS record",
        detail: `An HTTPS or SVCB record at the apex tells a browser which protocols and endpoints the origin supports before it opens a connection, and it can carry the hints that let a client skip an insecure first attempt. ${domain} publishes none, so every client falls back to guessing from the A and AAAA records.`,
        severity: "info",
        remediation:
          'Publish an HTTPS record, for example: example.com. HTTPS 1 . alpn="h2,h3". This is a modern optimisation and not a defect, so it is reported as information.',
        reference: {
          label: "RFC 9460",
          url: "https://datatracker.ietf.org/doc/html/rfc9460",
        },
      });
    }

    const inconsistent = mailHosts.filter((h) => h.addresses.length > 0 && !h.consistent);
    if (inconsistent.length > 0) {
      findings.push({
        id: "dns-mx-ptr-mismatch",
        title: `${inconsistent.length} mail host${inconsistent.length === 1 ? "" : "s"} do not match their reverse record`,
        detail: inconsistent
          .map(
            (h) =>
              `${h.host} resolves to ${h.addresses[0]}, whose reverse name is ${h.reverse ?? "nothing"}.`
          )
          .join(" "),
        severity: "medium",
        remediation:
          "Ask the hosting provider to set the PTR record for the mail server address to the hostname the MX points at. Receiving servers use this pair as a reputation signal, and a mismatch is a common reason for messages to be deferred or filed as spam.",
      });
    }

    if (mxHosts.length > 0 && tlsRpt === null) {
      findings.push({
        id: "dns-no-tls-rpt",
        title: "No TLS reporting record for inbound mail",
        detail: `The domain publishes ${mxHosts.length} mail exchanger${mxHosts.length === 1 ? "" : "s"} but no _smtp._tls record, so failures to negotiate TLS with those hosts are invisible. Without the report you cannot tell whether your mail is being delivered in the clear.`,
        severity: "low",
        remediation: `Publish a TLS-RPT record: _smtp._tls.${domain} TXT "v=TLSRPTv1; rua=mailto:tls-reports@${domain}".`,
        reference: {
          label: "RFC 8460",
          url: "https://datatracker.ietf.org/doc/html/rfc8460",
        },
      });
    }

    const status: CheckResult["status"] = findings.some(
      (f) => f.severity === "critical" || f.severity === "high"
    )
      ? "fail"
      : findings.some((f) => f.severity === "medium")
        ? "warn"
        : "pass";

    const headline = `${wildcardResolves ? "A wildcard answers for any name" : "No wildcard answers for unregistered names"}, ${httpsRecord ? "an HTTPS record is published" : "no HTTPS record is published"}, and ${mailHosts.length === 0 ? "the apex publishes no mail exchanger" : `${mailHosts.filter((h) => h.consistent).length} of ${mailHosts.length} mail host${mailHosts.length === 1 ? "" : "s"} match their reverse record`}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        wildcard: { resolves: wildcardResolves, addresses: wildAddresses },
        httpsRecord,
        mailHosts,
        tlsRpt,
      } satisfies DnsHygieneData,
      ms: Math.round(performance.now() - started),
      source: "Google and Cloudflare DNS over HTTPS",
      note: `The wildcard test uses one probe label, ${PROBE_LABEL}, which is chosen so that no real service would answer it. A resolver that rewrites every name, such as some captive portals and filtering resolvers, would report a wildcard where none exists.`,
    };
  },
};
