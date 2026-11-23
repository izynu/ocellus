/**
 * DNSSEC: whether the zone is signed, and with what.
 *
 * The chain of trust shows up in exactly two places. The parent zone carries a
 * DS record, published through the registrar, which commits to a key. The zone
 * itself carries the matching DNSKEY at its apex. A DS with no DNSKEY is the
 * signature of a broken delegation, and it is worse than no DNSSEC at all:
 * validating resolvers answer SERVFAIL for the whole zone.
 *
 * The AD flag from the resolver is reported because it is real evidence, but it
 * is not treated as proof that the zone is signed. A resolver can set AD while
 * proving that a delegation is deliberately unsigned.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { answeredDefinitively } from "../net/dns";

export type DsRecord = {
  keyTag: number;
  algorithm: number;
  algorithmName: string;
  digestType: number;
  digestTypeName: string;
  digest: string;
};

export type DnskeyRecord = {
  flags: number;
  protocol: number;
  algorithm: number;
  algorithmName: string;
  key: string;
};

export type DnssecData = {
  ds: DsRecord[];
  dnskey: DnskeyRecord[];
  /** AD flag on the DS lookup. Validation evidence, not proof of signing. */
  authenticated: boolean;
  provider: string;
};

const ALGORITHMS: Record<number, string> = {
  5: "RSASHA1",
  7: "RSASHA1-NSEC3-SHA1",
  8: "RSASHA256",
  10: "RSASHA512",
  13: "ECDSAP256SHA256",
  14: "ECDSAP384SHA384",
  15: "ED25519",
  16: "ED448",
};

const DIGEST_TYPES: Record<number, string> = {
  1: "SHA-1",
  2: "SHA-256",
  4: "SHA-384",
};

/** Algorithms 5 and 7 are SHA-1 based and no longer recommended for signing. */
const DEPRECATED_ALGORITHMS = new Set([5, 7]);

function algorithmName(code: number): string {
  return ALGORITHMS[code] ?? `algorithm ${code}`;
}

function digestName(code: number): string {
  return DIGEST_TYPES[code] ?? `digest ${code}`;
}

export const dnssec: CheckDefinition = {
  id: "dnssec",
  title: "DNSSEC",
  question: "Is the zone signed, and does the delegation from the parent resolve to a published key?",
  group: "dns",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    const [dsRes, keyRes] = await Promise.all([
      ctx.dns.query(domain, "DS"),
      ctx.dns.query(domain, "DNSKEY"),
    ]);

    // A failed lookup cannot be told apart from an absent record, and the two
    // verdicts are opposites, so refuse to guess when either query failed.
    if (dsRes.failed || keyRes.failed) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: `DNSSEC records for ${domain} could not be read from the resolver.`,
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "DNS-over-HTTPS",
        note: "Both public DoH providers failed for at least one record type. Re-running the scan usually succeeds.",
      };
    }

    // A resolver can answer with a DNSSEC status that is neither NOERROR nor
    // NXDOMAIN: SERVFAIL (2) when validation itself fails, or REFUSED (5). Those
    // answers carry zero records, which looks exactly like "the zone publishes no
    // DNSKEY", but it is not. A live query for dnssec-failed.org returned DS
    // NOERROR with one record and DNSKEY SERVFAIL with none; reading the second
    // as an absent key would have reported a broken delegation as fact, when the
    // resolver was actually saying it could not validate the zone at all. The
    // record set is unknown, so the check declines rather than asserts.
    if (!answeredDefinitively(dsRes) || !answeredDefinitively(keyRes)) {
      const dsUnreadable = !answeredDefinitively(dsRes);
      const which = dsUnreadable ? "DS" : "DNSKEY";
      const code = dsUnreadable ? dsRes.status : keyRes.status;
      const why =
        code === DNS_SERVFAIL
          ? "the resolver could not validate the zone (SERVFAIL), which is often a DNSSEC misconfiguration rather than an absence of records"
          : `the resolver answered with status ${code}, which is not a NOERROR or NODATA answer`;
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: `The DNSSEC lookup for ${domain} did not return a readable ${which} answer.`,
        findings: [],
        ms: Math.round(performance.now() - started),
        source: dsRes.provider === keyRes.provider ? dsRes.provider : "DNS-over-HTTPS",
        note: `The ${which} query answered with status ${code}: ${why}. An empty answer is not an empty record set here, so no signing verdict is claimed. A SERVFAIL on a signed zone is itself worth checking with a zone validator such as dnsviz.net.`,
      };
    }

    // Both queries returned NXDOMAIN: the name does not exist, so there is no
    // zone to be signed or unsigned. The DNS records check reports the
    // nonexistence as a critical finding, and a "not signed" finding here would
    // stack a second conclusion on the same fact, so this check declines.
    if (dsRes.status === DNS_NXDOMAIN && keyRes.status === DNS_NXDOMAIN) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "info",
        headline: `${domain} does not exist in DNS, so there is no zone to sign.`,
        findings: [],
        ms: Math.round(performance.now() - started),
        source: dsRes.provider === keyRes.provider ? dsRes.provider : "DNS-over-HTTPS",
        note: "Both lookups returned NXDOMAIN. The DNS records check reports the missing domain; this check makes no claim about signing for a name that does not resolve.",
      };
    }

    const ds: DsRecord[] = dsRes.answers
      .filter((a) => a.type === 43)
      .map((a) => {
        // "2371 13 2 <hex>" = key tag, algorithm, digest type, digest.
        const [tag, alg, digestType, digest] = a.data.trim().split(/\s+/);
        const algorithm = Number(alg) || 0;
        const digestCode = Number(digestType) || 0;
        return {
          keyTag: Number(tag) || 0,
          algorithm,
          algorithmName: algorithmName(algorithm),
          digestType: digestCode,
          digestTypeName: digestName(digestCode),
          digest: digest ?? "",
        };
      });

    const dnskey: DnskeyRecord[] = keyRes.answers
      .filter((a) => a.type === 48)
      .map((a) => {
        // "256 3 13 <base64>" = flags, protocol, algorithm, public key.
        const parts = a.data.trim().split(/\s+/);
        const algorithm = Number(parts[2]) || 0;
        return {
          flags: Number(parts[0]) || 0,
          protocol: Number(parts[1]) || 0,
          algorithm,
          algorithmName: algorithmName(algorithm),
          key: parts.slice(3).join(""),
        };
      });

    const hasDs = ds.length > 0;
    const hasKey = dnskey.length > 0;
    const findings: Finding[] = [];

    if (!hasDs && !hasKey) {
      findings.push({
        id: "dnssec-none",
        title: "The zone is not signed",
        detail: `${domain} publishes neither a DS record at the parent nor a DNSKEY at the apex. Any answer for this name can be forged by an on-path resolver without detection.`,
        severity: "medium",
        remediation:
          "Enable DNSSEC at the registrar. That publishes a DS record in the parent zone, and the DNS host then signs the zone with a DNSKEY. Both the registrar and the DNS host have to support it.",
        reference: {
          label: "RFC 4033",
          url: "https://www.rfc-editor.org/rfc/rfc4033.html",
        },
      });
    } else if (hasDs && !hasKey) {
      findings.push({
        id: "dnssec-broken-chain",
        title: "The parent delegates with DNSSEC but the zone publishes no key",
        detail: `The parent zone carries ${ds.length} DS record${ds.length === 1 ? "" : "s"} for ${domain}, but the apex returns no DNSKEY. A validating resolver treats this as a broken chain and fails the lookup.`,
        severity: "high",
        remediation:
          "Either publish the DNSKEY that matches the DS record at the apex, or remove the DS record at the registrar. The second option turns DNSSEC off cleanly; leaving it as it is breaks resolution for every validating resolver.",
        reference: {
          label: "RFC 4035",
          url: "https://www.rfc-editor.org/rfc/rfc4035.html",
        },
      });
    } else if (!hasDs && hasKey) {
      // A signed zone with no DS at the parent validates nowhere: the resolver
      // has no trusted anchor to start from, so the signatures prove nothing.
      findings.push({
        id: "dnssec-no-ds",
        title: "The zone is signed but the parent publishes no DS record",
        detail: `${domain} returns ${dnskey.length} DNSKEY record${dnskey.length === 1 ? "" : "s"}, but the parent zone carries no DS record for it. Without the DS at the parent, no validating resolver can build a chain, so the signatures protect nothing.`,
        severity: "medium",
        remediation:
          "Publish the DS record at the registrar, using the key tag and digest of the current KSK. Until the DS exists, the zone's signatures are not part of any chain of trust.",
        reference: {
          label: "RFC 4035",
          url: "https://www.rfc-editor.org/rfc/rfc4035.html",
        },
      });
    }

    const deprecated = [
      ...ds.filter((d) => DEPRECATED_ALGORITHMS.has(d.algorithm)).map((d) => `DS ${d.algorithmName}`),
      ...dnskey.filter((k) => DEPRECATED_ALGORITHMS.has(k.algorithm)).map((k) => `DNSKEY ${k.algorithmName}`),
    ];

    if (deprecated.length > 0) {
      findings.push({
        id: "dnssec-deprecated-algorithm",
        title: "A DNSSEC key uses a SHA-1 algorithm",
        detail: `The zone publishes ${deprecated.join(", ")}. SHA-1 based signing algorithms are deprecated for DNSSEC and are no longer recommended for new deployments.`,
        severity: "medium",
        remediation:
          "Roll the zone signing key to algorithm 13 (ECDSAP256SHA256) or 15 (ED25519), and publish the new DS record at the registrar before retiring the old key.",
        reference: {
          label: "RFC 8624",
          url: "https://www.rfc-editor.org/rfc/rfc8624.html",
        },
        evidence: deprecated.map((d) => ({ label: "Key", value: d, tone: "bad" })),
      });
    }

    const sha1Digests = ds.filter((d) => d.digestType === 1);
    if (sha1Digests.length > 0) {
      findings.push({
        id: "dnssec-sha1-digest",
        title: "A DS record uses a SHA-1 digest",
        detail: `${sha1Digests.length} DS record${sha1Digests.length === 1 ? "" : "s"} at the parent use digest type 1, which is SHA-1. The digest commits the parent to the child key, so a weaker digest weakens the delegation itself.`,
        severity: "low",
        remediation: "Publish the DS record with digest type 2 (SHA-256) or 4 (SHA-384) and withdraw the SHA-1 entry.",
        reference: {
          label: "RFC 4034 §5.1.3",
          url: "https://www.rfc-editor.org/rfc/rfc4034.html#section-5.1.3",
        },
      });
    }

    const adNote = dsRes.authenticated
      ? " The resolver set the AD flag on this lookup, which is validation evidence for the answer but not proof that the zone is signed."
      : "";

    const headline =
      hasDs && hasKey
        ? `${domain} is signed: ${ds.length} DS record${ds.length === 1 ? "" : "s"} at the parent and ${dnskey.length} DNSKEY record${dnskey.length === 1 ? "" : "s"} at the apex.${adNote}`
        : !hasDs && !hasKey
          ? `${domain} publishes no DS or DNSKEY record, so the zone is not signed.${adNote}`
          : hasDs
            ? `${domain} has ${ds.length} DS record${ds.length === 1 ? "" : "s"} at the parent and no DNSKEY at the apex, which breaks the chain.${adNote}`
            : `${domain} publishes ${dnskey.length} DNSKEY record${dnskey.length === 1 ? "" : "s"} but the parent has no DS record, so no resolver can validate it.${adNote}`;

    const status: CheckResult["status"] = findings.some(
      (f) => f.severity === "high" || f.severity === "critical"
    )
      ? "fail"
      : findings.length > 0
        ? "warn"
        : "pass";

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        ds,
        dnskey,
        authenticated: dsRes.authenticated,
        provider: dsRes.provider,
      } satisfies DnssecData,
      ms: Math.round(performance.now() - started),
      source: `${dsRes.provider} over DNS-over-HTTPS`,
    };
  },
};
