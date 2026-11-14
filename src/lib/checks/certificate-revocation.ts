/**
 * Certificate revocation: whether any certificate issued for the domain has
 * been revoked, and in particular whether a certificate that is still inside
 * its validity window has been.
 *
 * That distinction is the whole point. A revoked certificate that has already
 * expired is ordinary rotation: every CA revokes a certificate when it is
 * replaced, and nothing about that is a problem. A revoked certificate that is
 * still valid is the CA saying the key behind it can no longer be trusted, and
 * whoever holds that key can keep using it until the expiry date.
 *
 * Cert Spotter is the source because it is the one certificate transparency
 * index that both answers cross-origin with `Access-Control-Allow-Origin: *`
 * and reports a `revoked` flag per issuance. crt.sh, the index the CT check
 * uses, publishes no revocation state at all. The flag is Cert Spotter's own
 * observation of revocation information published to the logs, not the CA's
 * live OCSP or CRL answer, so a certificate revoked only at the CA may never
 * appear. The check says so rather than presenting the list as complete.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";

type CertSpotterIssuer = {
  name?: string;
  friendly_name?: string;
  pubkey_sha256?: string;
};

/**
 * One issuance, as returned with `expand=dns_names&expand=issuer&expand=cert`.
 * The `cert` expansion carries the DER under a base64 `data` field; this check
 * does not decode it, because the metadata beside it answers the question and
 * the fingerprint is already present as `cert_sha256`.
 */
type CertSpotterEntry = {
  id?: string;
  tbs_sha256?: string;
  cert_sha256?: string;
  dns_names?: string[];
  issuer?: CertSpotterIssuer;
  not_before?: string;
  not_after?: string;
  revoked?: boolean;
};

export type LiveRevokedCertificate = {
  issuer: string;
  notBefore: string | null;
  notAfter: string | null;
  /** SHA-256 of the certificate, when the service reports it. */
  fingerprint: string | null;
};

export type CertificateRevocationData = {
  /** Issuances in the response. Cert Spotter returns at most 100 per page. */
  listed: number;
  revoked: number;
  /** Revoked certificates whose validity window has not yet closed. */
  revokedLive: number;
  issuers: Array<{ name: string; count: number }>;
  /** Earliest and latest not_before in the list, as ISO strings. */
  earliest: string | null;
  latest: string | null;
  liveRevoked: LiveRevokedCertificate[];
  /** True when a full page came back, so further issuances may exist. */
  possiblyTruncated: boolean;
};

/**
 * The service's own short label for a CA, falling back to the CN in the
 * distinguished name. The full DN is long enough to swamp a finding, and the
 * friendly name is the label Cert Spotter itself groups by.
 */
function issuerLabel(issuer: CertSpotterIssuer | undefined): string {
  const friendly = issuer?.friendly_name?.trim();
  if (friendly) return friendly;
  const cn = /CN=([^,]+)/.exec(issuer?.name ?? "")?.[1]?.trim();
  return cn || issuer?.name?.trim() || "an unnamed issuer";
}

/**
 * A certificate counts as live only when both dates parse and today falls
 * between them. An entry with a missing or unparseable date is not counted,
 * because calling it live would assert a fact the response did not state.
 */
function isLive(notBefore: string | undefined, notAfter: string | undefined, now: number): boolean {
  const start = notBefore ? Date.parse(notBefore) : NaN;
  const end = notAfter ? Date.parse(notAfter) : NaN;
  if (Number.isNaN(start) || Number.isNaN(end)) return false;
  return start <= now && now <= end;
}

function day(iso: string | null): string {
  return iso ? iso.slice(0, 10) : "an unknown date";
}

export const certificateRevocation: CheckDefinition = {
  id: "certificate-revocation",
  title: "Certificate revocation",
  question: "Are any of the domain's issued certificates revoked?",
  group: "transport",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;
    const url =
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
      "&include_subdomains=false&expand=dns_names&expand=issuer&expand=cert";

    // The service allows 100 requests an hour per IP without a key, which is
    // ample for a scan, so a retry is not worth the extra wait. The timeout is
    // generous because a busy domain returns a large body: every issuance here
    // carries its DER certificate.
    const res = await ctx.net.json<CertSpotterEntry[]>(url, {
      timeoutMs: 25_000,
      cacheKey: `certspotter:${domain}`,
    });

    if (!res.ok) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: describeFailure(res, "The Cert Spotter issuance index"),
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Cert Spotter",
        note: "The index sends `Access-Control-Allow-Origin: *`, so a failure here is usually rate limiting or a network fault. It says nothing about whether the domain's certificates are revoked.",
      };
    }

    // A 200 whose body is not an array is an error page or a shape change. The
    // service answers `[]` when it has observed nothing, so anything else is a
    // response that cannot be read as an issuance list.
    if (!Array.isArray(res.json)) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The Cert Spotter issuance index returned a response that was not a list of issuances.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Cert Spotter",
        note: "An unreadable response is not evidence that no certificates exist for the domain, and it is not evidence that none is revoked.",
      };
    }

    const entries = res.json;

    // The service paginates at 100 and advertises the next page in a Link
    // header that it does not expose to browsers, so the Link check only fires
    // when the caller is not a browser. The entry count is the fallback signal.
    const link = res.headers.get("link") ?? "";
    const possiblyTruncated = /rel="?next"?/.test(link) || entries.length >= 100;

    if (entries.length === 0) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "info",
        headline: `Cert Spotter lists no issuances for ${domain}.`,
        findings: [],
        data: {
          listed: 0,
          revoked: 0,
          revokedLive: 0,
          issuers: [],
          earliest: null,
          latest: null,
          liveRevoked: [],
          possiblyTruncated: false,
        } satisfies CertificateRevocationData,
        ms: Math.round(performance.now() - started),
        source: "Cert Spotter issuance index",
        note: "Cert Spotter lists issuances it has observed in public certificate logs and is not the CA's own revocation list, so a certificate revoked only at the CA may not appear here. OCSP and CRL are the authoritative sources, and a browser cannot query either cross-origin. An empty list means this index has observed no issuance for the name, which does not by itself prove that none exists.",
      };
    }

    const now = Date.now();
    const issuerCounts = new Map<string, number>();
    const liveRevoked: LiveRevokedCertificate[] = [];
    let revoked = 0;
    /** Revoked entries whose not_after parsed and has passed. */
    let revokedExpired = 0;
    /** Revoked entries with a missing or unreadable date, so neither claim holds. */
    let revokedUndated = 0;
    let earliest: string | null = null;
    let latest: string | null = null;

    for (const entry of entries) {
      if (!entry || typeof entry !== "object") continue;

      const label = issuerLabel(entry.issuer);
      issuerCounts.set(label, (issuerCounts.get(label) ?? 0) + 1);

      if (entry.revoked === true) {
        revoked++;
        if (isLive(entry.not_before, entry.not_after, now)) {
          liveRevoked.push({
            issuer: label,
            notBefore: entry.not_before ?? null,
            notAfter: entry.not_after ?? null,
            fingerprint: entry.cert_sha256 ?? null,
          });
        } else {
          const end = entry.not_after ? Date.parse(entry.not_after) : NaN;
          if (!Number.isNaN(end) && end < now) revokedExpired++;
          else revokedUndated++;
        }
      }

      const issued = entry.not_before ? Date.parse(entry.not_before) : NaN;
      if (!Number.isNaN(issued)) {
        const iso = new Date(issued).toISOString();
        if (!earliest || iso < earliest) earliest = iso;
        if (!latest || iso > latest) latest = iso;
      }
    }

    const issuers = [...issuerCounts.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

    const findings: Finding[] = [];

    if (liveRevoked.length > 0) {
      // The serious case: the CA has withdrawn trust in a key that is still
      // usable. Naming the CA and the window is what makes the finding
      // checkable against the CA's own records.
      const first = liveRevoked[0];
      findings.push({
        id: "certificate-revocation-live",
        title: "A certificate that is still valid has been revoked",
        detail: `${liveRevoked.length} certificate${liveRevoked.length === 1 ? "" : "s"} that Cert Spotter marks revoked ${liveRevoked.length === 1 ? "is" : "are"} still inside ${liveRevoked.length === 1 ? "its" : "their"} validity window. The first was issued by ${first.issuer}, valid from ${day(first.notBefore)} to ${day(first.notAfter)}. A revocation inside the validity window means the CA no longer trusts the key behind the certificate, and the key keeps working until the expiry date.`,
        severity: "high",
        remediation:
          "Confirm the revocation against the CA with OCSP or the CRL, then replace the certificate. If the key itself was compromised, reissue on a new key pair and revoke every certificate bound to the old one.",
        reference: {
          label: "RFC 6960: Online Certificate Status Protocol",
          url: "https://www.rfc-editor.org/rfc/rfc6960.html",
        },
        evidence: liveRevoked.slice(0, 5).map((c) => ({
          label: c.issuer,
          value: `${day(c.notBefore)} to ${day(c.notAfter)}${c.fingerprint ? `, SHA-256 ${c.fingerprint.slice(0, 16)}` : ""}`,
          tone: "bad" as const,
        })),
      });
    } else if (revoked > 0 && revokedExpired === revoked) {
      // Every revoked entry is provably past its expiry, which is what a
      // normal reissue looks like. The wording stays descriptive rather than
      // reassuring, because the reader still decides whether the rotation was
      // expected.
      findings.push({
        id: "certificate-revocation-expired",
        title: "Revoked certificates exist, and all of them have expired",
        detail: `${revoked} of the ${entries.length} listed certificates ${revoked === 1 ? "is" : "are"} marked revoked, and ${revoked === 1 ? "it is" : "all of them are"} past the expiry date. Revoking a certificate after it expires is normal rotation, so this is not evidence of a compromised key.`,
        severity: "low",
      });
    }

    const plural = (n: number) => (n === 1 ? "" : "s");
    const listed = entries.length;

    // The revoked tail has three shapes, and each states only what the dates
    // support. A revoked entry with no readable expiry is reported as such
    // rather than folded into either "live" or "expired".
    const revokedTail =
      liveRevoked.length > 0
        ? `${revoked} ${revoked === 1 ? "is" : "are"} revoked, and ${liveRevoked.length} of them ${liveRevoked.length === 1 ? "is" : "are"} still inside ${liveRevoked.length === 1 ? "its" : "their"} validity window${plural(liveRevoked.length)}`
        : revokedUndated > 0
          ? `${revoked} ${revoked === 1 ? "is" : "are"} revoked, and ${revokedUndated} ${revokedUndated === 1 ? "has" : "have"} no readable expiry date, so it cannot be said whether ${revokedUndated === 1 ? "it is" : "they are"} still valid`
          : `${revoked} ${revoked === 1 ? "is" : "are"} revoked, and ${revoked === 1 ? "it is past its expiry date" : "all of them are past their expiry date"}`;

    const headline =
      revoked > 0
        ? `Cert Spotter lists ${listed} issuance${plural(listed)}; ${revokedTail}.`
        : `Cert Spotter lists ${listed} issuance${plural(listed)} for ${domain}, and none is marked revoked.`;

    const status: CheckResult["status"] =
      liveRevoked.length > 0 ? "fail" : findings.length > 0 ? "warn" : "pass";

    const truncationNote = possiblyTruncated
      ? " The service returns at most 100 issuances per page and does not expose its pagination header to browsers, so this count is the first page and a busy domain may have more beyond it."
      : "";

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        listed,
        revoked,
        revokedLive: liveRevoked.length,
        issuers,
        earliest,
        latest,
        liveRevoked,
        possiblyTruncated,
      } satisfies CertificateRevocationData,
      ms: Math.round(performance.now() - started),
      source: "Cert Spotter issuance index",
      note:
        "Cert Spotter lists issuances it has observed in public certificate logs and is not the CA's own revocation list, so a certificate revoked only at the CA may not appear here. OCSP and CRL are the authoritative sources, and a browser cannot query either cross-origin." +
        truncationNote,
    };
  },
};
