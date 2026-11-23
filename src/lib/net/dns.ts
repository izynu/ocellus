/**
 * DNS over HTTPS.
 *
 * A static page cannot open a DNS socket, so every record here comes from a
 * JSON DoH endpoint. Google and Cloudflare both send
 * `Access-Control-Allow-Origin: *` and both support the same JSON shape, so we
 * use Google first and fall back to Cloudflare.
 *
 * Answers are cached per (name, type) because several checks want the same
 * records: SPF lives in TXT, and both the email and domain checks read it.
 */

import type { NetClient } from "./client";

export type DnsAnswer = {
  name: string;
  type: number;
  ttl: number;
  data: string;
};

export type DnsResponse = {
  /** DoH status: 0 = NOERROR, 3 = NXDOMAIN, 2 = SERVFAIL, 5 = REFUSED, -1 = no answer obtained. */
  status: number;
  answers: DnsAnswer[];
  authority: DnsAnswer[];
  /** True when the resolver validated DNSSEC for this answer. */
  authenticated: boolean;
  provider: string;
  /**
   * True when every provider failed to answer, so the record set is unknown
   * rather than empty. This distinction is the whole point: an empty `answers`
   * array from a network failure and an empty array from a real NODATA reply
   * look identical, and reading the first as the second fabricates findings.
   * A check that sees `failed` must report unavailable, never "no record".
   */
  failed: boolean;
};

export type RecordType =
  | "A"
  | "AAAA"
  | "CNAME"
  | "MX"
  | "NS"
  | "TXT"
  | "SOA"
  | "CAA"
  | "SRV"
  | "PTR"
  | "DS"
  | "DNSKEY"
  | "TLSA"
  | "HTTPS";

const TYPE_NAMES: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  43: "DS",
  46: "RRSIG",
  48: "DNSKEY",
  52: "TLSA",
  257: "CAA",
  65: "HTTPS",
};

const PROVIDERS = [
  { name: "Google Public DNS", url: "https://dns.google/resolve" },
  { name: "Cloudflare 1.1.1.1", url: "https://cloudflare-dns.com/dns-query" },
];

export function typeName(code: number): string {
  return TYPE_NAMES[code] ?? `TYPE${code}`;
}

type RawDoh = {
  Status: number;
  Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
  Authority?: Array<{ name: string; type: number; TTL: number; data: string }>;
  AD?: boolean;
};

export class DnsResolver {
  private cache = new Map<string, Promise<DnsResponse>>();

  constructor(private readonly net: NetClient) {}

  query(name: string, type: RecordType): Promise<DnsResponse> {
    const key = `${name.toLowerCase()}|${type}`;
    const hit = this.cache.get(key);
    if (hit) return hit;
    const promise = this.resolve(name, type);
    this.cache.set(key, promise);
    return promise;
  }

  /** Convenience: the `data` strings for one record type. */
  async values(name: string, type: RecordType): Promise<string[]> {
    const res = await this.query(name, type);
    return res.answers.filter((a) => a.type === TYPE_NAMES_REVERSE[type]).map((a) => a.data);
  }

  /** True when the name has any record of that type. */
  async exists(name: string, type: RecordType): Promise<boolean> {
    const res = await this.query(name, type);
    return res.status === 0 && res.answers.length > 0;
  }

  private async resolve(name: string, type: RecordType): Promise<DnsResponse> {
    let lastError: DnsResponse = {
      status: -1,
      answers: [],
      authority: [],
      authenticated: false,
      provider: "none",
      failed: true,
    };

    for (const provider of PROVIDERS) {
      const url = `${provider.url}?name=${encodeURIComponent(name)}&type=${type}`;
      const res = await this.net.json<RawDoh>(url, {
        headers: { accept: "application/dns-json" },
        timeoutMs: 9000,
      });
      if (!res.ok) {
        lastError = { ...lastError, provider: provider.name };
        continue;
      }
      const body = res.json as RawDoh;
      if (!body || typeof body.Status !== "number") {
        lastError = { ...lastError, provider: provider.name };
        continue;
      }
      return {
        status: body.Status,
        answers: (body.Answer ?? []).map((a) => ({
          name: a.name,
          type: a.type,
          ttl: a.TTL,
          data: a.data,
        })),
        authority: (body.Authority ?? []).map((a) => ({
          name: a.name,
          type: a.type,
          ttl: a.TTL,
          data: a.data,
        })),
        // Only trust the AD flag on a NOERROR answer. A refused or failed query
        // is not validated, and reporting it as authenticated would be a claim
        // about a response nobody received.
        authenticated: body.Status === 0 && Boolean(body.AD),
        provider: provider.name,
        failed: false,
      };
    }
    return lastError;
  }
}

const TYPE_NAMES_REVERSE: Record<RecordType, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DS: 43,
  DNSKEY: 48,
  TLSA: 52,
  CAA: 257,
  HTTPS: 65,
};

/** DNS status codes that mean "the name exists but has no record of this type". */
export const DNS_NOERROR = 0;
export const DNS_NXDOMAIN = 3;
/**
 * The resolver could not produce an answer. SERVFAIL in particular is what a
 * validating resolver returns when DNSSEC validation fails, so its empty answer
 * array is not an absence of records. A `failed` response is different again:
 * that means no provider answered at all, while SERVFAIL is a real answer from
 * one. Checks that read record absence must test both.
 */
export const DNS_SERVFAIL = 2;
export const DNS_REFUSED = 5;

/**
 * True when a response carries a record set that can be read as present or
 * absent. A failed lookup and a SERVFAIL/REFUSED answer both leave `answers`
 * empty, so an empty array alone proves nothing; this is the gate a check uses
 * before treating emptiness as an absence.
 */
export function answeredDefinitively(res: DnsResponse): boolean {
  if (res.failed) return false;
  return res.status === DNS_NOERROR || res.status === DNS_NXDOMAIN;
}

/** Join the character-strings of a TXT record and strip the surrounding quotes. */
export function unquoteTxt(data: string): string {
  return data
    .split('" "')
    .map((part) => part.replace(/^"/, "").replace(/"$/, ""))
    .join("");
}
