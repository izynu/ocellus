/**
 * Which other hostnames sit on the same address, and what that does or does not
 * mean.
 *
 * The infrastructure check resolves the A record and the ASN. This one takes the
 * same address to AlienVault OTX's passive DNS, which records every hostname
 * that has been observed resolving to it, and asks whether the company is
 * interesting.
 *
 * The answer is easy to over-read, and reading it wrong is expensive. A
 * Cloudflare, Fastly, Akamai or Google edge serves thousands of unrelated
 * customers from one address, so a long list of hostnames there is the ordinary
 * state of the web and says nothing at all about the target. Reporting that as a
 * risk would fire on a large share of everything scanned, so a shared address is
 * named as shared and the check stops there.
 *
 * The case worth reading is the opposite one: a small address where a handful of
 * names that have nothing to do with the target share it. That is the cheap
 * hosting pattern, where one compromised neighbour can be used against the
 * others on the same box. It is reported as context and never as a finding.
 * Sharing an address is not a vulnerability.
 *
 * For the same reason the check does not award a clean verdict: it adds
 * information, so its status is `info` in the ordinary case and `unavailable`
 * when a lookup failed. A failed lookup is never "no co-hosted domains", and the
 * two are kept apart in separate branches below.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import type { FetchFail, FetchResult } from "../net/client";
import { registrableDomain } from "../target";

/**
 * A short reason, for sentences that place a failure inside a list.
 *
 * `describeFailure` in the fetch layer is written to be a whole message: it
 * begins with the name it is given, and its network case ends with a second
 * sentence explaining CORS. Both are right on their own and wrong mid-sentence,
 * where the source name gets said twice and the aside splits the list in half.
 * This gives the reason alone, for callers that supply the subject themselves.
 */
function shortReason(fail: FetchFail): string {
  switch (fail.reason) {
    case "timeout":
      return "timed out";
    case "blocked":
      return `refused the request (${fail.status ?? "no status"})`;
    case "ratelimited":
      return "rate limited the request";
    case "parse":
      return "returned a response that could not be read";
    case "network":
      return "could not be reached";
    default:
      return `returned ${fail.status ?? "an error"}`;
  }
}

type OtxPassiveRecord = {
  hostname?: string;
  record_type?: string;
  first?: string;
  last?: string;
  asn?: string | null;
};

type OtxPassiveResponse = {
  passive_dns?: OtxPassiveRecord[];
  count?: number;
};

/** The subset of Shodan InternetDB this check reads. */
type IdbShape = {
  hostnames?: string[];
  tags?: string[];
};

export type CohostedData = {
  ip: string | null;
  /** Distinct hostnames OTX returned for the address, after deduplication. */
  totalHostnames: number;
  /** The displayed subset, sorted, capped at DISPLAY_CAP. */
  hostnames: string[];
  /** Hostnames on the target's own registrable domain. */
  relatedHostnames: string[];
  unrelatedCount: number;
  sharedAddress: boolean;
  /** Raw record count, so a reader can tell the 500 cap was reached. */
  recordsSeen: number;
  cappedAt500: boolean;
  /** Distinct registrable domains among the unrelated hostnames. */
  unrelatedDomains: number;
  /**
   * The ASN string OTX recorded for the address, e.g. "AS13335 cloudflare".
   * Null when the response carried none, which happens for addresses OTX has no
   * announcement for.
   */
  network: string | null;
  /**
   * True when Shodan tags the address as a CDN edge.
   *
   * A third signal alongside the count thresholds, because a Cloudflare edge
   * answered with one hostname from Shodan and 130 from OTX. When OTX is the
   * source that failed, the tag is what stops a one-name list on an edge from
   * being read as a dedicated address.
   */
  cdnTagged: boolean;
  /** Hostnames Shodan contributed that OTX did not list. */
  fromInternetDb: number;
  /** False when OTX failed and Shodan's index carried the whole answer. */
  otxAnswered: boolean;
};

/** OTX hard-caps this endpoint at 500 records per address. */
const OTX_RECORD_CAP = 500;

/** How many hostnames the payload and the headline may show. */
const DISPLAY_CAP = 6;

/** How many unrelated names the headline may name before counting the rest. */
const NAMED_IN_HEADLINE = 3;

/**
 * Thresholds for "this address is shared".
 *
 * Calibrated against live responses on 2026-11-14:
 *
 *  - 104.20.23.154 (Cloudflare, behind example.com): 130 records, 110 distinct
 *    registrable domains, 128 hostnames outside the target's domain.
 *  - 185.199.108.153 (Fastly, GitHub Pages): 500 records, 340 unrelated domains.
 *  - 151.101.194.132 (Fastly, debian.org): 500 records, 240 unrelated domains,
 *    every hostname outside the target's domain.
 *  - 207.241.224.2 (Internet Archive): 500 records, but 474 of them are under
 *    archive.org and only 20 domains are unrelated, so it is one large dedicated
 *    host and not an edge.
 *  - 172.105.4.254 (Linode, kernel.org): 4 records, one unrelated name.
 *  - 104.207.153.241 (sive.rs): 15 records, 12 unrelated names across 9 domains.
 *
 * The three tests together separate those: at least 25 hostnames, at least 12
 * distinct unrelated registrable domains, and at least half the hostnames
 * outside the target's domain. The count alone would mislabel the Internet
 * Archive; the ratio alone would mislabel a small dedicated box. The ASN is
 * deliberately not a trigger: an ordinary EC2 instance sits in Amazon's ASN and
 * is not shared.
 */
const SHARED_MIN_HOSTNAMES = 25;
const SHARED_MIN_UNRELATED_DOMAINS = 12;
const SHARED_MIN_UNRELATED_SHARE = 0.5;

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** True when the host is on the given registrable domain, respecting the dot boundary. */
function inDomain(host: string, domain: string): boolean {
  return host === domain || host.endsWith("." + domain);
}

/**
 * Clean one hostname from the response, or drop it.
 *
 * A wildcard is not a name that resolves, and a bare address is OTX recording
 * the address as its own name when the lookup had no PTR, which is not a
 * co-hosted hostname. A single label cannot resolve from the public internet.
 */
function normaliseHostname(raw: string): string | null {
  const host = raw.trim().toLowerCase().replace(/\.$/, "");
  if (!host) return null;
  if (host.startsWith("*.")) return null;
  if (host.startsWith(".") || host.includes("..")) return null;
  if (/\s/.test(host)) return null;
  if (!host.includes(".")) return null;
  if (IPV4.test(host) || host.includes(":")) return null;
  return host;
}

/** A list cut to a length, with the remainder counted rather than hidden. */
function nameList(items: string[], max: number): string {
  const shown = items.slice(0, max);
  const hidden = items.length - shown.length;
  return hidden > 0 ? `${shown.join(", ")} and ${hidden} more` : shown.join(", ");
}

export const cohosted: CheckDefinition = {
  id: "cohosted",
  title: "Co-hosted domains",
  question:
    "Which other hostnames resolve to the same address, and does sharing that address tell you anything?",
  group: "infrastructure",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;
    // Sharing an address is not a defect, so this check never produces a
    // finding. Everything it learns is context for the report.
    const findings: Finding[] = [];

    const aRes = await ctx.dns.query(ctx.target.host, "A");
    const ip = aRes.answers.find((r) => r.type === 1)?.data ?? null;

    if (aRes.failed) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline:
          "The DNS resolver did not answer, so the address could not be read and no co-hosted hostnames were looked up.",
        findings,
        ms: Math.round(performance.now() - started),
        source: "AlienVault OTX passive DNS",
        note: "No answer from either resolver is a failure of the lookup, not an absence of the A record. Passive DNS is keyed by address, so without one there was nothing to ask.",
      };
    }

    if (!ip) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: `${ctx.target.host} has no IPv4 address, so there is no address to look up.`,
        findings,
        ms: Math.round(performance.now() - started),
        source: "AlienVault OTX passive DNS",
        note: "An IPv6-only host is unusual for a public website, and this check is keyed by IPv4 address. Check the AAAA record in the DNS section. This is a gap in the lookup, not evidence that nothing else shares the host.",
      };
    }

    // The address is placed straight into a URL path, so it is checked against
    // the IPv4 shape rather than trusted. An A record answer is data from a
    // third party resolver, and a malformed one should not shape a request.
    if (!IPV4.test(ip)) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: `The A record answer for ${ctx.target.host} was not an IPv4 address, so it was not queried.`,
        findings,
        ms: Math.round(performance.now() - started),
        source: "AlienVault OTX passive DNS",
        note: "The resolver returned an answer that is not in IPv4 form. That is a resolver problem rather than a fact about the site, so no passive DNS query was issued.",
      };
    }

    // Two sources, asked at the same time.
    //
    // OTX passive DNS is the rich one: it returned 130 hostnames across 110
    // registrable domains for a single Cloudflare edge, which is what makes the
    // shared-versus-dedicated distinction possible. It is also unreliable. Live
    // measurements on 2026-11-14 gave answers in 0.37 to 0.81 seconds for an
    // address OTX already held, 2 to 29 seconds when it had to build one, and
    // outright 500s for several addresses, including example.com's own edge on
    // repeated attempts minutes apart. A scan that waited 30 seconds and then
    // showed nothing was the worst of both outcomes.
    //
    // Shodan's InternetDB is the second source. It is the same endpoint the
    // infrastructure check already reads, under the same cache key, so asking
    // for it here costs no extra request when that check has run and one fast
    // request when it has not. It answered in 0.34 to 0.74 seconds on every
    // address tested, and its `hostnames` array carries a real list for a
    // dedicated box (9 names for a Linode instance, 24 for WordPress.com) where
    // OTX would have been slow, plus a `cdn` tag on addresses Shodan recognises
    // as edges.
    //
    // Neither alone is enough. InternetDB listed one hostname for a Cloudflare
    // edge where OTX listed 130, so it cannot carry the shared-versus-dedicated
    // judgement on counts; OTX cannot be relied on to answer at all. Together
    // they cover each other, and the twelve second ceiling below is now the
    // right one: with a fallback in hand there is no reason to sit for thirty
    // seconds on the richer source.
    const [idbRes, otxRes] = await Promise.all([
      ctx.net.json<IdbShape>(`https://internetdb.shodan.io/${ip}`, {
        timeoutMs: 12_000,
        cacheKey: `idb:${ip}`,
      }),
      ctx.net.json<OtxPassiveResponse>(
        `https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/passive_dns`,
        { timeoutMs: 12_000, cacheKey: `otx-pdns:${ip}` }
      ),
    ]);

    // InternetDB 404s for an address it has never scanned, which is "nothing
    // known" rather than "could not ask", so it is read as absent data.
    const idb = idbRes.ok && idbRes.json && typeof idbRes.json === "object" ? idbRes.json : null;
    const idbHostnames = Array.isArray(idb?.hostnames) ? idb.hostnames : [];
    const cdnTagged = Array.isArray(idb?.tags) && idb.tags.includes("cdn");

    const otxBody = otxRes.ok ? otxRes.json : null;
    const otxList =
      otxBody && typeof otxBody === "object" && Array.isArray(otxBody.passive_dns)
        ? otxBody.passive_dns
        : null;

    // Nothing answered. Saying so is the only honest result: an address whose
    // neighbours are unknown is not an address with no neighbours.
    if (otxList === null && idbHostnames.length === 0) {
      // Both clauses come from `shortReason`, which gives the reason without
      // the source name or the explanatory second sentence, so the one sentence
      // below can carry both sources. The shared `describeFailure` helper was
      // tried first and produced "AlienVault OTX passive DNS AlienVault OTX
      // passive DNS did not respond in time."
      const why = (fail: FetchResult, okReason: string): string =>
        fail.ok ? okReason : shortReason(fail);
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: `Neither source answered for ${ip}. AlienVault OTX ${why(otxRes, "returned no passive DNS list")}, and Shodan InternetDB ${why(idbRes, "holds no scan of this address")}.`,
        findings,
        ms: Math.round(performance.now() - started),
        source: "AlienVault OTX passive DNS and Shodan InternetDB",
        note: "Both lookups failed, so the co-hosted set for this address is unknown. That is not the same as an address with nothing else on it, and this result says nothing either way.",
      };
    }

    const records = otxList ?? [];
    const recordsSeen = records.length;

    const hostSet = new Set<string>();
    let nonAddressRecords = 0;
    let network: string | null = null;

    for (const record of records) {
      // The ASN is a property of the address and repeats on every record, so it
      // is read before the record type filter. One live response carried the
      // literal string "ASNone" for an address with no announcement recorded, so
      // a value that does not start with an AS number is discarded.
      if (network === null && typeof record?.asn === "string" && /^AS\d+/i.test(record.asn.trim())) {
        network = record.asn.trim().replace(/\s+/g, " ");
      }
      if (typeof record?.hostname !== "string") continue;
      // The question is which hostnames resolve to the address. An NS or SOA
      // entry says the name's zone is served by the address, which is a
      // different claim, so those are counted separately and not listed.
      if (typeof record.record_type === "string" && record.record_type.toUpperCase() !== "A") {
        nonAddressRecords++;
        continue;
      }
      const host = normaliseHostname(record.hostname);
      if (host) hostSet.add(host);
    }

    // InternetDB's list is added after OTX's, so the count is the union rather
    // than a second opinion. It is usually a strict subset of OTX's, which is
    // why the deduplication matters: on a busy edge it adds nothing, and on a
    // dedicated box where OTX failed it is the entire answer.
    const otxOnlyCount = hostSet.size;
    for (const raw of idbHostnames) {
      if (typeof raw !== "string") continue;
      const host = normaliseHostname(raw);
      if (host) hostSet.add(host);
    }
    const fromInternetDb = hostSet.size - otxOnlyCount;
    // Which source carried the list, said in the report rather than left for
    // the reader to infer from a name they do not recognise.
    const sourceLabel =
      otxList === null
        ? "Shodan InternetDB"
        : fromInternetDb > 0
          ? "AlienVault OTX passive DNS and Shodan InternetDB"
          : "AlienVault OTX passive DNS";
    const attribution = otxList === null ? "InternetDB" : "OTX";

    const allHostnames = [...hostSet].sort();
    const totalHostnames = allHostnames.length;
    const relatedHostnames = allHostnames.filter((host) => inDomain(host, domain));
    const unrelated = allHostnames.filter((host) => !inDomain(host, domain));
    const unrelatedCount = unrelated.length;
    const unrelatedDomains = new Set(unrelated.map((host) => registrableDomain(host))).size;
    const totalDomains = new Set(allHostnames.map((host) => registrableDomain(host))).size;
    const unrelatedShare = totalHostnames > 0 ? unrelatedCount / totalHostnames : 0;

    const sharedAddress =
      totalHostnames >= SHARED_MIN_HOSTNAMES &&
      unrelatedDomains >= SHARED_MIN_UNRELATED_DOMAINS &&
      unrelatedShare >= SHARED_MIN_UNRELATED_SHARE;
    const hostnames = allHostnames.slice(0, DISPLAY_CAP);
    const hidden = totalHostnames - hostnames.length;
    const cappedAt500 = recordsSeen >= OTX_RECORD_CAP;

    // Saying how many names were left out keeps the displayed six from reading
    // as the whole set.
    const shownClause =
      hidden > 0 ? ` ${hostnames.length} of the ${totalHostnames} are shown and ${hidden} are not.` : "";

    // "1 domains" is the kind of thing that makes a reader distrust the numbers
    // beside it, so the noun agrees with the count wherever a count appears.
    const domainCount = (n: number): string => `${n} registrable domain${n === 1 ? "" : "s"}`;

    let headline: string;
    if (totalHostnames === 0) {
      // Both sources answered and both had nothing. Phrased per source so the
      // sentence names the thing that was actually empty.
      headline =
        otxList === null
          ? `Shodan holds no hostname on ${ip}, so no co-hosted names could be listed.`
          : `OTX holds no passive DNS record of a hostname resolving to ${ip}, so no co-hosted names could be listed.`;
    } else if (sharedAddress) {
      // Said plainly, because the alternative is a false alarm: the hostnames
      // behind a CDN edge belong to unrelated customers and are not neighbours.
      // The target's own share is phrased for the zero case, because a live
      // scan of debian.org returned 500 hostnames and not one on the domain,
      // and "only 0 of them belong to" reads as a bug rather than a finding.
      const ownShare =
        relatedHostnames.length === 0
          ? `none of them on ${domain}`
          : relatedHostnames.length === 1
            ? `only 1 of them on ${domain}`
            : `only ${relatedHostnames.length} of them on ${domain}`;
      headline = `${ip} is a shared address. ${attribution} lists ${totalHostnames} hostnames across ${domainCount(totalDomains)}, ${ownShare}. The rest are other customers of the same edge or hosting pool, so sharing this address says nothing about this site.${shownClause}`;
    } else if (cdnTagged) {
      // The tag has to outrank the count here. A Cloudflare edge answered with
      // exactly one hostname from Shodan, and that hostname was the target's
      // own www record, so every count-based test saw a dedicated box. Shodan
      // had already tagged the address `cdn`, which is the fact that settles it:
      // an edge serves many customers whether or not the index happens to know
      // their names, so the neighbour reading must not apply.
      const own =
        relatedHostnames.length === 0
          ? `none of them on ${domain}`
          : relatedHostnames.length === 1
            ? `1 of them on ${domain}`
            : `${relatedHostnames.length} of them on ${domain}`;
      headline = `${ip} is a CDN edge address. ${attribution} lists ${totalHostnames} hostname${totalHostnames === 1 ? "" : "s"} on it, ${own}. An edge serves many customers from one address, so sharing it says nothing about this site.${shownClause}`;
    } else {
      const hostCount = `hostname${totalHostnames === 1 ? "" : "s"}`;
      const unrelatedClause =
        unrelatedCount === 0
          ? ""
          : unrelatedCount === 1
            ? ` One of them is unrelated to ${domain}: ${unrelated[0]}.`
            : ` ${unrelatedCount} of them are unrelated to ${domain}: ${nameList(unrelated, NAMED_IN_HEADLINE)}.`;
      // "none of them on X and 2 unrelated" was the shape the first version
      // produced, which reads as two clauses fighting over the same subject.
      // The list is stated first and the split second, so each sentence has one
      // job. The all-related case gets its own wording because "2 of them on X"
      // when both of them are on X reads as a count that lost the rest.
      headline =
        unrelatedCount === 0
          ? `${ip} carries ${totalHostnames} ${hostCount}, ${totalHostnames === 1 ? "and it is on" : "all of them on"} ${domain}.${shownClause}`
          : relatedHostnames.length === 0
            ? `${ip} carries ${totalHostnames} ${hostCount}, and none of them is on ${domain}.${unrelatedClause}${shownClause}`
            : `${ip} carries ${totalHostnames} ${hostCount}, ${relatedHostnames.length} of them on ${domain}.${unrelatedClause}${shownClause}`;
    }

    const noteParts: string[] = [];
    if (otxList === null) {
      // The richer source failed and the fallback carried the answer. Saying so
      // keeps a short list from reading as a complete one, and explains why the
      // names here may be fewer than the address actually carries. The failure
      // phrase is spliced in without the source name, because the sentence
      // already names OTX and "OTX ... (OTX did not respond)" reads as a bug.
      const why = otxRes.ok ? "its response carried no passive DNS list" : shortReason(otxRes);
      noteParts.push(
        `AlienVault OTX did not answer for this address (${why}), so the hostnames come from Shodan's index alone. That index records what a scan saw on the address rather than every name ever pointed at it, so a short list here does not mean the address is exclusive.`
      );
    } else {
      noteParts.push(
        "Passive DNS records hostnames that have resolved to this address at some point in the past, not what resolves to it now, so a listed name may have moved on since."
      );
      noteParts.push(
        cappedAt500
          ? `OTX caps this endpoint at ${OTX_RECORD_CAP} records and returned that many, so the list is a lower bound and the real set is larger.`
          : `OTX caps this endpoint at ${OTX_RECORD_CAP} records. This response came back under the cap, but passive DNS is still a record of observations rather than a complete inventory, so the list is a lower bound.`
      );
    }
    if (otxList !== null && totalHostnames === 0) {
      noteParts.push(
        "An empty passive DNS record means no observer has reported a hostname on this address, which is common for a newly allocated address and is not evidence that nothing shares it."
      );
    }
    if (fromInternetDb > 0 && otxList !== null) {
      noteParts.push(
        `Shodan's index contributed ${fromInternetDb} hostname${fromInternetDb === 1 ? "" : "s"} that OTX did not list, and they are counted above.`
      );
    }
    if (nonAddressRecords > 0) {
      noteParts.push(
        `${nonAddressRecords} NS or SOA ${nonAddressRecords === 1 ? "entry" : "entries"} in the same response describe a zone served by the address rather than a hostname that resolves to it, so ${nonAddressRecords === 1 ? "it is" : "they are"} not counted here.`
      );
    }
    if (sharedAddress) {
      noteParts.push(
        "The address is shared, so the other hostnames are other customers rather than neighbours of this site."
      );
    } else if (cdnTagged) {
      noteParts.push(
        "Shodan tags this address as a CDN edge. An edge is built to serve many customers from one address, so the short list here reflects what the index has named rather than how many sites actually sit on it."
      );
    } else if (unrelatedCount >= 2) {
      // One unrelated name is often the provider's own reverse record for the
      // address, as li1958-254.members.linode.com was for 172.105.4.254, so the
      // neighbour remark needs at least two before it says anything.
      noteParts.push(
        "This address is not a busy edge, so the unrelated names are more likely to be neighbours than passing traffic. On cheap or shared hosting one compromised neighbour can be used against the others on the same address, which is why the names are listed."
      );
    }

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status: "info",
      headline,
      findings,
      data: {
        ip,
        totalHostnames,
        hostnames,
        relatedHostnames,
        unrelatedCount,
        sharedAddress,
        recordsSeen,
        cappedAt500,
        unrelatedDomains,
        network,
        cdnTagged,
        fromInternetDb,
        otxAnswered: otxList !== null,
      } satisfies CohostedData,
      ms: Math.round(performance.now() - started),
      source: sourceLabel,
      note: noteParts.join(" "),
    };
  },
};
