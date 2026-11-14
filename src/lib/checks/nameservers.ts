/**
 * Nameserver delegation.
 *
 * dns-records lists the NS names and stops there, which leaves the most useful
 * question about a delegation unanswered: who actually operates the servers
 * that answer for this zone, and is that operator the same one that hosts the
 * website?
 *
 * This check follows the delegation one hop further. It resolves each
 * nameserver to an address, asks RIPEstat which autonomous system announces
 * that address, and does the same for the address that serves the scanned host.
 * Comparing the two answers separates a site that runs its own DNS from one
 * that delegates it to a DNS provider, which is ordinary and not a defect.
 *
 * The one thing worth a finding is a zone with a single nameserver, because
 * every registry and RFC 1034 expect at least two. That is an availability
 * problem, not a security one, and it is reported at low severity as such.
 */

import type { CheckDefinition, CheckResult, Finding, ScanContext } from "../types";
import { DNS_NXDOMAIN } from "../net/dns";

/** Why an address list looks the way it does. */
export type AddressState = "resolved" | "no-address" | "lookup-failed" | "not-queried";

/**
 * Why an ASN looks the way it does. `absent` means RIPEstat answered and named
 * no announcing network; `failed` means the request itself did not complete.
 * The two must never be collapsed, because one is a fact about the address and
 * the other is a fact about the scan.
 */
export type NetworkState = "ok" | "absent" | "failed" | "not-looked-up";

export type NameserverEntry = {
  /** NS target, lowercased, with the trailing dot removed. */
  name: string;
  /** A records for the name. Empty when the lookup failed or returned nothing. */
  addresses: string[];
  /** Announcing AS, formatted "AS13335", or null when unknown or absent. */
  asn: string | null;
  /** Registered holder of that AS, as RIPEstat reports it. */
  holder: string | null;
  /** The prefix RIPEstat matched the address to, for example "172.64.35.0/24". */
  prefix: string | null;
  /** Tells "no address exists" apart from "the address lookup failed". */
  addressState: AddressState;
  /** Tells "no network announces it" apart from "the network lookup failed". */
  asnState: NetworkState;
};

export type NameserversData = {
  nameservers: NameserverEntry[];
  siteAsn: string | null;
  siteHolder: string | null;
  /** The prefix the website's address sits in, when RIPEstat reported one. */
  sitePrefix: string | null;
  /** First A record of the scanned host, the address whose network is the site's. */
  siteAddress: string | null;
  siteAddressState: AddressState;
  siteAsnState: NetworkState;
  /** Distinct announcing ASes among the nameservers that were resolved. */
  distinctNetworks: number;
  /** True when every nameserver resolved to one and the same network. */
  sameNetwork: boolean;
  /** True when no nameserver shares the website's network. */
  independentDns: boolean;
  /** NS names published for the zone, after de-duplication. */
  count: number;
  /** True when NS names beyond the address-lookup cap are listed without addresses. */
  nameserversCapped: boolean;
  /** RIPEstat prefix calls actually made. Never above 3. */
  ripeCalls: number;
};

/**
 * A zone with more nameservers than this is listed in full but only the first
 * few are resolved. Four is enough to see the operator pattern, and each extra
 * name costs a DNS query for a value that is almost always the same AS as one
 * already collected.
 */
const MAX_NS_LOOKUPS = 4;

/** Distinct nameserver addresses that get a prefix lookup. */
const NS_PREFIX_BUDGET = 2;

/**
 * Total prefix lookups per scan, including the website's own address. The site
 * needs one so the comparison has a right-hand side, which is why this is one
 * more than the nameserver budget.
 */
const MAX_RIPE_CALLS = 3;

/**
 * The subset of RIPEstat's prefix-overview response that this check reads.
 * `asns` is an array because a prefix can be announced by more than one AS,
 * and `resource` is the prefix RIPEstat aligned the address to, which may be a
 * less specific block than the address itself.
 */
type RipePrefix = {
  data?: {
    announced?: boolean;
    resource?: string;
    asns?: Array<{ asn?: number | string; holder?: string }>;
  };
};

type PrefixOutcome = {
  state: "ok" | "absent" | "failed";
  asn: string | null;
  holder: string | null;
  prefix: string | null;
};

/** RIPEstat returns the ASN as a number. Normalise it to the "AS13335" form. */
function formatAsn(value: number | string | undefined): string | null {
  if (typeof value === "number" && Number.isFinite(value)) return `AS${value}`;
  if (typeof value === "string" && /^\d+$/.test(value.trim())) return `AS${value.trim()}`;
  return null;
}

async function lookupPrefix(ctx: ScanContext, ip: string): Promise<PrefixOutcome> {
  // RIPEstat sends `Access-Control-Allow-Origin: *` on this endpoint, so it is
  // readable from a static page with no proxy. One request per address; the
  // caller enforces the budget and reuses the result for repeated addresses.
  const res = await ctx.net.json<RipePrefix>(
    `https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`,
    { timeoutMs: 20_000, cacheKey: `ripe-prefix:${ip}` }
  );

  if (!res.ok || !res.json || !res.json.data) {
    // The request failed or the body had no data object. Either way the network
    // is unknown. Reporting this as "no network" would state a fact about the
    // address that the response never gave.
    return { state: "failed", asn: null, holder: null, prefix: null };
  }

  const data = res.json.data;
  const prefix =
    typeof data.resource === "string" && data.resource.length > 0 ? data.resource : null;
  const first = (data.asns ?? []).find((entry) => formatAsn(entry?.asn) !== null);
  const asn = first ? formatAsn(first.asn) : null;

  if (first === undefined || asn === null) {
    // RIPEstat answered. An empty ASN list is a real answer: no AS announces
    // this address (the response carries `announced: false` and may still name
    // the enclosing registry block). That is absence, not a failed lookup.
    return { state: "absent", asn: null, holder: null, prefix };
  }

  const holder =
    typeof first.holder === "string" && first.holder.trim().length > 0
      ? first.holder.trim()
      : null;
  return { state: "ok", asn, holder, prefix };
}

function describeNetwork(asn: string | null, holder: string | null): string {
  if (asn && holder) return `${asn} (${holder})`;
  if (asn) return asn;
  if (holder) return holder;
  return "an unidentified network";
}

function emptyData(): NameserversData {
  return {
    nameservers: [],
    siteAsn: null,
    siteHolder: null,
    sitePrefix: null,
    siteAddress: null,
    siteAddressState: "not-queried",
    siteAsnState: "not-looked-up",
    distinctNetworks: 0,
    sameNetwork: false,
    independentDns: false,
    count: 0,
    nameserversCapped: false,
    ripeCalls: 0,
  };
}

export const nameservers: CheckDefinition = {
  id: "nameservers",
  title: "Nameserver delegation",
  question:
    "Which servers actually answer for this zone, what network are they on, and is DNS hosted independently of the website?",
  group: "dns",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;
    const source = "Google and Cloudflare DNS over HTTPS, RIPEstat";

    const nsRes = await ctx.dns.query(domain, "NS");

    // A resolver that never answered returns status -1 with empty answers, the
    // same shape as a real NODATA reply. Tested first, so a dead resolver can
    // never be reported as a zone with no nameservers.
    if (nsRes.failed) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The DNS resolver did not answer, so the delegation could not be read.",
        findings: [],
        data: emptyData(),
        ms: Math.round(performance.now() - started),
        source,
        note: "Neither resolver answered the NS query. That is a failure of the lookup, not a zone without nameservers.",
      };
    }

    // De-duplicated because two identical NS records are still one server, and
    // the count feeds the resilience judgement: counting records rather than
    // distinct hosts would let a duplicated record hide a single point of
    // failure.
    const nsNames = [
      ...new Set(
        nsRes.answers
          .filter((r) => r.type === 2)
          .map((r) => r.data.replace(/\.$/, "").toLowerCase())
          .filter((name) => name.length > 0)
      ),
    ];
    const count = nsNames.length;

    // A resolver that answered with no NS records gave a verdict, and it is not
    // the single-nameserver case. NXDOMAIN is reported by the DNS records check,
    // so this one states the absence and does not duplicate the finding.
    if (count === 0) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "info",
        headline: `${domain} publishes no NS records, so nothing is delegated to answer for the zone.`,
        findings: [],
        data: emptyData(),
        ms: Math.round(performance.now() - started),
        source,
        note:
          nsRes.status === DNS_NXDOMAIN
            ? `The resolver returned NXDOMAIN for ${domain}, so the domain does not exist in DNS. The DNS records check reports that separately.`
            : "The resolver answered the NS query and the answer was empty. That is an absence in the zone, not a failed lookup.",
      };
    }

    const lookupNames = nsNames.slice(0, MAX_NS_LOOKUPS);

    // Different names, cached per name by the resolver, so these run together.
    // The shared gate in NetClient keeps the burst small even so.
    const aResults = await Promise.all(lookupNames.map((name) => ctx.dns.query(name, "A")));

    const entries: NameserverEntry[] = [];
    /** Address to prefix answer, so a shared address is one request, not two. */
    const prefixByAddress = new Map<string, PrefixOutcome>();
    let ripeCalls = 0;
    let nsRipeCalls = 0;
    let skippedForRipe = 0;

    for (let i = 0; i < lookupNames.length; i++) {
      const name = lookupNames[i];
      const answer = aResults[i];

      let addresses: string[] = [];
      let addressState: AddressState;
      if (answer.failed) {
        addressState = "lookup-failed";
      } else {
        addresses = answer.answers.filter((r) => r.type === 1).map((r) => r.data);
        addressState = addresses.length > 0 ? "resolved" : "no-address";
      }

      // Only the first address is looked up. A nameserver with several
      // addresses is normally one operator behind anycast, so the second
      // address would spend a request to repeat the first answer.
      let outcome: PrefixOutcome | null = null;
      const ip = addresses[0];
      if (ip) {
        const cached = prefixByAddress.get(ip);
        if (cached) {
          outcome = cached;
        } else if (nsRipeCalls < NS_PREFIX_BUDGET && ripeCalls < MAX_RIPE_CALLS) {
          outcome = await lookupPrefix(ctx, ip);
          prefixByAddress.set(ip, outcome);
          nsRipeCalls++;
          ripeCalls++;
        } else {
          // An address exists but the budget is spent. Recorded as not looked
          // up, never as an address without a network.
          skippedForRipe++;
        }
      }

      entries.push({
        name,
        addresses,
        asn: outcome?.asn ?? null,
        holder: outcome?.holder ?? null,
        prefix: outcome?.prefix ?? null,
        addressState,
        asnState: outcome === null ? "not-looked-up" : outcome.state,
      });
    }

    // Names beyond the cap are still listed by name, so the report shows the
    // whole delegation, but their addresses are explicitly not queried.
    for (const name of nsNames.slice(MAX_NS_LOOKUPS)) {
      entries.push({
        name,
        addresses: [],
        asn: null,
        holder: null,
        prefix: null,
        addressState: "not-queried",
        asnState: "not-looked-up",
      });
    }

    // The site's network is the network of the address that actually serves the
    // scanned URL. That is the host, not necessarily the apex, because a host
    // can be served from a different provider than the domain root.
    const siteA = await ctx.dns.query(ctx.target.host, "A");
    let siteAddress: string | null = null;
    let siteAddressState: AddressState;
    if (siteA.failed) {
      siteAddressState = "lookup-failed";
    } else {
      siteAddress = siteA.answers.find((r) => r.type === 1)?.data ?? null;
      siteAddressState = siteAddress ? "resolved" : "no-address";
    }

    let siteOutcome: PrefixOutcome | null = null;
    if (siteAddress) {
      const cached = prefixByAddress.get(siteAddress);
      if (cached) {
        siteOutcome = cached;
      } else if (ripeCalls < MAX_RIPE_CALLS) {
        siteOutcome = await lookupPrefix(ctx, siteAddress);
        prefixByAddress.set(siteAddress, siteOutcome);
        ripeCalls++;
      }
    }

    const siteAsn = siteOutcome !== null && siteOutcome.state === "ok" ? siteOutcome.asn : null;
    const siteHolder =
      siteOutcome !== null && siteOutcome.state === "ok" ? siteOutcome.holder : null;
    const sitePrefix = siteOutcome?.prefix ?? null;
    const siteAsnState: NetworkState = siteOutcome === null ? "not-looked-up" : siteOutcome.state;

    // The network identity is the announcing AS, not the prefix. A prefix
    // without an announcing AS is a registry block, not an operator, and two
    // unrelated addresses can sit in blocks of the same size without sharing a
    // provider.
    const resolvedEntries = entries.filter((entry) => entry.asnState === "ok" && entry.asn !== null);
    const zoneAsns = resolvedEntries.map((entry) => entry.asn as string);
    const uniqueZoneAsns = [...new Set(zoneAsns)];
    const distinctNetworks = uniqueZoneAsns.length;

    const holderByAsn = new Map<string, string | null>();
    for (const entry of resolvedEntries) {
      if (entry.asn && !holderByAsn.has(entry.asn)) holderByAsn.set(entry.asn, entry.holder);
    }

    // Independent means no nameserver shares the website's network. A zone
    // where one nameserver sits with the hosting provider and another sits
    // elsewhere still shares infrastructure with the site, so it is not called
    // independent.
    const independentDns =
      siteAsn !== null && zoneAsns.length > 0 && !zoneAsns.includes(siteAsn);

    // Only claimed when every nameserver was resolved and all landed on one AS.
    // With a capped list, or a failed lookup, "same network" would be a guess.
    const sameNetwork = count >= 2 && zoneAsns.length === count && distinctNetworks === 1;

    const findings: Finding[] = [];

    if (count === 1) {
      const sole = entries[0];
      const network = sole.asn ? ` on ${describeNetwork(sole.asn, sole.holder)}` : "";
      findings.push({
        id: "ns-single-nameserver",
        title: "The zone is delegated to a single nameserver",
        detail: `${sole.name}${network} is the only NS record for ${domain}. If that server or the network it sits on is unavailable, every record in the zone stops resolving at once: the website, the mail exchangers and anything else that depends on the name.`,
        severity: "low",
        remediation:
          "Publish a second NS record, ideally at a different network provider, so an outage at one provider cannot take the whole zone down. RFC 1034 and every registry expect at least two.",
        reference: {
          label: "RFC 1034 §4.2.2",
          url: "https://datatracker.ietf.org/doc/html/rfc1034#section-4.2.2",
        },
      });
    }

    let headline: string;
    if (count === 1) {
      const sole = entries[0];
      const network = sole.asn ? ` on ${describeNetwork(sole.asn, sole.holder)}` : "";
      headline = `${domain} is delegated to a single nameserver, ${sole.name}${network}, so an outage there stops the whole zone resolving.`;
    } else {
      // When no ASN was collected, the reason matters: a lookup that failed, an
      // answer with no announcing network, and a name that was never looked up
      // are three different statements. Each gets its own phrase so the
      // headline never turns a failed request into a claim about the zone.
      const absentCount = entries.filter((entry) => entry.asnState === "absent").length;
      const failedCount = entries.filter((entry) => entry.asnState === "failed").length;
      const unqueriedCount = entries.filter((entry) => entry.asnState === "not-looked-up").length;

      let netPhrase: string;
      if (distinctNetworks === 1) {
        netPhrase = `${count} nameservers, all on ${describeNetwork(uniqueZoneAsns[0], holderByAsn.get(uniqueZoneAsns[0]) ?? null)}`;
      } else if (distinctNetworks > 1) {
        netPhrase = `${count} nameservers across ${distinctNetworks} networks (${uniqueZoneAsns.slice(0, 3).join(", ")}${uniqueZoneAsns.length > 3 ? " and others" : ""})`;
      } else if (absentCount === count) {
        netPhrase = `${count} nameservers, none of them inside an announced network`;
      } else if (failedCount > 0) {
        netPhrase = `${count} nameservers whose networks could not all be read`;
      } else if (unqueriedCount > 0) {
        netPhrase = `${count} nameservers, of which ${unqueriedCount} were not looked up`;
      } else {
        netPhrase = `${count} nameservers`;
      }

      const siteDescription = siteAsn ? describeNetwork(siteAsn, siteHolder) : null;
      // "Unknown" is spelled three ways, because RIPEstat not being asked, not
      // answering, and answering with no announcing network are three different
      // facts. Only the last one says anything about the address itself.
      const independence =
        siteAsn !== null
          ? independentDns
            ? `, separate from the website's network at ${siteDescription}`
            : `, sharing a network with the website at ${siteDescription}`
          : siteAsnState === "absent"
            ? ", and the website's address is not in an announced network, so no comparison with the site was possible"
            : siteAsnState === "failed"
              ? ", and the website's network could not be read, so no comparison with the site was possible"
              : ", and the website's network was not looked up";

      headline = `${domain} is delegated to ${netPhrase}${independence}.`;
    }

    const notes: string[] = [];

    if (siteAsnState === "absent") {
      notes.push(
        "RIPEstat answered for the website's address and named no announcing network, so the address is not inside a prefix any autonomous system currently announces. That is a real answer about the address, not a failed lookup, and it means the independence comparison could not be made."
      );
    } else if (siteAsnState === "failed") {
      notes.push(
        "The website's prefix lookup failed, so its network is unknown rather than unannounced. Whether DNS is hosted independently of the site is therefore unanswered."
      );
    } else if (siteAsnState === "not-looked-up") {
      notes.push(
        siteAddressState === "lookup-failed"
          ? "The website's own address lookup failed, so no network comparison was made."
          : "The website's address did not resolve, so there was no address to compare the nameservers against."
      );
    } else if (independentDns) {
      notes.push(
        "The nameservers are on a different network from the website. That is normal: many sites delegate DNS to a provider that does not host the site, and it is context, not a defect."
      );
    } else if (zoneAsns.length > 0 && !independentDns) {
      notes.push(
        `At least one nameserver sits on the website's own network, ${describeNetwork(siteAsn, siteHolder)}, so the DNS provider and the hosting provider share an operator.`
      );
    } else {
      // Site ASN known and every nameserver ASN known, yet nothing to compare:
      // this is the case where no nameserver could be resolved to an AS at all
      // (all absent or unqueried), so independence is undetermined rather than
      // false.
      notes.push(
        "No nameserver network could be compared with the website's, so whether DNS is hosted independently of the site is undetermined here."
      );
    }

    if (sameNetwork) {
      notes.push(
        `All ${count} nameservers resolve to the same network, ${describeNetwork(uniqueZoneAsns[0], holderByAsn.get(uniqueZoneAsns[0]) ?? null)}. That is a single point of failure at the provider level: one outage takes the whole zone down at once. Many providers run their nameservers this way and it is a legitimate design, not a misconfiguration, so it is recorded here and not raised as a finding.`
      );
    }

    if (count === 1) {
      notes.push(
        "A single nameserver is an availability risk for every record in the zone, not a security defect, which is why the finding is low severity."
      );
    }

    if (count > MAX_NS_LOOKUPS) {
      notes.push(
        `The zone publishes ${count} nameservers. Only the first ${MAX_NS_LOOKUPS} were resolved to addresses, so the remaining ${count - MAX_NS_LOOKUPS} are listed by name only.`
      );
    }

    if (skippedForRipe > 0) {
      notes.push(
        `Prefix lookups are capped at ${MAX_RIPE_CALLS} per scan so the check stays cheap. ${skippedForRipe} nameserver address${skippedForRipe === 1 ? " was" : "es were"} not looked up, so ${skippedForRipe === 1 ? "its network is" : "their networks are"} unknown here rather than absent.`
      );
    }

    const failedAddressNames = entries
      .filter((entry) => entry.addressState === "lookup-failed")
      .map((entry) => entry.name);
    if (failedAddressNames.length > 0) {
      notes.push(
        `The address lookup failed for ${failedAddressNames.join(", ")}. That is a failure of the lookup, not evidence that the nameserver has no address.`
      );
    }

    const failedNetworkNames = entries
      .filter((entry) => entry.asnState === "failed")
      .map((entry) => entry.name);
    if (failedNetworkNames.length > 0) {
      notes.push(
        `The prefix lookup failed for ${failedNetworkNames.join(", ")}. That says nothing about which network those addresses are on.`
      );
    }

    notes.push(
      "Network data comes from RIPEstat, which reports the autonomous systems announcing each address at the time of the query. An anycast address can be announced by the same AS from many locations, so one ASN does not mean one data centre."
    );

    // The status is `info` in every case, including the single-nameserver
    // finding. This check answers a descriptive question, and the only defect
    // it can find is an availability risk at low severity. Scoring reads the
    // status, so mapping that finding onto `warn` would take points off a
    // report for something the check deliberately describes as a resilience
    // note rather than a misconfiguration. The finding reaches the reader
    // through the findings list, which ranks it on its own severity.
    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status: "info",
      headline,
      findings,
      data: {
        nameservers: entries,
        siteAsn,
        siteHolder,
        sitePrefix,
        siteAddress,
        siteAddressState,
        siteAsnState,
        distinctNetworks,
        sameNetwork,
        independentDns,
        count,
        nameserversCapped: count > MAX_NS_LOOKUPS,
        ripeCalls,
      } satisfies NameserversData,
      ms: Math.round(performance.now() - started),
      source,
      note: notes.join(" "),
    };
  },
};
