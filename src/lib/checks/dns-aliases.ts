/**
 * The aliases a host publishes, and the service pointers the zone advertises.
 *
 * Two different questions share one check because they share a source and a
 * budget:
 *
 *  - Is the host actually served from its own name, or is it a CNAME to
 *    somewhere else? A CNAME to a CDN is routine. A CNAME to a claimable SaaS
 *    name that no longer resolves is a subdomain takeover waiting to happen,
 *    because anyone who registers that name inherits the hostname and its
 *    certificates.
 *  - Does the zone publish SRV records for XMPP, SIP or autodiscover, and do
 *    any of them name a host that was clearly meant to stay internal?
 *
 * The CNAME query is the one dns-hygiene's wildcard comment gestures at ("a
 * CNAME chain counts too") but never issues. This check issues it directly,
 * against the exact host rather than the apex, so the answer describes what a
 * visitor's resolver actually sees.
 *
 * Cost is kept at four queries: one CNAME plus three fixed SRV labels. Extra
 * address queries are issued only when the CNAME target is on a claimable
 * platform, because the takeover claim is not made without checking whether the
 * name still resolves. That branch is rare, so the usual cost stays at four.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { registrableDomain } from "../target";
import { DNS_NXDOMAIN } from "../net/dns";

export type DnsAliasesData = {
  cname: {
    present: boolean;
    /** The first name the CNAME points at, trailing dot removed. */
    target: string | null;
    /** The queried host followed by the CNAME target names that were returned. */
    chain: string[];
    /** True when the target sits outside the registrable domain of the host. */
    leavesDomain: boolean;
    /** The SaaS suffix that matched, when the target is on a claimable platform. */
    claimableHost: string | null;
    /**
     * Whether the CNAME target has an address. `null` when it was not probed:
     * no CNAME, a target that is not claimable, or a probe that did not answer.
     */
    targetResolves: boolean | null;
  };
  srv: Array<{
    name: string;
    target: string;
    port: number | null;
    priority: number | null;
    weight: number | null;
    internalLooking: boolean;
  }>;
  /** How many of the queries the check issued failed outright. */
  queriesFailed: number;
};

/**
 * The three service labels the check asks about, and nothing more. Spraying a
 * list of a hundred SRV names would turn a weight-2 check into a scan of the
 * zone; these three cover the services whose presence says something about how
 * the domain is used, and their absence is unremarkable.
 */
const SRV_LABELS = ["_xmpp-server._tcp", "_sip._tcp", "_autodiscover._tcp"] as const;

/**
 * Platforms where a name under the suffix can be claimed by anyone who signs
 * up, and where a dangling record therefore hands the hostname to a stranger.
 * The list is deliberately a set of well-known providers: a match is a prompt
 * to look, not proof on its own. Proof needs the second half of the test, that
 * the target does not resolve.
 */
const CLAIMABLE_SUFFIXES = [
  "herokuapp.com",
  "s3.amazonaws.com",
  "azurewebsites.net",
  "cloudfront.net",
  "github.io",
  "netlify.app",
  "vercel.app",
  "trafficmanager.net",
  "azure-api.net",
  "wordpress.com",
  "myshopify.com",
  "surge.sh",
  "bitbucket.io",
  "ghost.io",
  "readme.io",
  "unbounce.com",
  "zendesk.com",
];

/** Suffixes that only ever appear in private naming schemes, never in public DNS. */
const INTERNAL_SUFFIXES = [".local", ".internal", ".lan", ".corp", ".home.arpa"];

/** Strip one trailing dot, which is how DNS writes an absolute name. */
function stripDot(value: string): string {
  return value.replace(/\.$/, "");
}

/**
 * The claimable suffix the target belongs to, or null. The dot boundary matters:
 * `evilherokuapp.com` ends with `herokuapp.com` as a string but is a different
 * registrable domain, and calling it claimable would be wrong.
 */
function claimableSuffix(target: string): string | null {
  const t = target.toLowerCase();
  return CLAIMABLE_SUFFIXES.find((suffix) => t.endsWith(`.${suffix}`)) ?? null;
}

/**
 * True when a published SRV target names something that was meant to stay
 * inside the network. A bare single label cannot be resolved from the public
 * internet without a search suffix, and the private suffixes are reserved for
 * names that should never leave the LAN.
 */
function looksInternal(target: string): boolean {
  const t = target.toLowerCase();
  // "." is the RFC 2782 null target: it means the service is explicitly not
  // offered here, which says nothing about internal naming.
  if (t === "." || t === "") return false;
  if (!t.includes(".")) return true;
  return INTERNAL_SUFFIXES.some((suffix) => t.endsWith(suffix));
}

/** Parse an integer field from SRV RDATA, or null when it is not a number. */
function intOrNull(value: string | undefined): number | null {
  if (value === undefined) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

export const dnsAliases: CheckDefinition = {
  id: "dns-aliases",
  title: "Aliases and service records",
  question: "Does the host alias another name, and does the zone publish service records that point somewhere unexpected?",
  group: "dns",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const host = ctx.target.host;
    const domain = ctx.target.domain;

    // Four queries: the host's CNAME, then one SRV query per fixed label. Each
    // is for a different name and type, so they run together.
    const [cnameRes, ...srvResults] = await Promise.all([
      ctx.dns.query(host, "CNAME"),
      ...SRV_LABELS.map((label) => ctx.dns.query(`${label}.${domain}`, "SRV")),
    ]);

    const emptyCname: DnsAliasesData["cname"] = {
      present: false,
      target: null,
      chain: [],
      leavesDomain: false,
      claimableHost: null,
      targetResolves: null,
    };

    // A resolver that never answered leaves the answer array empty with status
    // -1, which is indistinguishable from NODATA unless `failed` is read. Since
    // an empty CNAME answer is exactly what "the host is not an alias" looks
    // like, and an empty SRV answer is what "no service record" looks like, a
    // failure here must never be reported as either. The check declines rather
    // than guessing, the same way dns-records does.
    const cnameFailed = cnameRes.failed;
    const srvFailed = srvResults.filter((r) => r.failed).length;
    const queriesFailed = (cnameFailed ? 1 : 0) + srvFailed;
    if (queriesFailed > 0) {
      const headline = cnameFailed
        ? "The DNS resolver did not answer for the host's CNAME, so whether it is an alias could not be read."
        : `The DNS resolver did not answer for ${srvFailed} of the ${SRV_LABELS.length} service labels, so the service records could not be read.`;
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline,
        findings: [],
        data: {
          cname: emptyCname,
          srv: [],
          queriesFailed,
        } satisfies DnsAliasesData,
        ms: Math.round(performance.now() - started),
        source: "Google and Cloudflare DNS over HTTPS",
        note: `${queriesFailed} of ${1 + SRV_LABELS.length} queries got no answer from either resolver. A failed lookup is not an absence of the record, so no conclusion is drawn about aliases or service records.`,
      };
    }

    // NXDOMAIN is a verdict the resolver really gave: the host does not exist.
    // Tested after the failure guard so a dead resolver can never be read as a
    // nonexistent name. An alias verdict for a name that does not resolve would
    // be meaningless, so the check stops and says so.
    if (cnameRes.status === DNS_NXDOMAIN) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "info",
        headline: `${host} does not resolve, so it has no alias to judge.`,
        findings: [],
        data: {
          cname: emptyCname,
          srv: [],
          queriesFailed: 0,
        } satisfies DnsAliasesData,
        ms: Math.round(performance.now() - started),
        source: "Google and Cloudflare DNS over HTTPS",
        note: "NXDOMAIN means the name itself does not exist. That is reported by the DNS records check for the zone; here it means there is no CNAME to evaluate.",
      };
    }

    // A single CNAME query returns the first hop, and some resolvers include
    // further hops in the same answer section. Collect every type-5 answer in
    // the order it arrived; do not follow the chain with more queries, because
    // the first hop is what decides whether the host is delegated.
    const cnameTargets = cnameRes.answers
      .filter((r) => r.type === 5)
      .map((r) => stripDot(r.data).toLowerCase())
      .filter(Boolean);

    const cnameTarget = cnameTargets[0] ?? null;
    const chain: string[] = [];
    if (cnameTarget !== null) {
      chain.push(host);
      for (const name of cnameTargets) if (!chain.includes(name)) chain.push(name);
    }

    // Leaving the registrable domain is what a CDN alias does, and it is not a
    // defect. It is recorded because the report should show where the host is
    // really served from, not because it is a problem.
    const leavesDomain =
      cnameTarget !== null && registrableDomain(cnameTarget) !== domain;

    const claimableHost = cnameTarget !== null ? claimableSuffix(cnameTarget) : null;

    // The takeover precondition has two halves, and only the second one proves
    // anything: the target must be on a platform anyone can claim, and the name
    // must currently resolve to nothing. The extra queries are issued only when
    // the first half holds, so the usual scan pays four queries rather than
    // five or six.
    let targetResolves: boolean | null = null;
    let confirmFailed = 0;
    if (claimableHost !== null && cnameTarget !== null) {
      const targetA = await ctx.dns.query(cnameTarget, "A");
      if (targetA.failed) {
        // No answer is not an answer of "nothing". Leaving this null keeps the
        // check from claiming a takeover it could not confirm.
        confirmFailed = 1;
      } else if (targetA.status === 3) {
        // NXDOMAIN: the name does not exist at all, which is the clearest form
        // of dangling. A nonexistent name cannot have an AAAA either.
        targetResolves = false;
      } else if (targetA.answers.some((r) => r.type === 1)) {
        targetResolves = true;
      } else {
        // NOERROR with no A record is the shape CloudFront and several other
        // platforms return for an unclaimed distribution name. It is also the
        // shape an IPv6-only service returns, so AAAA is checked before the
        // name is called dangling. Calling a live IPv6-only target a takeover
        // would be exactly the false positive this check must not produce.
        const targetAaaa = await ctx.dns.query(cnameTarget, "AAAA");
        if (targetAaaa.failed) {
          confirmFailed = 1;
        } else {
          targetResolves = targetAaaa.answers.some((r) => r.type === 28);
        }
      }
    }

    // SRV RDATA is `priority weight port target.` in that order, per RFC 2782.
    // Do not guess at a different order: a four-field record that does not
    // parse into three numbers and a name is skipped rather than reported with
    // fields in the wrong slots.
    const srv: DnsAliasesData["srv"] = [];
    SRV_LABELS.forEach((label, index) => {
      const res = srvResults[index];
      if (!res) return;
      const name = `${label}.${domain}`;
      for (const answer of res.answers) {
        if (answer.type !== 33) continue;
        const parts = answer.data.trim().split(/\s+/);
        if (parts.length < 4) continue;
        const [priorityRaw, weightRaw, portRaw, targetRaw] = parts;
        // "." is the null target and must survive the trailing-dot strip.
        const target = targetRaw === "." ? "." : stripDot(targetRaw ?? "").toLowerCase();
        if (!target) continue;
        srv.push({
          name,
          target,
          port: intOrNull(portRaw),
          priority: intOrNull(priorityRaw),
          weight: intOrNull(weightRaw),
          internalLooking: looksInternal(target),
        });
      }
    });

    const findings: Finding[] = [];

    // The takeover finding is raised only on the full precondition. A claimable
    // host alone is not enough: most such aliases are live, and reporting them
    // as takeovers would be the loudest possible false positive.
    if (claimableHost !== null && targetResolves === false) {
      findings.push({
        id: "dns-cname-takeover",
        title: "The host aliases a claimable name that does not resolve",
        detail: `${host} is a CNAME for ${cnameTarget}, which sits under ${claimableHost}, a platform where anyone can register a name. ${cnameTarget} currently returns no address, so the name is unclaimed. Whoever claims it inherits every request and every certificate for ${host}.`,
        severity: "high",
        remediation: `Remove the CNAME for ${host}, or re-register ${cnameTarget} on ${claimableHost} and point it back at your service. Leaving the record in place keeps the takeover open for as long as it exists.`,
        reference: {
          label: "OWASP: Subdomain takeover",
          url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
        },
        evidence: [
          { label: "Host", value: host },
          { label: "CNAME target", value: cnameTarget ?? "", tone: "bad" as const },
          { label: "Platform", value: claimableHost },
        ],
      });
    } else if (claimableHost !== null) {
      // The platform is claimable but the target still resolves, or the probe
      // could not answer. Both are information rather than a verdict.
      const state =
        targetResolves === true
          ? `${cnameTarget} resolves, so the name is currently in use`
          : `whether ${cnameTarget} is dangling could not be confirmed, because the address lookup did not answer`;
      findings.push({
        id: "dns-cname-claimable",
        title: "The host aliases a name on a platform anyone can claim",
        detail: `${host} is a CNAME for ${cnameTarget}, which sits under ${claimableHost}. That pattern is only a takeover risk while the target name is unclaimed. Here ${state}, so no takeover is reported.`,
        severity: "info",
        remediation:
          "Keep the target name registered for as long as the CNAME exists. A record pointing at a name you no longer control becomes claimable by the next person who registers it.",
        evidence: [
          { label: "CNAME target", value: cnameTarget ?? "" },
          { label: "Platform", value: claimableHost },
        ],
      });
    }

    const internalSrv = srv.filter((r) => r.internalLooking);
    if (internalSrv.length > 0) {
      findings.push({
        id: "dns-srv-internal-target",
        title: `${internalSrv.length} service record${internalSrv.length === 1 ? " points" : "s point"} at an internal name`,
        detail: internalSrv
          .map(
            (r) =>
              `${r.name} publishes ${r.target}${r.port === null ? "" : ` on port ${r.port}`}, which is a name that only makes sense inside a private network.`
          )
          .join(" "),
        severity: "low",
        remediation:
          "Publish the SRV target as a public name, or remove the record if the service is not meant to be reachable from the internet. The record itself leaks the internal naming scheme even when the host is unreachable.",
      });
    }

    // Status follows the severities, not the count: a normal CDN alias and a
    // published SRV record are context, so they land on info, while a low
    // finding is a warn and a confirmed takeover is a fail.
    const status: CheckResult["status"] =
      findings.some((f) => f.severity === "critical" || f.severity === "high")
        ? "fail"
        : findings.some((f) => f.severity === "medium" || f.severity === "low")
          ? "warn"
          : findings.length > 0 || cnameTarget !== null || srv.length > 0
            ? "info"
            : "pass";

    const aliasClause =
      cnameTarget === null
        ? `${host} is served from its own name with no CNAME`
        : `${host} is an alias for ${cnameTarget}${leavesDomain ? `, outside ${domain}` : ""}`;
    const srvClause =
      srv.length === 0
        ? "no XMPP, SIP or autodiscover service record was published"
        : `${srv.length} service record${srv.length === 1 ? "" : "s"} published under the XMPP, SIP or autodiscover labels`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline: `${aliasClause}, and ${srvClause}.`,
      findings,
      data: {
        cname: {
          present: cnameTarget !== null,
          target: cnameTarget,
          chain,
          leavesDomain,
          claimableHost,
          targetResolves,
        },
        srv,
        queriesFailed: confirmFailed,
      } satisfies DnsAliasesData,
      ms: Math.round(performance.now() - started),
      source: "Google and Cloudflare DNS over HTTPS",
      note:
        confirmFailed > 0
          ? `The address lookup for ${cnameTarget ?? "the CNAME target"} did not answer, so whether the claimable name is dangling was not confirmed.`
          : `Only three service labels are queried: ${SRV_LABELS.join(", ")}. A zone that publishes SRV records for other services will not show them here, and their absence is not a defect.`,
    };
  },
};
