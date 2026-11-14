/**
 * Domain registration, read over RDAP.
 *
 * RDAP is the IETF successor to WHOIS: a JSON format over HTTPS, published by
 * the registry for each TLD. It is the only place a registration date, an
 * expiry date and a registrar can be read without scraping a text protocol, and
 * unlike WHOIS it sends CORS headers, so a browser can read it directly.
 *
 * The check answers three questions a reader actually has: how long has this
 * domain existed, when does it lapse, and is it locked against transfer. A
 * recently registered domain that imitates a brand is the single strongest
 * signal in phishing, and an unlocked, soon-to-expire domain is how legitimate
 * sites are lost.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";

type RdapEntity = {
  roles?: string[];
  vcardArray?: unknown[];
  handle?: string;
};

type RdapResponse = {
  ldhName?: string;
  handle?: string;
  status?: string[];
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  entities?: RdapEntity[];
  nameservers?: Array<{ ldhName?: string }>;
  secureDNS?: { delegationSigned?: boolean };
};

export type WhoisData = {
  registered: string | null;
  expires: string | null;
  updated: string | null;
  /** Whole days between registration and the scan. Null when unknown. */
  ageDays: number | null;
  /** Whole days until expiry. Negative when already expired. */
  daysToExpiry: number | null;
  registrar: string | null;
  statuses: string[];
  nameservers: string[];
  dnssecSigned: boolean | null;
  registry: string;
};

/** Pull the registrar name out of an RDAP vCard, which is an array of arrays. */
function registrarFrom(entities: RdapEntity[] | undefined): string | null {
  if (!entities) return null;
  for (const entity of entities) {
    if (!entity.roles?.includes("registrar")) continue;
    const vcard = entity.vcardArray;
    if (!Array.isArray(vcard) || vcard.length < 2) continue;
    const fields = vcard[1];
    if (!Array.isArray(fields)) continue;
    for (const field of fields) {
      if (!Array.isArray(field) || field[0] !== "fn") continue;
      const value = field[3];
      if (typeof value === "string" && value.trim()) return value.trim();
    }
  }
  return null;
}

function daysBetween(fromIso: string, toMs: number): number | null {
  const from = Date.parse(fromIso);
  if (Number.isNaN(from)) return null;
  return Math.round((toMs - from) / 86_400_000);
}

/**
 * Days from now until an ISO date. Positive in the future, negative once the
 * date has passed. This is the mirror of `daysBetween`, which measures elapsed
 * time, and keeping them separate is deliberate: passing the arguments in the
 * wrong order here reports a domain that expires next year as expired last
 * year, which is a wrong verdict rather than a wrong number.
 */
function daysUntil(iso: string, nowMs: number): number | null {
  const target = Date.parse(iso);
  if (Number.isNaN(target)) return null;
  return Math.round((target - nowMs) / 86_400_000);
}

/**
 * Status values that mean the domain cannot be deleted or moved out from under
 * its owner without an explicit act. Their presence is the normal, safe state.
 */
const PROTECTIVE = new Set([
  "client transfer prohibited",
  "server transfer prohibited",
  "client delete prohibited",
  "server delete prohibited",
  "client update prohibited",
  "server update prohibited",
]);

/** Status values that mean the domain is on its way out or frozen. */
const BAD_STATUSES = new Set([
  "pending delete",
  "redemption period",
  "pending delete restored",
  "client hold",
  "server hold",
  "inactive",
]);

export const whois: CheckDefinition = {
  id: "whois",
  title: "Domain registration",
  question: "When was the domain registered, when does it expire, and is it locked against transfer?",
  group: "dns",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    // rdap.org is a bootstrap that redirects to the authoritative registry for
    // the TLD, so one URL works for every domain. It sends CORS headers on the
    // redirect itself, which is what makes the browser follow it.
    const res = await ctx.net.json<RdapResponse>(
      `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      { timeoutMs: 20_000, cacheKey: `rdap:${domain}` }
    );

    if (!res.ok || !res.json) {
      // describeFailure takes the failure branch, so the narrowing has to be
      // explicit: a 200 whose body is not an object is also a failure here.
      const headline = res.ok
        ? "The registration registry answered with a body that is not a record."
        : describeFailure(res, "The registration registry");
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline,
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "RDAP via rdap.org",
        note: "Not every TLD publishes RDAP, and some registries rate limit anonymous lookups. This is a gap in the lookup, not a fact about the domain.",
      };
    }

    const body = res.json;
    const eventDate = (action: string): string | null =>
      body.events?.find((e) => e.eventAction === action)?.eventDate ?? null;

    const registered = eventDate("registration");
    const expires = eventDate("expiration");
    const updated = eventDate("last changed");
    const now = Date.now();

    const statuses = (body.status ?? []).map((s) => s.toLowerCase());
    const protective = statuses.filter((s) => PROTECTIVE.has(s));
    const bad = statuses.filter((s) => BAD_STATUSES.has(s));
    const registrar = registrarFrom(body.entities);
    const nameservers = (body.nameservers ?? [])
      .map((n) => (n.ldhName ?? "").toLowerCase().replace(/\.$/, ""))
      .filter(Boolean);

    const ageDays = registered ? daysBetween(registered, now) : null;
    const daysToExpiry = expires ? daysUntil(expires, now) : null;

    const findings: Finding[] = [];

    if (ageDays !== null && ageDays >= 0 && ageDays < 90) {
      findings.push({
        id: "whois-new-domain",
        title: `The domain was registered ${ageDays} day${ageDays === 1 ? "" : "s"} ago`,
        detail: `Registration is dated ${registered?.slice(0, 10)}. A domain this new has no history to check, no reputation, and no time for a legitimate owner to have built one. That is not a defect in itself, and it is the single most common property of a domain set up to imitate another.`,
        severity: "medium",
        remediation:
          "If this is your domain, no action is needed beyond waiting. If you are evaluating someone else's, treat a new domain with more caution than an established one and check whether it imitates a name you know.",
        reference: {
          label: "ICANN: registration data policy",
          url: "https://www.icann.org/resources/pages/registration-data-policy-2024-08-21-en",
        },
      });
    }

    if (daysToExpiry !== null && daysToExpiry < 0) {
      findings.push({
        id: "whois-expired",
        title: "The registration has expired",
        detail: `The registry lists ${expires?.slice(0, 10)} as the expiration date, which is ${Math.abs(daysToExpiry)} days ago. An expired domain can be taken over by anyone willing to pay the redemption fee, and mail to it starts failing.`,
        severity: "critical",
        remediation:
          "Renew the domain immediately. Check that the registrar has a current payment method on file.",
      });
    } else if (daysToExpiry !== null && daysToExpiry <= 30) {
      findings.push({
        id: "whois-expiring",
        title: `The registration expires in ${daysToExpiry} day${daysToExpiry === 1 ? "" : "s"}`,
        detail: `The registry lists ${expires?.slice(0, 10)} as the expiration date. A lapsed registration is the cheapest way to lose a site: the domain is released and anyone can claim it, including the address its mail points at.`,
        severity: "high",
        remediation:
          "Renew now rather than at the deadline, and enable auto-renew if the registrar offers it.",
      });
    }

    if (bad.length > 0) {
      findings.push({
        id: "whois-hold",
        title: "The registry has placed a hold on the domain",
        detail: `The registry reports the status ${bad.join(", ")}. A hold takes the domain out of the DNS, which makes the site and its mail stop resolving until the underlying dispute or billing problem is resolved.`,
        severity: "critical",
        remediation:
          "Contact the registrar. A hold is normally a billing failure or a complaint that needs an answer.",
      });
    }

    if (protective.length === 0 && !bad.some((s) => s.includes("hold"))) {
      findings.push({
        id: "whois-no-lock",
        title: "The domain is not locked against transfer",
        detail:
          "The registry reports no transfer-prohibited status. Without a lock, a transfer can be started by anyone who obtains the authorisation code, and the domain can move to another registrar without the owner's involvement.",
        severity: "medium",
        remediation:
          "Enable registrar lock, and keep the authorisation code private. Most registrars call this Transfer Lock or Domain Lock.",
      });
    }

    const status: CheckResult["status"] = findings.some(
      (f) => f.severity === "critical" || f.severity === "high"
    )
      ? "fail"
      : findings.length > 0
        ? "warn"
        : "pass";

    const ageText =
      ageDays === null
        ? "an unknown age"
        : ageDays >= 365
          ? `${(ageDays / 365).toFixed(1)} years old`
          : `${ageDays} days old`;

    const headline = registered
      ? `${domain} is ${ageText}, registered ${registered.slice(0, 10)}${registrar ? ` with ${registrar}` : ""}${daysToExpiry !== null && daysToExpiry >= 0 ? `, and expires in ${daysToExpiry} days` : ""}.`
      : `The registry answered for ${domain} but published no registration date.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        registered,
        expires,
        updated,
        ageDays,
        daysToExpiry,
        registrar,
        statuses,
        nameservers,
        dnssecSigned: body.secureDNS?.delegationSigned ?? null,
        registry: body.ldhName ?? domain,
      } satisfies WhoisData,
      ms: Math.round(performance.now() - started),
      source: "RDAP, the registry's own JSON record",
      note: "RDAP replaced WHOIS in 2020 and is the authoritative record for a registration. Most registries redact personal contact data under the ICANN registration data policy, so this reports dates and status rather than an owner.",
    };
  },
};
