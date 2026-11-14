/**
 * Whether the organisation behind the domain has appeared in a public breach.
 *
 * This is not a check on the website. It is a check on the operator, and it is
 * included because it changes how a reader should act. A company that has
 * already had a customer database taken is a company whose credentials are
 * already circulating, and the people most exposed are the ones who signed up
 * before the breach was disclosed. That is information a visitor cannot get from
 * the site itself.
 *
 * The source is Have I Been Pwned's catalogue of breach metadata, which is the
 * only part of the service available without a key. It is a single JSON document
 * of every publicly disclosed breach, each with the domain it affected. The
 * check matches the scanned registrable domain against that field, exactly, and
 * reports what the catalogue says.
 *
 * The endpoint returns nothing about individuals. It is a list of incidents, not
 * a list of addresses, and no email is ever sent anywhere.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";

type Breach = {
  Name?: string;
  Title?: string;
  Domain?: string;
  BreachDate?: string;
  AddedDate?: string;
  PwnCount?: number;
  DataClasses?: string[];
  IsVerified?: boolean;
  IsFabricated?: boolean;
  IsSensitive?: boolean;
  IsRetired?: boolean;
  IsSpamList?: boolean;
};

export type BreachData = {
  /** Breaches whose Domain field is exactly the scanned registrable domain. */
  breaches: Array<{
    name: string;
    title: string;
    date: string | null;
    added: string | null;
    accounts: number;
    dataClasses: string[];
    verified: boolean;
    /** Fabricated or spam-list entries are listed but never counted as a breach. */
    excluded: string | null;
  }>;
  /** Total size of the catalogue the match was made against. */
  catalogSize: number;
  /** Accounts across the matched breaches, summed. */
  accountsExposed: number;
};

/** The catalogue is one document; caching it by a fixed key means one fetch per scan. */
const CATALOG_URL = "https://haveibeenpwned.com/api/v3/breaches";

function count(value: number | undefined): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

export const breachHistory: CheckDefinition = {
  id: "breach-history",
  title: "Operator breach history",
  question: "Has the organisation behind this domain appeared in a publicly disclosed data breach?",
  group: "threat",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    const res = await ctx.net.json<Breach[]>(CATALOG_URL, {
      timeoutMs: 25_000,
      retry: true,
      cacheKey: "hibp:breaches",
    });

    if (!res.ok || !Array.isArray(res.json)) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The breach catalogue could not be read.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Have I Been Pwned breach catalogue",
        note: "The catalogue is a single document of roughly a thousand entries. A failure to load it is a failure of this check, not evidence that no breach has occurred.",
      };
    }

    const catalog = res.json;
    const matches = catalog.filter(
      (entry) => (entry.Domain ?? "").toLowerCase().replace(/^www\./, "") === domain
    );

    const breaches: BreachData["breaches"] = matches.map((entry) => {
      // A fabricated entry is in the catalogue to be refuted, and a spam list is
      // not a breach. Both are shown so the record is complete, and both are
      // marked so they never read as an incident.
      const excluded = entry.IsFabricated
        ? "listed as fabricated"
        : entry.IsSpamList
          ? "a spam list, not a breach"
          : entry.IsRetired
            ? "retired from the catalogue"
            : null;
      return {
        name: entry.Name ?? "",
        title: entry.Title ?? entry.Name ?? "",
        date: entry.BreachDate ?? null,
        added: entry.AddedDate ?? null,
        accounts: count(entry.PwnCount),
        dataClasses: entry.DataClasses ?? [],
        verified: entry.IsVerified === true,
        excluded,
      };
    });

    const real = breaches.filter((entry) => entry.excluded === null);
    const accountsExposed = real.reduce((sum, entry) => sum + entry.accounts, 0);

    const findings: Finding[] = [];

    if (real.length > 0) {
      const newest = real
        .slice()
        .sort((a, b) => (b.date ?? "").localeCompare(a.date ?? ""))[0];
      const classes = Array.from(new Set(real.flatMap((entry) => entry.dataClasses)));
      const hasPasswords = classes.some((name) => /password/i.test(name));

      findings.push({
        id: "breach-known",
        title: `${real.length} disclosed breach${real.length === 1 ? "" : "es"} name this domain`,
        detail: `The catalogue records ${real
          .map((entry) => `${entry.title} (${entry.date ?? "an unknown date"}, ${entry.accounts.toLocaleString("en-US")} accounts)`)
          .join("; ")}. The most recent is dated ${newest.date ?? "unknown"}. The exposed data included ${classes.slice(0, 5).join(", ")}.${hasPasswords ? " Passwords were among the exposed fields, so any account a person reused elsewhere is at risk, and the site itself should be assumed to have had credentials in circulation since that date." : ""} This is a fact about the operator's history, not a defect in the site as it stands today.`,
        severity: hasPasswords ? "medium" : "low",
        remediation:
          "If the domain is yours, confirm that the exposed credentials were invalidated and that affected users were notified, and check whether the same account database is still in use. If you are a visitor, change the password for any account you hold here if it predates the breach date.",
        reference: {
          label: "Have I Been Pwned",
          url: "https://haveibeenpwned.com/PwnedWebsites",
        },
        evidence: real.slice(0, 8).map((entry) => ({
          label: entry.date ?? "unknown date",
          value: `${entry.title}, ${entry.accounts.toLocaleString("en-US")} accounts`,
          tone: "bad" as const,
          detail: entry.dataClasses.length > 0 ? entry.dataClasses.join(", ") : undefined,
        })),
      });
    }

    const status: CheckResult["status"] =
      real.length === 0 ? "pass" : findings[0].severity === "medium" ? "warn" : "info";

    const headline =
      real.length === 0
        ? `No disclosed breach in the catalogue names ${domain}.`
        : `${real.length} disclosed breach${real.length === 1 ? "" : "es"} in the catalogue name ${domain}, covering ${accountsExposed.toLocaleString("en-US")} accounts.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: { breaches, catalogSize: catalog.length, accountsExposed } satisfies BreachData,
      ms: Math.round(performance.now() - started),
      source: "Have I Been Pwned breach catalogue",
      note: "The catalogue lists breaches that were publicly disclosed and verified. An absence of a match means no disclosed breach names this exact domain, not that no breach has occurred, and not that the site is safe today. Subdomains are not matched.",
    };
  },
};
