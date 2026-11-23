/**
 * How widely the domain is seen in traffic, from Tranco.
 *
 * Tranco is a research-grade popularity list built from the union of four
 * providers' rankings, which is why it is used here rather than a single
 * vendor's list: one provider's ranking is a marketing number, a union with
 * documented methodology is a measurement. It sends CORS headers, needs no key,
 * and returns the daily rank for the last several weeks.
 *
 * Popularity is not a security property. It is context that changes how every
 * other finding should be read: a missing header on a site with a million daily
 * visitors is a different problem from the same header missing on a personal
 * page. The check states the rank and says that explicitly.
 */

import type { CheckDefinition, CheckResult } from "../types";

type TrancoResponse = {
  domain?: string;
  ranks?: Array<{ date?: string; rank?: number }>;
};

export type PopularityData = {
  /** The most recent daily rank, or null when the domain is not in the list. */
  rank: number | null;
  /** Date of that rank. */
  rankDate: string | null;
  /** Every daily rank returned, oldest last, for a small trend. */
  history: Array<{ date: string; rank: number }>;
  /** The list is the top one million. */
  inTopMillion: boolean;
  /** Rough bucket, so a reader does not have to interpret a raw number. */
  bucket: string;
};

/** Buckets are stated rather than implied, so the label is auditable. */
function bucketFor(rank: number | null): string {
  if (rank === null) return "not ranked";
  if (rank <= 1_000) return "top 1,000";
  if (rank <= 10_000) return "top 10,000";
  if (rank <= 100_000) return "top 100,000";
  if (rank <= 500_000) return "top 500,000";
  return "top 1 million";
}

export const popularity: CheckDefinition = {
  id: "popularity",
  title: "Popularity rank",
  question: "Where does this domain sit in a public traffic ranking?",
  group: "threat",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    const res = await ctx.net.json<TrancoResponse>(
      `https://tranco-list.eu/api/ranks/domain/${encodeURIComponent(domain)}`,
      { timeoutMs: 15_000, cacheKey: `tranco:${domain}` }
    );

    if (!res.ok || !res.json) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The popularity list did not answer for this domain.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Tranco research ranking",
        note: "Tranco answers a domain it has never seen with an empty rank list rather than an error, so a failed request and an unranked domain are different outcomes. This one is a failed request.",
      };
    }

    // Tranco returns {ranks:[...]} for a known domain and a body with no ranks
    // array is a malformed or changed response, not a domain outside the list.
    if (!Array.isArray(res.json.ranks)) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The popularity list answered with a body this check could not read.",
        findings: [],
        data: { rank: null, bucket: "unavailable", rankDate: null, history: [], inTopMillion: false } satisfies PopularityData,
        ms: Math.round(performance.now() - started),
        source: "Tranco research ranking",
        note: "An empty rank list is a real answer for an unranked domain; a body with no rank list at all is not, so no ranking verdict is claimed here.",
      };
    }

    const rows = (res.json.ranks ?? [])
      .filter(
        (r): r is { date: string; rank: number } =>
          typeof r.date === "string" &&
          typeof r.rank === "number" &&
          Number.isFinite(r.rank) &&
          // A rank is a position in a list, so 0 and negatives are not ranks.
          // Accepting them would print "ranked 0", which reads as the top of
          // the list, when the source said nothing usable.
          r.rank > 0
      )
      .sort((a, b) => b.date.localeCompare(a.date));

    // A missing rank stays null, so it is reported as "not ranked" rather than
    // filled in with a zero. The two are opposite claims: unranked says the
    // domain is outside the list, zero says it is at the top of it.
    const latest = rows[0] ?? null;
    const rank = latest?.rank ?? null;
    const bucket = bucketFor(rank);

    const headline =
      rank === null
        ? `${domain} is not ranked in the Tranco top one million.`
        : `${domain} is ranked ${rank.toLocaleString("en-US")} by Tranco, which places it in the ${bucket} of the web${latest ? `, measured on ${latest.date}` : ""}.`;

    // No findings. Popularity is context, and turning it into a verdict would
    // mean either penalising small sites or rewarding large ones for a number
    // that says nothing about their configuration.
    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status: rank === null ? "info" : "pass",
      headline,
      findings: [],
      data: {
        rank,
        rankDate: latest?.date ?? null,
        history: rows.slice(0, 30),
        inTopMillion: rank !== null,
        bucket,
      } satisfies PopularityData,
      ms: Math.round(performance.now() - started),
      source: "Tranco research ranking, a union of four provider lists",
      note: "A rank is context, not a verdict. A low rank means fewer people are watching the site and less reputation is at stake, and it also means the site is less likely to be targeted. Neither direction is a defect.",
    };
  },
};
