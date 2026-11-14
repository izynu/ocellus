/**
 * How far back the public archive reaches for this site.
 *
 * The Wayback Machine is the only public record of a site's past, and it is
 * read here through its availability endpoint rather than its CDX index. The
 * CDX index is richer but sends no CORS header, so a browser cannot read it;
 * the availability endpoint does send one and answers a timestamped query with
 * the closest capture to that moment. Asking it once at the start of the web
 * and once at the present gives the first and last capture, which is what dates
 * the record.
 *
 * Two questions follow from those dates. A site with no archive at all is
 * usually new, private, or crawler-blocked, and none of those is a defect. A
 * site whose record begins recently but whose domain is old is worth a reader's
 * attention, because that is the shape of a domain that was reused.
 *
 * The endpoint answers "nothing here" and "I could not answer" with the same
 * empty snapshot list, and it puts its own failures in the body of a 200. So
 * each query carries an ok flag out of `closestCapture`, and a null date is
 * only read as an absence when the query that produced it answered. A failure
 * on one side leaves that side unknown and the result is information, not a
 * verdict.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";

type AvailabilityResponse = {
  archived_snapshots?: {
    closest?: {
      available?: boolean;
      url?: string;
      timestamp?: string;
      status?: string;
    };
  };
  timestamp?: string;
  /**
   * The endpoint reports its own failures in the body of a 200 response, for
   * example `{"archived_snapshots":{},"error":{"code":"timeout","message":
   * "client timeout at 5.0 seconds"}}`. Without this field an HTTP success with
   * an error inside reads as "the archive holds nothing", which is a conclusion
   * about the site drawn from a query that never answered.
   */
  error?: { code?: string; message?: string };
};

export type ArchiveData = {
  /** ISO date of the earliest capture the archive reports. */
  firstCapture: string | null;
  /** ISO date of the most recent capture. */
  lastCapture: string | null;
  /** Years between the first capture and now, one decimal. */
  spanYears: number | null;
  /** Wayback URL for the most recent capture. */
  snapshotUrl: string | null;
  /** HTTP status of the most recent capture, when reported. */
  lastStatus: string | null;
  /**
   * Set when the earliest-capture query failed, so `firstCapture` is null
   * because the answer was not read rather than because the archive holds
   * nothing. Optional so a consumer that predates this field still compiles.
   */
  firstQueryFailed?: boolean;
  /** The same distinction for the most recent capture. */
  lastQueryFailed?: boolean;
};

/** Wayback timestamps are YYYYMMDDhhmmss. */
function tsToIso(ts: string | undefined): string | null {
  if (!ts || !/^\d{14}$/.test(ts)) return null;
  const iso = `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}T${ts.slice(8, 10)}:${ts.slice(10, 12)}:${ts.slice(12, 14)}Z`;
  return Number.isNaN(Date.parse(iso)) ? null : iso;
}

/** "20261114112747" to "20261114112747", the form the replay URL wants. */
function toWaybackStamp(iso: string | null): string | null {
  if (!iso) return null;
  return iso.replace(/[-:TZ]/g, "").slice(0, 14);
}

async function closestCapture(
  net: import("../net/client").NetClient,
  url: string,
  timestamp: string,
  cacheKey: string
): Promise<{ iso: string | null; replayUrl: string | null; status: string | null; ok: boolean }> {
  const res = await net.json<AvailabilityResponse>(
    `https://archive.org/wayback/available?url=${encodeURIComponent(url)}&timestamp=${timestamp}`,
    { timeoutMs: 20_000, cacheKey }
  );

  if (!res.ok || !res.json) {
    return { iso: null, replayUrl: null, status: null, ok: false };
  }

  // A 200 carrying an error object is still a query that did not answer. The
  // endpoint's 5-second client timeout arrives this way, and reading it as an
  // empty archive is what turns a failed request into a false statement.
  if (res.json.error) {
    return { iso: null, replayUrl: null, status: null, ok: false };
  }

  const closest = res.json.archived_snapshots?.closest;
  if (!closest?.available) {
    return { iso: null, replayUrl: null, status: null, ok: true };
  }

  return {
    iso: tsToIso(closest.timestamp),
    replayUrl: closest.url ?? null,
    status: closest.status ?? null,
    ok: true,
  };
}

export const archiveHistory: CheckDefinition = {
  id: "archive-history",
  title: "Archive history",
  question: "How far back does the public archive reach for this site?",
  group: "threat",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const target = ctx.target.url;

    // One query at the start of the web and one at the present. The endpoint
    // returns the closest capture to the requested moment, so the pair bounds
    // the record from both ends without transferring an index.
    const [earliest, latest] = await Promise.all([
      closestCapture(ctx.net, target, "19960101", `wayback:first:${target}`),
      closestCapture(ctx.net, target, "29990101", `wayback:last:${target}`),
    ]);

    if (!earliest.ok && !latest.ok) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The archive could not be reached for this site.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "Internet Archive Wayback availability API",
        note: "The availability endpoint is a shared public service and occasionally refuses requests. A failure here says nothing about whether the site is archived; re-running usually answers.",
      };
    }

    const firstCapture = earliest.iso;
    const lastCapture = latest.iso;
    const firstFailed = !earliest.ok;
    const lastFailed = !latest.ok;

    // The span is only a real measurement when the earliest date was read. It is
    // null in the branches where that query failed, so those branches cannot
    // carry a number that looks measured but is not.
    const spanYears = firstCapture
      ? Math.round(((Date.now() - Date.parse(firstCapture)) / (365.25 * 86_400_000)) * 10) / 10
      : null;

    // A link to the latest capture, from the endpoint when it gave one and from
    // the timestamp when it only gave the date. Null whenever the latest query
    // did not answer, because there is no capture to link to in that case.
    const snapshotUrl =
      latest.replayUrl ??
      (toWaybackStamp(lastCapture)
        ? `https://web.archive.org/web/${toWaybackStamp(lastCapture)}/${target}`
        : null);

    // "The archive holds nothing" is a statement about the site, so it is only
    // made when both queries answered. A null from a failed query means the
    // answer was not read, which is not the same thing.
    if (!firstFailed && !lastFailed && !firstCapture && !lastCapture) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "info",
        headline: `The public archive holds no capture of ${ctx.target.host}.`,
        findings: [],
        data: {
          firstCapture: null,
          lastCapture: null,
          spanYears: null,
          snapshotUrl: null,
          lastStatus: null,
          firstQueryFailed: false,
          lastQueryFailed: false,
        } satisfies ArchiveData,
        ms: Math.round(performance.now() - started),
        source: "Internet Archive Wayback availability API",
        note: "A site that was never archived is usually new, private, or blocked from crawlers. None of those is a defect, so this is reported as information rather than a verdict.",
      };
    }

    // The earliest query did not answer. The latest one may still have, and
    // that half is reported, but the headline may not extend to the half that
    // did not answer: "no earlier capture" would be a conclusion drawn from a
    // request that failed. A partial answer is information, not a verdict.
    if (firstFailed) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "info",
        headline: lastCapture
          ? `The most recent capture is on ${lastCapture.slice(0, 10)}, but the earliest capture could not be determined because the archive did not answer that query.`
          : `The archive reported no capture at the present, and the query for the earliest capture did not answer, so the start of the record is unknown.`,
        findings: [],
        data: {
          firstCapture: null,
          lastCapture,
          spanYears: null,
          snapshotUrl,
          lastStatus: latest.status,
          firstQueryFailed: true,
          lastQueryFailed: false,
        } satisfies ArchiveData,
        ms: Math.round(performance.now() - started),
        source: "Internet Archive Wayback availability API",
        note: "The query for the earliest capture did not answer, so the start of the record is unknown. That is a gap in this check, not a fact about the site; re-running usually answers.",
      };
    }

    // The same treatment for the most recent capture.
    if (lastFailed) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "info",
        headline: firstCapture
          ? `The earliest capture is on ${firstCapture.slice(0, 10)}, but the most recent capture could not be determined because the archive did not answer that query.`
          : `The archive reported no capture at the start of the web, and the query for the most recent capture did not answer, so the end of the record is unknown.`,
        findings: [],
        data: {
          firstCapture,
          lastCapture: null,
          spanYears,
          snapshotUrl: null,
          lastStatus: null,
          firstQueryFailed: false,
          lastQueryFailed: true,
        } satisfies ArchiveData,
        ms: Math.round(performance.now() - started),
        source: "Internet Archive Wayback availability API",
        note: "The query for the most recent capture did not answer, so the end of the record is unknown. That is a gap in this check, not a fact about the site; re-running usually answers.",
      };
    }

    const findings: Finding[] = [];

    // The registration date comes from the same RDAP record the domain check
    // reads. The request URL and cache key are identical, so whichever check
    // runs first performs one fetch and the other is served from the shared
    // cache: no second request, and no dependency on run order.
    const rdap = await ctx.net.json<{
      events?: Array<{ eventAction?: string; eventDate?: string }>;
    }>(`https://rdap.org/domain/${encodeURIComponent(ctx.target.domain)}`, {
      timeoutMs: 20_000,
      cacheKey: `rdap:${ctx.target.domain}`,
    });
    const registration =
      rdap.ok && rdap.json
        ? (rdap.json.events?.find((e) => e.eventAction === "registration")?.eventDate ?? null)
        : null;

    // The comparison is only made when the registration date is known, because
    // "the archive starts recently" means nothing without something to compare
    // it to. A registration older than the archive by two years or more is the
    // reusable-domain shape. Both dates must come from queries that answered:
    // a failed query leaves `firstCapture` null, and a gap computed from a date
    // that was never read would be a finding built on a missing answer.
    if (!firstFailed && !lastFailed && firstCapture && registration) {
      const gapDays = Math.round(
        (Date.parse(firstCapture) - Date.parse(registration)) / 86_400_000
      );
      if (gapDays >= 730) {
        findings.push({
          id: "archive-late-start",
          title: "The archive begins well after the domain was registered",
          detail: `The domain was registered on ${registration.slice(0, 10)}, and the earliest capture in the public archive is ${firstCapture.slice(0, 10)}, ${Math.round(gapDays / 365)} years later. That gap is the shape of a domain that sat unused and was later put to work, which is normal for a parked domain and is also how a lapsed domain is reused.`,
          severity: "low",
          remediation:
            "If the domain changed hands recently, confirm the current content is what you expect. If it did not, no action is needed: the gap is a fact about the archive's coverage, not about the site.",
        });
      }
    }

    const status: CheckResult["status"] = findings.length > 0 ? "warn" : "info";

    // Reached only when both queries answered, so neither date is null because
    // of a failure. A query can still answer "nothing here", and that case is
    // described as what it is rather than filled in with an invented date.
    const headline = firstCapture
      ? lastCapture
        ? `Archived since ${firstCapture.slice(0, 10)}, with the most recent capture on ${lastCapture.slice(0, 10)}${spanYears !== null ? `, a record spanning ${spanYears} years` : ""}.`
        : `The archive holds a capture from ${firstCapture.slice(0, 10)}, but none close to the present.`
      : `The archive holds a recent capture of ${ctx.target.host}, but none close to the start of the web.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        firstCapture,
        lastCapture,
        spanYears,
        snapshotUrl,
        lastStatus: latest.status,
        firstQueryFailed: false,
        lastQueryFailed: false,
      } satisfies ArchiveData,
      ms: Math.round(performance.now() - started),
      source: "Internet Archive Wayback availability API",
      note: "The availability endpoint returns the capture closest to a requested moment, so the two dates here are the ends of the record rather than a count of how often the site was archived.",
    };
  },
};
