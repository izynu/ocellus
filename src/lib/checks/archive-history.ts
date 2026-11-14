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

    if (!firstCapture && !lastCapture) {
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
        } satisfies ArchiveData,
        ms: Math.round(performance.now() - started),
        source: "Internet Archive Wayback availability API",
        note: "A site that was never archived is usually new, private, or blocked from crawlers. None of those is a defect, so this is reported as information rather than a verdict.",
      };
    }

    const spanYears = firstCapture
      ? Math.round(((Date.now() - Date.parse(firstCapture)) / (365.25 * 86_400_000)) * 10) / 10
      : null;

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
    // reusable-domain shape.
    if (firstCapture && registration) {
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

    const headline = firstCapture
      ? `Archived since ${firstCapture.slice(0, 10)}, with the most recent capture on ${lastCapture?.slice(0, 10) ?? "an unknown date"}${spanYears !== null ? `, a record spanning ${spanYears} years` : ""}.`
      : "The archive reports a recent capture but no earlier one.";

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
        snapshotUrl:
          latest.replayUrl ??
          (toWaybackStamp(lastCapture)
            ? `https://web.archive.org/web/${toWaybackStamp(lastCapture)}/${target}`
            : null),
        lastStatus: latest.status,
      } satisfies ArchiveData,
      ms: Math.round(performance.now() - started),
      source: "Internet Archive Wayback availability API",
      note: "The availability endpoint returns the capture closest to a requested moment, so the two dates here are the ends of the record rather than a count of how often the site was archived.",
    };
  },
};
