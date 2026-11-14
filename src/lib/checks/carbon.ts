/**
 * Energy and carbon per page view, from the Website Carbon estimator.
 *
 * This is context, not a verdict. The number comes from a third party's model,
 * which renders the page from its own location and applies an average grid
 * carbon intensity. It is not a measurement of what this scan downloaded, and
 * it is not a measurement of what a visitor's browser renders. The check states
 * the figure, states what it is, and never turns it into a defect.
 *
 * Endpoint note: the documented `/site` endpoint answers 401 "Unauthorised."
 * with no Access-Control-Allow-Origin header, which makes it unreadable from a
 * browser and unusable without a key. The undocumented `/b` endpoint answers
 * 200 with `Access-Control-Allow-Origin: *`, and also sends that header on its
 * 422 validation error, so a browser can read both outcomes. This check codes
 * against `/b` for that reason.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";

/** The `/b` body. Every field is optional because the upstream can vary. */
type CarbonResponse = {
  /** Grams of CO2 per page view, as the model reports it. */
  c?: number;
  /** Percentile, 0 to 100. Higher is better: a cleaner page. */
  p?: number;
  /** The URL the estimator actually measured, after its own normalisation. */
  url?: string;
  error?: string;
};

export type CarbonData = {
  /** Grams of CO2 per view the model reports, or null when unavailable. */
  gramsPerView: number | null;
  /** Raw percentile 0 to 100 from the model, or null. Higher is better. */
  percentile: number | null;
  /**
   * The same value as `percentile`, under a name that cannot be read as a
   * score where higher is worse. A reader who sees "99" expects a near-fail,
   * so the field says outright that 99 percent of pages are dirtier.
   */
  cleanerThanPercent: number | null;
  /** True when the model reported exactly 0, its floor for a very light page. */
  belowFloor: boolean;
  /** The URL the estimator measured, which may differ from the target URL. */
  estimatedUrl: string | null;
};

/** Keeps a small decimal readable without printing a spurious trailing zero. */
function gramsLabel(grams: number): string {
  const text = grams < 0.01 ? grams.toString() : grams.toFixed(2).replace(/\.?0+$/, "");
  return `${text} g`;
}

export const carbon: CheckDefinition = {
  id: "carbon",
  title: "Energy estimate",
  question: "How much energy and carbon does one page view cost, by a published model?",
  group: "performance",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();

    const res = await ctx.net.json<CarbonResponse | null>(
      `https://api.websitecarbon.com/b?url=${encodeURIComponent(ctx.target.url)}`,
      // A weight-1 context check must not hold the report open. The endpoint
      // answers in about two seconds when it answers at all; a live scan caught
      // it hanging, and at 20 seconds it became the longest check in the run and
      // the reason the whole scan took 23 seconds. Eight seconds is several
      // times the normal latency, so a real answer still lands, and a hung
      // request costs the reader eight seconds instead of twenty.
      { timeoutMs: 8_000, cacheKey: "carbon:" + ctx.target.url }
    );

    if (!res.ok) {
      // 422 is the estimator's "I could not validate this URL" answer. It
      // arrives with CORS, so the browser sees it; it is a refusal to model,
      // not a measurement of zero.
      const validationRefused = res.status === 422;
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: validationRefused
          ? "The estimator could not validate this URL, so it produced no energy estimate."
          : describeFailure(res, "The Website Carbon estimator"),
        findings: [],
        data: {
          gramsPerView: null,
          percentile: null,
          cleanerThanPercent: null,
          belowFloor: false,
          estimatedUrl: null,
        } satisfies CarbonData,
        ms: Math.round(performance.now() - started),
        source: "Website Carbon estimator",
        note: validationRefused
          ? "A 422 from the estimator means it declined to model this URL, usually because it could not fetch the page from its own location. That is not a statement about the page's weight, and no figure is invented here."
          : "The estimator did not return a usable response, so no energy figure is reported. Nothing is assumed to be zero.",
      };
    }

    const body = res.json;
    // A body missing either number is malformed, not a zero. The endpoint can
    // return an error object or a truncated payload, and reading a missing `c`
    // as 0 would present a failure as the cleanest possible page.
    if (!body || typeof body.c !== "number" || !Number.isFinite(body.c) || typeof body.p !== "number" || !Number.isFinite(body.p)) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The estimator answered with a body this check could not read.",
        findings: [],
        data: {
          gramsPerView: null,
          percentile: null,
          cleanerThanPercent: null,
          belowFloor: false,
          estimatedUrl: null,
        } satisfies CarbonData,
        ms: Math.round(performance.now() - started),
        source: "Website Carbon estimator",
        note: "The response did not carry both a grams figure and a percentile. A missing value is treated as unavailable rather than as zero, because zero is a real answer from this endpoint and the two must not be confused.",
      };
    }

    const grams = body.c;
    const percentile = Math.max(0, Math.min(100, body.p));
    const belowFloor = grams === 0;
    const estimatedUrl = typeof body.url === "string" && body.url.length > 0 ? body.url : ctx.target.url;

    // The percentile runs the opposite way from a score: 99 means the page is
    // cleaner than 99 percent of the pages measured. Wikipedia gets 99 and is
    // the lightest of the reference sites; YouTube gets 64 and is heavier. A
    // reader who treats 99 as a near-fail would invert the result, so both the
    // headline and the data field say which way it points.
    const headline = belowFloor
      ? `One page view falls below the model's reporting floor: it reports 0 g CO2, which is the floor for a very light page rather than a claim of zero emissions. Its percentile is ${Math.round(percentile)}, and a higher percentile means a cleaner page.`
      : `One page view is estimated at ${gramsLabel(grams)} CO2, cleaner than ${Math.round(percentile)} percent of the pages this model has measured. A higher percentile is better, so this is not a score to lower.`;

    const findings: Finding[] = [
      {
        id: "carbon-estimate",
        title: belowFloor
          ? "Estimated below the model's reporting floor"
          : `Estimated ${gramsLabel(grams)} CO2 per page view`,
        detail: belowFloor
          ? `The model reports 0 g for this page, which is its floor for a page light enough to round down, not a measurement of zero emissions. It places the page at percentile ${Math.round(percentile)}, where higher is cleaner.`
          : `The model estimates ${gramsLabel(grams)} of CO2 per view, placing the page at percentile ${Math.round(percentile)}. The percentile counts pages that are dirtier, so higher is better.`,
        severity: "info",
        reference: { label: "Website Carbon Calculator", url: "https://www.websitecarbon.com/" },
        evidence: [
          {
            label: "Grams CO2 per view",
            value: belowFloor ? "0, at the model's floor" : gramsLabel(grams),
            tone: "neutral",
          },
          {
            label: "Percentile (higher is cleaner)",
            value: `${Math.round(percentile)}`,
            tone: "neutral",
            detail: `The page is estimated to be cleaner than ${Math.round(percentile)} percent of the pages the model has measured.`,
          },
          { label: "URL the model measured", value: estimatedUrl, tone: "neutral" },
        ],
      },
    ];

    const notes = [
      "This is a third-party estimate from a published model, not a measurement of this page's transfer. The model renders the page from its own location and applies an average grid carbon intensity, so its inputs are the page weight it saw there, which can differ from what a visitor downloads.",
      "The percentile is inverted relative to a normal score: a higher number means a cleaner page.",
    ];
    if (belowFloor) {
      notes.push("A reported 0 with a percentile of 100 is the model's floor for a very light page, not a claim that the page emits nothing.");
    }
    notes.push("This scan's own fetch is not an input to the estimate.");

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status: "info",
      headline,
      findings,
      data: {
        gramsPerView: grams,
        percentile,
        cleanerThanPercent: percentile,
        belowFloor,
        estimatedUrl,
      } satisfies CarbonData,
      ms: Math.round(performance.now() - started),
      source: "Website Carbon estimator",
      note: notes.join(" "),
    };
  },
};
