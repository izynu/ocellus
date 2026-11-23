/**
 * VirusTotal, for the visitor who brought a key.
 *
 * VirusTotal is the multi-engine verdict most people reach for, and it is the
 * one source a browser cannot read at all. Verified on 23 November 2026: the v3
 * API sends no `Access-Control-Allow-Origin` header on any response, including
 * its 401, so a page can neither read a result nor even distinguish a rejected
 * key from a network failure. A preflight is answered with a 200 carrying no
 * CORS headers, which the browser rejects.
 *
 * So this check exists and is honest about what happens. With a key stored it
 * attempts the documented endpoint, and because the attempt cannot succeed from
 * a browser it reports `unavailable` with the reason, never a fabricated
 * verdict, and never a pass. It still earns its place in the registry: the
 * report and the sources page can then say exactly why VirusTotal is missing
 * rather than leaving the visitor to guess.
 *
 * If VirusTotal ever adds CORS support, the request below starts returning data
 * and the parser turns it into a finding with no further change.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";
import { readKey } from "../scan/keys";

type VtAnalysis = {
  data?: {
    attributes?: {
      last_analysis_stats?: {
        harmless?: number;
        malicious?: number;
        suspicious?: number;
        undetected?: number;
        timeout?: number;
      };
      last_analysis_results?: Record<
        string,
        { category?: string; result?: string | null; engine_name?: string }
      >;
      reputation?: number;
      categories?: Record<string, string>;
      last_analysis_date?: number;
    };
  };
};

export type VirusTotalData = {
  queried: boolean;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  engines: number;
  detections: Array<{ engine: string; result: string }>;
  reputation: number | null;
};

const EMPTY: VirusTotalData = {
  queried: false,
  malicious: 0,
  suspicious: 0,
  harmless: 0,
  undetected: 0,
  engines: 0,
  detections: [],
  reputation: null,
};

/** Build the detection list from the per-engine results, worst first. */
function detectionsFrom(body: VtAnalysis): Array<{ engine: string; result: string }> {
  const results = body.data?.attributes?.last_analysis_results ?? {};
  const bad: Array<{ engine: string; result: string }> = [];
  for (const [engine, value] of Object.entries(results)) {
    if (value?.category === "malicious" || value?.category === "suspicious") {
      bad.push({
        engine: value.engine_name ?? engine,
        result: value.result ?? value.category ?? "flagged",
      });
    }
  }
  return bad;
}

export const virusTotal: CheckDefinition = {
  id: "virustotal",
  title: "VirusTotal verdict",
  question: "Do VirusTotal's engines flag this domain, and which ones?",
  group: "threat",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    const key = readKey("virustotal");
    if (!key) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "No VirusTotal key is stored, so the multi-engine verdict was not queried.",
        findings: [],
        data: EMPTY,
        ms: Math.round(performance.now() - started),
        source: "www.virustotal.com/api/v3 (key required)",
        note: "Add a VirusTotal key in the key panel. Note that the API sends no cross-origin header, so a browser cannot read even an authenticated answer; the check will say so rather than invent one.",
      };
    }

    const res = await ctx.net.json<VtAnalysis>(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
      {
        timeoutMs: 25_000,
        cacheKey: `vt:${domain}`,
        headers: { "x-apikey": key },
      }
    );

    // The expected outcome in a browser: the request is refused by CORS before
    // any body is readable, or a 401 is returned without a cross-origin header.
    // Both are reported as unavailable with the true cause, never as clean.
    if (!res.ok) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: describeFailure(res, "VirusTotal"),
        findings: [],
        data: EMPTY,
        ms: Math.round(performance.now() - started),
        source: "www.virustotal.com/api/v3 (key required)",
        note:
          "VirusTotal sends no Access-Control-Allow-Origin header, so a page cannot read its API even with a valid key. This is a property of their API, not a verdict about the site. Open the VirusTotal page for this domain to see the result directly.",
      };
    }

    const body = res.json as VtAnalysis;
    const stats = body.data?.attributes?.last_analysis_stats ?? {};
    const detections = detectionsFrom(body);
    const engines =
      (stats.harmless ?? 0) +
      (stats.malicious ?? 0) +
      (stats.suspicious ?? 0) +
      (stats.undetected ?? 0) +
      (stats.timeout ?? 0);

    const data: VirusTotalData = {
      queried: true,
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      undetected: stats.undetected ?? 0,
      engines,
      detections: detections.slice(0, 20),
      reputation: typeof body.data?.attributes?.reputation === "number" ? body.data.attributes.reputation : null,
    };

    const findings: Finding[] = [];
    const flagged = data.malicious + data.suspicious;
    if (flagged > 0) {
      findings.push({
        id: "virustotal-detections",
        title: `${flagged} of ${engines} engines flag this domain`,
        detail: detections
          .slice(0, 8)
          .map((d) => `${d.engine}: ${d.result}`)
          .join(", "),
        severity: data.malicious >= 5 ? "critical" : data.malicious > 0 ? "high" : "medium",
        remediation:
          "Read each detection against the engine's own report before acting. One engine naming a shared-hosting neighbour is common and is not the same as the site being malicious.",
        reference: { label: "VirusTotal", url: `https://www.virustotal.com/gui/domain/${domain}` },
        evidence: detections.slice(0, 12).map((d) => ({ label: d.engine, value: d.result, tone: "bad" as const })),
      });
    }

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status: flagged > 0 ? (data.malicious > 0 ? "fail" : "warn") : "pass",
      headline:
        engines === 0
          ? `VirusTotal holds no analysis for ${domain}.`
          : `${flagged === 0 ? "None" : flagged} of ${engines} engines flag ${domain}${data.reputation !== null ? `, reputation ${data.reputation}` : ""}.`,
      findings,
      data,
      ms: Math.round(performance.now() - started),
      source: "www.virustotal.com/api/v3 (key required)",
      note: "A verdict is a set of vendor classifications that can be wrong in both directions. A clean answer means no engine objected, not that the site is safe.",
    };
  },
};
