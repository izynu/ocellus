/**
 * Reputation, from AlienVault OTX.
 *
 * OTX collects "pulses": curated bundles of indicators that describe a campaign.
 * A domain appearing in one is a signal, not a verdict. The same string shows up
 * in lookalike-domain research, in sinkhole lists and in brand-protection feeds
 * that exist precisely because the domain is a victim. So the check reports the
 * pulse names and the tags, and says plainly that a human has to read them.
 *
 * OTX also runs its own whitelist, which reports the domain as a known false
 * positive or a whitelisted domain. When it does, the severity drops to info,
 * because the source is telling us its own data is not about a compromise.
 *
 * This endpoint echoes the request Origin, which is the only reason a browser
 * can read it. A CORS failure is a real possibility and is reported as
 * unavailable rather than as a clean result.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { describeFailure } from "../net/client";

type OtxValidation = {
  source?: string;
  name?: string;
  message?: string;
};

type OtxPulse = {
  name?: string;
  created?: string;
  tags?: string[];
  adversary?: string;
  malware_families?: Array<string | { display_name?: string; name?: string }>;
};

type OtxResponse = {
  pulse_info?: {
    count?: number;
    pulses?: OtxPulse[];
  };
  validation?: OtxValidation[];
  false_positive?: boolean;
};

export type ThreatIntelData = {
  pulses: number;
  pulseNames: string[];
  tags: string[];
  whitelisted: boolean;
  validations: Array<{ source: string; name: string }>;
};

export const threatIntel: CheckDefinition = {
  id: "threat-intel",
  title: "Threat reputation",
  question: "Does public threat intelligence associate this domain with known malicious activity?",
  group: "threat",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    const res = await ctx.net.json<OtxResponse>(
      `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/general`,
      { timeoutMs: 15_000, cacheKey: `otx:${domain}` }
    );

    if (!res.ok) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: describeFailure(res, "AlienVault OTX"),
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "AlienVault OTX",
        note: "OTX allows browser reads by reflecting the request origin. A failure here usually means that reflection was rejected or the API rate limited the request. It is not a clean result.",
      };
    }

    const body = (res.json ?? {}) as OtxResponse;

    // A 200 with no pulse_info is not the same as a domain with zero pulses,
    // and reporting it as clean would be a fabricated pass.
    if (!body || typeof body !== "object" || !body.pulse_info || typeof body.pulse_info !== "object") {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "AlienVault OTX returned a response without pulse information.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "AlienVault OTX",
        note: "The response did not carry the expected pulse_info object, so no verdict can be drawn from it.",
      };
    }

    const pulseCount = typeof body.pulse_info?.count === "number" ? body.pulse_info.count : 0;
    const pulses = Array.isArray(body.pulse_info?.pulses) ? body.pulse_info.pulses : [];
    const validations = Array.isArray(body.validation) ? body.validation : [];
    const falsePositive = body.false_positive === true;

    const pulseNames = pulses
      .map((p) => (typeof p?.name === "string" ? p.name : ""))
      .filter(Boolean);

    // Tags are repeated across pulses, so collect them once and sort. The list
    // is what tells a reader whether the pulse is about phishing, malware or a
    // lookalike, which the count alone cannot.
    const tagSet = new Set<string>();
    for (const pulse of pulses) {
      if (!Array.isArray(pulse?.tags)) continue;
      for (const tag of pulse.tags) {
        if (typeof tag === "string" && tag.trim()) tagSet.add(tag.trim());
      }
    }
    const tags = [...tagSet].sort();

    // Not every validation entry is a whitelist. OTX returns rank signals
    // ("Akamai rank: #3", "Listed on Alexa") alongside explicit whitelists, and
    // a rank says nothing about whether the pulses are about a compromise. Only
    // an entry whose name or source names a whitelist or a false positive
    // suppresses the finding, which is what the source itself means by it.
    const whitelistEntries = validations.filter((v) =>
      /whitelist|false.?positive/i.test(`${v.name ?? ""} ${v.source ?? ""} ${v.message ?? ""}`)
    );
    const whitelisted = whitelistEntries.length > 0 || falsePositive;

    const findings: Finding[] = [];

    if (pulseCount > 0) {
      // A whitelist entry from OTX itself outranks the pulse count: a domain
      // that appears in many pulses precisely because it is a popular target,
      // and that OTX has whitelisted, is not being accused of anything.
      const severity: Finding["severity"] = whitelisted
        ? "info"
        : pulseCount >= 3
          ? "high"
          : "medium";

      const named = pulseNames.slice(0, 5).join("; ");
      const tagsLine = tags.length > 0 ? ` Tags across the pulses: ${tags.slice(0, 8).join(", ")}.` : "";
      const fpLine = whitelisted
        ? ` OTX also reports ${whitelistEntries.length > 0 ? `${whitelistEntries.length} whitelist entr${whitelistEntries.length === 1 ? "y" : "ies"} for this domain (${whitelistEntries.map((v) => v.name ?? v.source ?? "unnamed").slice(0, 3).join(", ")})` : "the domain as a known false positive"}, so the association is likely to be a name collision or a popular-domain listing rather than a compromise.`
        : "";

      findings.push({
        id: "threat-intel-pulses",
        title: `The domain appears in ${pulseCount} threat intelligence pulse${pulseCount === 1 ? "" : "s"}`,
        detail: `${domain} is referenced by ${pulseCount} OTX pulse${pulseCount === 1 ? "" : "s"}${named ? `: ${named}${pulseNames.length > 5 ? " and others" : ""}` : ""}.${tagsLine}${fpLine}`,
        // A false positive is reported as context, not as a defect, so it needs
        // no remediation and no warning-level weight.
        severity,
        remediation:
          severity === "info"
            ? undefined
            : "Read the pulses before acting. A pulse may be about this domain, or about a lookalike registered to impersonate it. If the reference is genuine, treat the domain as compromised or malicious until proven otherwise and rotate any credentials that touched it.",
        reference: {
          label: "AlienVault OTX",
          url: "https://otx.alienvault.com/",
        },
        evidence: pulses.slice(0, 8).map((p) => ({
          label: typeof p?.name === "string" ? p.name : "Pulse",
          value: typeof p?.created === "string" ? p.created.slice(0, 10) : "undated",
          tone: whitelisted ? ("neutral" as const) : ("bad" as const),
        })),
      });
    }

    if (whitelisted && pulseCount === 0) {
      findings.push({
        id: "threat-intel-whitelisted",
        title: "The domain is on a reputation whitelist",
        detail: `${validations.length > 0 ? `OTX reports ${validations.length} validation${validations.length === 1 ? "" : "s"} for this domain, including ${validations.map((v) => v.name ?? v.source ?? "an unnamed source").slice(0, 3).join(", ")}` : "OTX marks the domain as a known false positive"}. No pulses reference it.`,
        severity: "info",
      });
    }

    const status: CheckResult["status"] =
      pulseCount === 0 ? "pass" : whitelisted ? "info" : pulseCount >= 3 ? "fail" : "warn";

    const headline =
      pulseCount === 0
        ? `${domain} does not appear in any OTX pulse${whitelisted ? ", and the domain is on a reputation whitelist" : ""}.`
        : `${domain} appears in ${pulseCount} OTX pulse${pulseCount === 1 ? "" : "s"}${whitelisted ? ", which OTX also lists as a whitelisted domain" : ""}${tags.length > 0 ? `, tagged ${tags.slice(0, 4).join(", ")}` : ""}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        pulses: pulseCount,
        pulseNames: pulseNames.slice(0, 50),
        tags,
        whitelisted,
        validations: validations
          .filter((v) => typeof v?.name === "string" || typeof v?.source === "string")
          .map((v) => ({ source: v.source ?? "", name: v.name ?? "" })),
      } satisfies ThreatIntelData,
      ms: Math.round(performance.now() - started),
      source: "AlienVault OTX domain reputation",
      note: "A pulse is a curated bundle of indicators, not a confirmed compromise. The count matters less than which pulses reference the domain, which is why the names are listed.",
    };
  },
};
