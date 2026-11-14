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

import type { CheckDefinition, CheckResult, EvidenceRow, Finding } from "../types";
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

/**
 * How many tags the finding text may name, and how much of a single tag it may
 * print. OTX tags are free text, so one tag can be a whole sentence pasted out
 * of a report. A fixed slice of eight of those produced a 600-character run-on,
 * which is unreadable and hides the tags that matter.
 */
const TAG_LIST_LIMIT = 4;
const TAG_HEADLINE_LIMIT = 3;
const TAG_DISPLAY_MAX = 48;

/**
 * OTX tags are contributed by pulse authors and most of them describe how the
 * pulse was built rather than what it is about: a capture date, a scraped
 * address, the file type of the sample. Sorted alphabetically those land at the
 * top, so they are removed before ranking.
 */
const TAG_NOISE_PATTERNS: RegExp[] = [
  // A date in any of the shapes authors use, or a bare year.
  /^\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}$/,
  /^(19|20)\d{2}$/,
  /^\d{1,2}(st|nd|rd|th)?\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?(\s+\d{2,4})?$/i,
  // A bare number, with or without separators or a decimal point.
  /^[\d.,]+$/,
  // A bare IPv4 address, optionally with a port, and a bare IPv6 address.
  /^\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?$/,
  /^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i,
  // A street address: a house number followed by a proper noun, or by any word
  // ending in a street suffix. The narrow shapes matter, because a house number
  // alone would also swallow tags like "2 factor authentication".
  /^\d+[a-z]?\s+[A-Z][\w'.-]*(\s+\S+)*$/,
  /^\d+[a-z]?\s+\S.*\b(street|road|avenue|boulevard|lane|drive|court|place|terrace|highway|parkway|square|way)\b\.?$/i,
];

/**
 * Words that name a file format or a field of the pulse record. They repeat
 * across thousands of unrelated pulses, so a high count for one of them says
 * nothing about this domain.
 */
const TAG_NOISE_WORDS = new Set([
  "ascii",
  "ascii text",
  "binary",
  "text",
  "file",
  "file type",
  "document",
  "exe",
  "dll",
  "pdf",
  "doc",
  "docx",
  "xls",
  "xlsx",
  "ppt",
  "pptx",
  "zip",
  "rar",
  "7z",
  "gz",
  "tar",
  "iso",
  "img",
  "apk",
  "jar",
  "msi",
  "bat",
  "cmd",
  "vbs",
  "ps1",
  "hta",
  "lnk",
  "html",
  "htm",
  "js",
  "javascript",
  "php",
  "csv",
  "json",
  "xml",
  "rtf",
  "png",
  "jpg",
  "jpeg",
  "gif",
  "svg",
  "date",
  "title",
  "info",
  "url",
  "urls",
  "link",
  "links",
  "source",
  "search",
  "ip",
  "ip address",
  "ipv4",
  "ipv6",
  "domain",
  "email",
  "hash",
  "md5",
  "sha1",
  "sha256",
]);

function isNoiseTag(tag: string): boolean {
  const lower = tag.toLowerCase();
  if (TAG_NOISE_WORDS.has(lower)) return true;
  return TAG_NOISE_PATTERNS.some((pattern) => pattern.test(tag));
}

/**
 * Rank tags by how much they say about the campaign. A tag seen in several
 * pulses is a property of the campaign; a tag seen once is a property of one
 * author's ingestion, so the single-pulse tags are only used when nothing
 * repeats. Frequency then decides, and the tag text breaks ties so the output
 * is stable between scans.
 */
function rankTags(tags: string[], pulseCounts: Map<string, number>): string[] {
  const informative = tags.filter((tag) => !isNoiseTag(tag));
  const repeated = informative.filter((tag) => (pulseCounts.get(tag) ?? 0) >= 2);
  const pool = repeated.length > 0 ? repeated : informative;
  return [...pool].sort((a, b) => {
    const byCount = (pulseCounts.get(b) ?? 0) - (pulseCounts.get(a) ?? 0);
    if (byCount !== 0) return byCount;
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

function shortTag(tag: string): string {
  return tag.length > TAG_DISPLAY_MAX ? `${tag.slice(0, TAG_DISPLAY_MAX - 3)}...` : tag;
}

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

    // OTX returns several pulses under the same name when one campaign was
    // published more than once. Listing the duplicates spends the reader's
    // attention on the same string and makes the count look larger than the
    // set of distinct campaigns, so names are deduplicated first-seen.
    const pulseNames = [...new Set(pulses.map((p) => (typeof p?.name === "string" ? p.name.trim() : "")).filter(Boolean))];

    // Tags are repeated across pulses, so collect them once and count how many
    // distinct pulses carry each one. The count is the ranking signal: a tag
    // shared by several pulses describes the campaign, one seen once describes
    // a single author's ingestion. The full set is still returned in `tags`,
    // because the UI counts it.
    const tagSet = new Set<string>();
    const tagPulseCounts = new Map<string, number>();
    for (const pulse of pulses) {
      if (!Array.isArray(pulse?.tags)) continue;
      const seenInThisPulse = new Set<string>();
      for (const tag of pulse.tags) {
        if (typeof tag !== "string" || !tag.trim()) continue;
        const clean = tag.trim();
        tagSet.add(clean);
        seenInThisPulse.add(clean);
      }
      for (const tag of seenInThisPulse) {
        tagPulseCounts.set(tag, (tagPulseCounts.get(tag) ?? 0) + 1);
      }
    }
    const tags = [...tagSet].sort();
    const rankedTags = rankTags(tags, tagPulseCounts);

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
      const topTags = rankedTags.slice(0, TAG_LIST_LIMIT).map(shortTag);
      const tagsLine =
        topTags.length > 0
          ? ` Of ${tags.length} distinct tag${tags.length === 1 ? "" : "s"} across the pulses, the most frequent informative ones are: ${topTags.join(", ")}.`
          : tags.length > 0
            ? ` The ${tags.length} distinct tag${tags.length === 1 ? "" : "s"} across the pulses are all dates, addresses or file-format words, which say nothing about the campaign.`
            : "";
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
        // The evidence rows repeat for the same reason the names do, so a pulse
        // is only listed once per distinct name. The earliest dated copy is
        // kept, since that is when the campaign first appeared.
        evidence: [...pulses]
          .filter((p) => typeof p?.name === "string" && p.name.trim())
          .sort((a, b) => (a.created ?? "").localeCompare(b.created ?? ""))
          .reduce<EvidenceRow[]>((rows, p) => {
            const name = (p.name as string).trim();
            if (rows.some((row) => row.label === name)) return rows;
            rows.push({
              label: name,
              value: typeof p.created === "string" ? p.created.slice(0, 10) : "undated",
              tone: whitelisted ? ("neutral" as const) : ("bad" as const),
            });
            return rows;
          }, [])
          .slice(0, 8),
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
        : `${domain} appears in ${pulseCount} OTX pulse${pulseCount === 1 ? "" : "s"}${whitelisted ? ", which OTX also lists as a whitelisted domain" : ""}${rankedTags.length > 0 ? `, tagged ${rankedTags.slice(0, TAG_HEADLINE_LIMIT).map(shortTag).join(", ")}` : ""}.`;

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
