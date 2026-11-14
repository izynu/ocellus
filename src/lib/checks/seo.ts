/**
 * SEO and crawlability.
 *
 * What a crawler sees, not what a browser renders: robots directives, the
 * canonical target, the sitemap, and whether social preview tags are present.
 * These never appear on screen, so a mistake in any of them can sit for months.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { isSameSite } from "../target";

export type SeoData = {
  robotsTxt: { found: boolean; status: number; sitemaps: string[]; disallowAll: boolean; groups: number };
  sitemap: { found: boolean; url: string | null; urlCount: number; isIndex: boolean; status: number };
  canonical: string | null;
  canonicalMatches: boolean;
  metaRobots: string | null;
  og: Record<string, string>;
  twitter: Record<string, string>;
  hasStructuredData: boolean;
  structuredTypes: string[];
  titleLength: number;
  descriptionLength: number;
};

export const seo: CheckDefinition = {
  id: "seo",
  title: "SEO and crawlability",
  question: "Can search engines crawl, index and correctly preview this site?",
  group: "seo",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const page = await ctx.html();
    const doc = page.doc;
    const origin = new URL(ctx.target.url).origin;

    // robots.txt and sitemap.xml are plain files; the reader returns their text.
    //
    // The reader reports HTTP 200 for its own successful fetch even when the
    // target answered 404, so its status says nothing about whether the file
    // exists. Text mode carries no status at all. JSON mode is the only one
    // that reports the target's real status, as `data.httpStatus`, but it
    // converts XML to markdown. So each file is read twice: JSON for the
    // status, text for the body that has to be parsed byte-faithfully. Both
    // bypass the reader cache, because a cached entry can predate the file.
    const readStatus = (path: string) =>
      ctx.net.json<{ code?: number; data?: { httpStatus?: number; finalUrl?: string } }>(
        `https://r.jina.ai/${origin}${path}`,
        {
          timeoutMs: 25_000,
          headers: { "x-no-cache": "true" },
          cacheKey: `status:${origin}${path}`,
        }
      );

    const readBody = (path: string, key: string) =>
      ctx.net.text(`https://r.jina.ai/${origin}${path}`, {
        timeoutMs: 20_000,
        headers: { "x-respond-with": "text", "x-no-cache": "true" },
        cacheKey: key,
      });

    const [robotsRes, sitemapRes, robotsStatusRes, sitemapStatusRes] = await Promise.all([
      readBody("/robots.txt", `robots:${origin}`),
      readBody("/sitemap.xml", `sitemap:${origin}`),
      readStatus("/robots.txt"),
      readStatus("/sitemap.xml"),
    ]);

    // The target's own status, when the reader reported one. `null` means the
    // status could not be established, which is different from a 404 and must
    // not be treated as absence.
    const targetStatus = (res: typeof robotsStatusRes): number | null => {
      if (!res.ok) return null;
      const s = res.json?.data?.httpStatus;
      return typeof s === "number" ? s : null;
    };
    const robotsStatus = targetStatus(robotsStatusRes);
    const sitemapStatus = targetStatus(sitemapStatusRes);

    const findings: Finding[] = [];

    // A failed fetch is not an absent file. The reader rate limits at 20
    // requests a minute, and a 429 here would otherwise be reported as "no
    // robots.txt", which is a fabricated finding. Only a successful response
    // that is empty or not a robots file counts as absent.
    const robotsReadable = robotsRes.ok;
    const sitemapReadable = sitemapRes.ok;

    // --- robots.txt ---
    const robotsText = robotsRes.ok ? robotsRes.text : "";
    const looksLikeHtml = /<html|<!doctype html/i.test(robotsText.slice(0, 300));
    // A robots.txt is a list of `directive: value` lines. Anything without a
    // single recognised directive is not one, whatever it is: an error page, a
    // consent wall, or the target's own 404 body, which the reader serves as a
    // 200. This body test is the primary signal because text mode carries no
    // status; the status probe below corroborates it.
    const looksLikeRobots =
      /^\s*(user-agent|disallow|allow|sitemap|crawl-delay|host|clean-param)\s*:/im.test(robotsText);
    const robotsMissing = robotsStatus === 404 || robotsStatus === 410;
    const robotsFound =
      robotsRes.ok && !robotsMissing && robotsText.trim().length > 0 && !looksLikeHtml && looksLikeRobots;
    const sitemaps = [...robotsText.matchAll(/^\s*sitemap:\s*(\S+)/gim)].map((m) => m[1]);
    const disallowAll = /^\s*user-agent:\s*\*\s*$[\s\S]{0,200}?^\s*disallow:\s*\/\s*$/im.test(robotsText);
    const groups = (robotsText.match(/^\s*user-agent:/gim) ?? []).length;

    // Absence is claimed only from a body we actually read. A failed request
    // proves nothing, so it yields no finding either way.
    if (robotsReadable && !robotsFound) {
      findings.push({
        id: "seo-no-robots",
        title: "No robots.txt",
        detail: "The site publishes no robots.txt. Crawlers fall back to fetching everything, which is usually harmless but leaves crawl budget unmanaged.",
        severity: "low",
        remediation: "Add a robots.txt at the root that names your sitemap and blocks only paths you truly do not want indexed.",
        reference: { label: "RFC 9309", url: "https://www.rfc-editor.org/rfc/rfc9309.html" },
      });
    } else if (robotsFound && disallowAll) {
      findings.push({
        id: "seo-robots-blocks-all",
        title: "robots.txt blocks every crawler from the whole site",
        detail: "A User-agent: * group disallows /. If this was not deliberate, the site will drop out of search results.",
        severity: "high",
        remediation: "Remove the Disallow: / line, or scope it to the paths that should not be crawled.",
        reference: { label: "RFC 9309", url: "https://www.rfc-editor.org/rfc/rfc9309.html" },
      });
    } else if (robotsFound && sitemaps.length === 0) {
      findings.push({
        id: "seo-no-sitemap-declared",
        title: "robots.txt does not declare a sitemap",
        detail: "Crawlers can still find pages, but a Sitemap: line is how you point them at the full set.",
        severity: "low",
        remediation: "Add Sitemap: https://yourdomain/sitemap.xml to robots.txt.",
      });
    }

    // --- sitemap ---
    const sitemapText = sitemapRes.ok ? sitemapRes.text : "";
    const sitemapIsXml = /<urlset|<sitemapindex/i.test(sitemapText);
    const sitemapMissing = sitemapStatus === 404 || sitemapStatus === 410;
    const rootSitemapFound = sitemapReadable && !sitemapMissing && sitemapIsXml;

    // A sitemap declared in robots.txt frequently lives somewhere other than
    // /sitemap.xml, such as /sitemap_index.xml or a CDN path. The old code read
    // only the root path and then reported "no sitemap" while the robots file it
    // had just parsed named one. The declared URL is fetched when it differs.
    let declaredSitemapFound = false;
    let declaredSitemapText = "";
    const declaredUrl = sitemaps[0] ?? null;
    if (!rootSitemapFound && declaredUrl) {
      let declaredPath = "";
      try {
        const u = new URL(declaredUrl, origin);
        // The reader needs an absolute URL; a cross-origin sitemap is followed
        // only when it is on the same site, so a scan cannot be pointed at an
        // arbitrary third-party document by a robots file.
        if (u.origin === origin) declaredPath = u.pathname + u.search;
      } catch {
        declaredPath = "";
      }
      if (declaredPath && declaredPath !== "/sitemap.xml") {
        const declaredRes = await readBody(declaredPath, `sitemap-declared:${origin}`);
        if (declaredRes.ok) {
          declaredSitemapText = declaredRes.text;
          declaredSitemapFound = /<urlset|<sitemapindex/i.test(declaredSitemapText);
        }
      }
    }

    const sitemapFound = rootSitemapFound || declaredSitemapFound;
    const effectiveSitemapText = rootSitemapFound ? sitemapText : declaredSitemapText;
    const urlCount = (effectiveSitemapText.match(/<url>/g) ?? []).length;
    const isIndex = /<sitemapindex/i.test(effectiveSitemapText);
    const sitemapUrl = sitemapFound
      ? rootSitemapFound
        ? `${origin}/sitemap.xml`
        : declaredUrl
      : null;

    if ((sitemapReadable || declaredUrl) && !sitemapFound) {
      findings.push({
        id: "seo-no-sitemap",
        title: "No sitemap could be read",
        detail: declaredUrl
          ? `robots.txt declares ${declaredUrl}, but neither that file nor ${origin}/sitemap.xml could be read as a sitemap.`
          : `Neither ${origin}/sitemap.xml nor a sitemap declared in robots.txt could be read.`,
        severity: "low",
        remediation: "Generate a sitemap and reference it from robots.txt.",
        reference: { label: "sitemaps.org", url: "https://www.sitemaps.org/protocol.html" },
      });
    }

    // --- document-level ---
    let canonical: string | null = null;
    let canonicalMatches = false;
    let metaRobots: string | null = null;
    const og: Record<string, string> = {};
    const twitter: Record<string, string> = {};
    let structuredTypes: string[] = [];
    let titleLength = 0;
    let descriptionLength = 0;

    if (doc) {
      canonical = doc.querySelector('link[rel="canonical" i]')?.getAttribute("href") ?? null;
      if (canonical) {
        try {
          const c = new URL(canonical, origin);
          // Same site, not same host: a canonical pointing from the apex to
          // www (or the reverse) is the normal consolidation pattern, not an
          // off-site canonical. Only a different registrable domain is the
          // defect this finding describes.
          canonicalMatches = isSameSite(c.hostname, ctx.target);
        } catch {
          canonicalMatches = false;
        }
      }
      metaRobots = doc.querySelector('meta[name="robots" i]')?.getAttribute("content") ?? null;

      for (const el of Array.from(doc.querySelectorAll('meta[property^="og:" i]'))) {
        const key = el.getAttribute("property")!.toLowerCase();
        og[key] = el.getAttribute("content") ?? "";
      }
      for (const el of Array.from(doc.querySelectorAll('meta[name^="twitter:" i]'))) {
        const key = el.getAttribute("name")!.toLowerCase();
        twitter[key] = el.getAttribute("content") ?? "";
      }

      const ld = Array.from(doc.querySelectorAll('script[type="application/ld+json" i]'));
      const types = new Set<string>();
      for (const script of ld) {
        try {
          const parsed = JSON.parse(script.textContent ?? "{}");
          const collect = (node: unknown) => {
            if (!node || typeof node !== "object") return;
            const obj = node as Record<string, unknown>;
            if (typeof obj["@type"] === "string") types.add(obj["@type"]);
            if (Array.isArray(obj["@type"])) for (const t of obj["@type"]) if (typeof t === "string") types.add(t);
            if (Array.isArray(obj["@graph"])) for (const g of obj["@graph"]) collect(g);
          };
          collect(parsed);
        } catch {
          // Malformed JSON-LD is common and not worth a separate finding.
        }
      }
      structuredTypes = [...types];

      const t = doc.querySelector("title")?.textContent?.trim() ?? "";
      const d = doc.querySelector('meta[name="description" i]')?.getAttribute("content")?.trim() ?? "";
      titleLength = t.length;
      descriptionLength = d.length;

      if (t.length > 60) {
        findings.push({
          id: "seo-title-long",
          title: `Title is ${t.length} characters`,
          detail: "Titles longer than about 60 characters are truncated in search results, so the end is never seen.",
          severity: "low",
          remediation: "Lead with the specific subject and keep the title under 60 characters.",
        });
      }
      if (d.length === 0) {
        findings.push({
          id: "seo-no-description",
          title: "No meta description",
          detail: "Without a description, search engines write their own snippet from page text, which is rarely the message you would choose.",
          severity: "medium",
          remediation: "Add a 120 to 155 character description that states what the page offers.",
        });
      } else if (d.length > 160) {
        findings.push({
          id: "seo-description-long",
          title: `Meta description is ${d.length} characters`,
          detail: "Descriptions over about 160 characters are cut off in results.",
          severity: "low",
          remediation: "Trim to under 160 characters, keeping the distinguishing detail first.",
        });
      }

      if (metaRobots && /noindex/i.test(metaRobots)) {
        findings.push({
          id: "seo-noindex",
          title: "The page sets noindex",
          detail: `The meta robots tag reads "${metaRobots}", which removes this page from search results.`,
          severity: "high",
          remediation: "Remove noindex if this page should be discoverable. It is a common leftover from staging.",
        });
      }

      if (!canonical) {
        findings.push({
          id: "seo-no-canonical",
          title: "No canonical link",
          detail: "Without a canonical, the same content reachable at several URLs is treated as several pages and splits ranking.",
          severity: "low",
          remediation: 'Add <link rel="canonical" href="https://yourdomain/page"> to each page.',
          reference: { label: "Google: canonical URLs", url: "https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls" },
        });
      } else if (!canonicalMatches) {
        findings.push({
          id: "seo-canonical-offsite",
          title: "The canonical points at a different host",
          detail: `The canonical is ${canonical}, which is not this host. Every page will be credited to that host instead.`,
          severity: "medium",
          remediation: "Point the canonical at the URL you want indexed, on the host that serves it.",
        });
      }

      if (Object.keys(og).length === 0) {
        findings.push({
          id: "seo-no-og",
          title: "No Open Graph tags",
          detail: "Links shared to social platforms and chat apps will render as a bare URL instead of a card with a title and image.",
          severity: "low",
          remediation: "Add og:title, og:description, og:image and og:url.",
          reference: { label: "Open Graph protocol", url: "https://ogp.me/" },
        });
      } else if (!og["og:image"]) {
        findings.push({
          id: "seo-no-og-image",
          title: "Open Graph tags have no image",
          detail: "Shared links will show a text-only card, which gets measurably fewer clicks than one with an image.",
          severity: "low",
          remediation: "Add og:image at 1200x630 and og:image:alt describing it.",
        });
      }
    }

    const serious = findings.filter((f) => f.severity === "high" || f.severity === "critical");

    // Document-derived findings are impossible without a document, and
    // reporting "no canonical, no description" for a page that was never read
    // is a fabricated finding. The file checks above are still real, so the
    // result degrades to a partial report rather than a false clean one.
    const docMissing = !doc;
    const status: CheckResult["status"] = docMissing
      ? "unavailable"
      : serious.length > 0
        ? "fail"
        : findings.length > 0
          ? "warn"
          : "pass";

    const sourceParts: string[] = [];
    if (robotsReadable || sitemapReadable) sourceParts.push("r.jina.ai reader for robots.txt and sitemap.xml");
    if (doc && page.via !== "unavailable") sourceParts.push(page.via);
    const source = sourceParts.length > 0 ? sourceParts.join(", ") : "unavailable";

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline: docMissing
        ? `The document could not be read, so canonical, description and preview tags were not judged.${findings.length > 0 ? ` ${findings.length} file-level issue${findings.length === 1 ? "" : "s"} found.` : ""}`
        : findings.length === 0
          ? "Crawl directives, canonical, sitemap and preview tags are all in place."
          : `${findings.length} SEO issue${findings.length === 1 ? "" : "s"} across crawl rules, canonical and preview tags.`,
      findings,
      data: {
        robotsTxt: { found: robotsFound, status: robotsStatus ?? (robotsRes.ok ? robotsRes.status : 0), sitemaps, disallowAll, groups },
        sitemap: { found: sitemapFound, url: sitemapUrl, urlCount, isIndex, status: sitemapStatus ?? (sitemapRes.ok ? sitemapRes.status : 0) },
        canonical,
        canonicalMatches,
        metaRobots,
        og,
        twitter,
        hasStructuredData: structuredTypes.length > 0,
        structuredTypes,
        titleLength,
        descriptionLength,
      } satisfies SeoData,
      ms: Math.round(performance.now() - started),
      source,
      note: docMissing
        ? "The document reader returned no HTML. Canonical, meta description, Open Graph and structured data all live in the document, so none of them were judged. This is not a clean result."
        : undefined,
    };
  },
};
