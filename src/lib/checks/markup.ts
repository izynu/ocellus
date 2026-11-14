/**
 * Markup and accessibility, read from the fetched document without rendering.
 *
 * Everything here is a rule that can be decided from the DOM alone. Contrast is
 * the notable exception: computing it needs computed styles, which a fetched
 * document does not have, so it is not claimed. Every rule states what it
 * cannot see, because a false "all clear" on accessibility is worse than no
 * check at all.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { isSameSite } from "../target";

export type MarkupData = {
  title: string | null;
  titleLength: number;
  description: string | null;
  descriptionLength: number;
  lang: string | null;
  charset: string | null;
  viewport: string | null;
  canonical: string | null;
  robots: string | null;
  themeColor: string | null;
  headings: Array<{ level: number; text: string }>;
  headingCounts: Record<number, number>;
  images: { total: number; missingAlt: number; emptyAlt: number; samples: string[] };
  links: { total: number; empty: number; insecure: number; external: number };
  forms: { total: number; unlabeled: number };
  duplicateIds: string[];
  inlineStyles: number;
  inlineScripts: number;
  deprecatedTags: string[];
  /** Elements with tabindex greater than zero, which break tab order. */
  positiveTabindex: number;
  ariaIssues: string[];
};

const DEPRECATED = ["center", "font", "marquee", "blink", "big", "strike", "tt", "frame", "frameset"];

export const markup: CheckDefinition = {
  id: "markup",
  title: "Markup and accessibility",
  question: "Is the document structured correctly for people and for assistive technology?",
  group: "content",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const page = await ctx.html();
    const doc = page.doc;

    if (!doc) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The document could not be retrieved for markup analysis.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: page.via,
        note: "The document reader returned no HTML. This happens when a site blocks automated fetching entirely.",
      };
    }

    const findings: Finding[] = [];

    const title = doc.querySelector("title")?.textContent?.trim() ?? null;
    const description =
      doc.querySelector('meta[name="description" i]')?.getAttribute("content")?.trim() ?? null;
    const lang = doc.documentElement.getAttribute("lang");
    const charset =
      doc.querySelector("meta[charset]")?.getAttribute("charset") ??
      /charset=([\w-]+)/i.exec(doc.querySelector('meta[http-equiv="Content-Type" i]')?.getAttribute("content") ?? "")?.[1] ??
      null;
    const viewport = doc.querySelector('meta[name="viewport" i]')?.getAttribute("content") ?? null;
    const canonical = doc.querySelector('link[rel="canonical" i]')?.getAttribute("href") ?? null;
    const robots = doc.querySelector('meta[name="robots" i]')?.getAttribute("content") ?? null;
    const themeColor = doc.querySelector('meta[name="theme-color" i]')?.getAttribute("content") ?? null;

    // --- headings ---
    const headings: Array<{ level: number; text: string }> = [];
    const headingCounts: Record<number, number> = {};
    for (const el of Array.from(doc.querySelectorAll("h1,h2,h3,h4,h5,h6"))) {
      const level = Number(el.tagName[1]);
      headings.push({ level, text: (el.textContent ?? "").trim().slice(0, 120) });
      headingCounts[level] = (headingCounts[level] ?? 0) + 1;
    }
    const h1s = headingCounts[1] ?? 0;
    if (h1s === 0) {
      findings.push({
        id: "markup-no-h1",
        title: "No h1 heading",
        detail: "The page has no top-level heading, so screen reader users get no summary of what the page is.",
        severity: "medium",
        remediation: "Add exactly one h1 that names the page's subject.",
        reference: { label: "WCAG 1.3.1", url: "https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships.html" },
      });
    } else if (h1s > 1) {
      findings.push({
        id: "markup-many-h1",
        title: `${h1s} h1 headings`,
        detail: "More than one h1 flattens the document outline and makes the page's subject ambiguous.",
        severity: "low",
        remediation: "Keep one h1 per page and demote the rest to h2.",
      });
    }

    let skipped = 0;
    let prev = 0;
    for (const h of headings) {
      if (prev && h.level > prev + 1) skipped++;
      prev = h.level;
    }
    if (skipped > 0) {
      findings.push({
        id: "markup-heading-skip",
        title: `${skipped} heading level${skipped === 1 ? "" : "s"} skipped`,
        detail: "The outline jumps a level (for example h2 straight to h4), which breaks navigation by heading for assistive technology.",
        severity: "low",
        remediation: "Use heading levels in order. Style them with CSS rather than picking a level for its size.",
        reference: { label: "WCAG 1.3.1", url: "https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships.html" },
      });
    }

    // --- images ---
    const imgs = Array.from(doc.querySelectorAll("img"));
    const missingAlt: string[] = [];
    let emptyAlt = 0;
    for (const img of imgs) {
      const alt = img.getAttribute("alt");
      if (alt === null) {
        missingAlt.push(img.getAttribute("src")?.slice(0, 120) ?? "(inline image)");
      } else if (alt.trim() === "") {
        emptyAlt++;
      }
    }
    if (missingAlt.length > 0) {
      findings.push({
        id: "markup-alt-missing",
        title: `${missingAlt.length} image${missingAlt.length === 1 ? "" : "s"} without an alt attribute`,
        detail: "These images have no alt attribute at all. A screen reader will announce the file name or skip them entirely.",
        severity: "high",
        remediation:
          'Add a description to every meaningful image, and alt="" to purely decorative ones. The attribute must be present either way.',
        reference: { label: "WCAG 1.1.1", url: "https://www.w3.org/WAI/WCAG22/Understanding/non-text-content.html" },
        evidence: missingAlt.slice(0, 10).map((src) => ({ label: "Image", value: src, tone: "bad" })),
      });
    }

    // --- links ---
    const links = Array.from(doc.querySelectorAll("a[href]"));
    let emptyLinks = 0;
    let insecure = 0;
    let external = 0;
    for (const a of links) {
      const text = (a.textContent ?? "").trim();
      const hasLabel = text.length > 0 || a.getAttribute("aria-label") || a.querySelector("img[alt]:not([alt=''])");
      if (!hasLabel) emptyLinks++;
      const href = a.getAttribute("href") ?? "";
      if (href.startsWith("http://")) insecure++;
      // `includes` on the raw string counted example.com.evil.tld as internal
      // because the scanned host appears inside it. The hostname has to be
      // parsed out and compared on a label boundary.
      if (/^https?:\/\//i.test(href)) {
        try {
          const host = new URL(href).hostname.toLowerCase();
          if (!isSameSite(host, ctx.target)) external++;
        } catch {
          // A relative or malformed href cannot be a cross-site absolute link.
        }
      }
    }
    if (emptyLinks > 0) {
      findings.push({
        id: "markup-empty-links",
        title: `${emptyLinks} link${emptyLinks === 1 ? "" : "s"} with no accessible name`,
        detail: "These anchors have no text, no aria-label and no image with alt text, so a screen reader announces only \"link\".",
        severity: "high",
        remediation: "Give each link text that describes its destination, or an aria-label when the visual design requires an icon.",
        reference: { label: "WCAG 2.4.4", url: "https://www.w3.org/WAI/WCAG22/Understanding/link-purpose-in-context.html" },
      });
    }
    if (insecure > 0) {
      findings.push({
        id: "markup-insecure-links",
        title: `${insecure} link${insecure === 1 ? "" : "s"} to a plaintext http:// address`,
        detail: "Following these links drops the visitor out of HTTPS, where the connection can be read and modified.",
        severity: "medium",
        remediation: "Change http:// to https:// where the destination supports it, or remove the link.",
      });
    }

    // --- forms ---
    const inputs = Array.from(
      doc.querySelectorAll("input:not([type=hidden]):not([type=submit]):not([type=button]), select, textarea")
    );
    let unlabeled = 0;
    for (const input of inputs) {
      const id = input.getAttribute("id");
      const hasLabel =
        (id && doc.querySelector(`label[for="${CSS.escape(id)}"]`)) ||
        input.closest("label") ||
        input.getAttribute("aria-label") ||
        input.getAttribute("aria-labelledby") ||
        input.getAttribute("title");
      if (!hasLabel) unlabeled++;
    }
    if (unlabeled > 0) {
      findings.push({
        id: "markup-unlabeled-inputs",
        title: `${unlabeled} form field${unlabeled === 1 ? "" : "s"} without a label`,
        detail: "A placeholder is not a label: it disappears on input and is not reliably announced. These fields have neither a label element nor an aria-label.",
        severity: "high",
        remediation: "Pair each field with a <label for> element, or add aria-label when a visible label is impossible.",
        reference: { label: "WCAG 1.3.1", url: "https://www.w3.org/WAI/WCAG22/Understanding/info-and-relationships.html" },
      });
    }

    // --- ids and tabindex ---
    const idCounts = new Map<string, number>();
    for (const el of Array.from(doc.querySelectorAll("[id]"))) {
      const id = el.id;
      if (!id) continue;
      idCounts.set(id, (idCounts.get(id) ?? 0) + 1);
    }
    const duplicateIds = [...idCounts.entries()].filter(([, n]) => n > 1).map(([id]) => id);
    if (duplicateIds.length > 0) {
      findings.push({
        id: "markup-duplicate-ids",
        title: `${duplicateIds.length} duplicate id${duplicateIds.length === 1 ? "" : "s"}`,
        detail: `Duplicate ids break label associations and fragment links. Repeated: ${duplicateIds.slice(0, 5).join(", ")}.`,
        severity: "medium",
        remediation: "Make every id unique. Generated ids in component libraries are a common source.",
        reference: { label: "WCAG 4.1.1", url: "https://www.w3.org/WAI/WCAG22/Understanding/parsing.html" },
      });
    }

    const positiveTabindex = Array.from(doc.querySelectorAll("[tabindex]")).filter(
      (el) => Number(el.getAttribute("tabindex")) > 0
    ).length;
    if (positiveTabindex > 0) {
      findings.push({
        id: "markup-positive-tabindex",
        title: `${positiveTabindex} element${positiveTabindex === 1 ? "" : "s"} with a positive tabindex`,
        detail: "Positive tabindex values override the natural order and create a focus sequence that does not match the visual layout.",
        severity: "medium",
        remediation: "Use tabindex=\"0\" or restructure the DOM so source order matches reading order.",
        reference: { label: "WCAG 2.4.3", url: "https://www.w3.org/WAI/WCAG22/Understanding/focus-order.html" },
      });
    }

    // --- document-level ---
    if (!lang) {
      findings.push({
        id: "markup-no-lang",
        title: "The html element has no lang attribute",
        detail: "Without a language, screen readers may use the wrong pronunciation rules for the entire page.",
        severity: "high",
        remediation: 'Add lang to the root element, for example <html lang="en">.',
        reference: { label: "WCAG 3.1.1", url: "https://www.w3.org/WAI/WCAG22/Understanding/language-of-page.html" },
      });
    }
    if (!viewport) {
      findings.push({
        id: "markup-no-viewport",
        title: "No viewport meta tag",
        detail: "Mobile browsers will render the page at desktop width and scale it down, which makes text unreadably small.",
        severity: "high",
        remediation: 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.',
        reference: { label: "WCAG 1.4.10", url: "https://www.w3.org/WAI/WCAG22/Understanding/reflow.html" },
      });
    }
    if (!title) {
      findings.push({
        id: "markup-no-title",
        title: "The document has no title",
        detail: "The title is what a screen reader announces first and what a browser tab shows.",
        severity: "critical",
        remediation: "Add a unique, descriptive <title>.",
        reference: { label: "WCAG 2.4.2", url: "https://www.w3.org/WAI/WCAG22/Understanding/page-titled.html" },
      });
    }

    const deprecatedTags: string[] = [];
    for (const tag of DEPRECATED) {
      if (doc.querySelector(tag)) deprecatedTags.push(tag);
    }

    const inlineStyles = doc.querySelectorAll("[style]").length;
    const inlineScripts = doc.querySelectorAll("script:not([src])").length;

    const ariaIssues: string[] = [];
    for (const el of Array.from(doc.querySelectorAll("[role]"))) {
      const role = el.getAttribute("role");
      if (role && !/^[a-z]+$/.test(role)) ariaIssues.push(`invalid role "${role}"`);
    }
    const ariaHiddenFocusable = Array.from(doc.querySelectorAll('[aria-hidden="true"]')).filter(
      (el) => el.querySelector("a[href], button, input, select, textarea, [tabindex]")
    ).length;
    if (ariaHiddenFocusable > 0) {
      ariaIssues.push(`${ariaHiddenFocusable} aria-hidden containers hold focusable elements`);
    }
    if (ariaHiddenFocusable > 0) {
      findings.push({
        id: "markup-aria-hidden-focus",
        title: "aria-hidden container holds focusable elements",
        detail: "A container marked aria-hidden still has links or controls inside it. Keyboard users can focus them, but screen readers announce nothing.",
        severity: "high",
        remediation: "Add inert or tabindex=\"-1\" to the focusable children, or remove aria-hidden.",
        reference: { label: "WCAG 4.1.2", url: "https://www.w3.org/WAI/WCAG22/Understanding/name-role-value.html" },
      });
    }

    const serious = findings.filter((f) => f.severity === "critical" || f.severity === "high");
    const status: CheckResult["status"] =
      serious.length >= 3 ? "fail" : findings.length > 0 ? "warn" : "pass";

    // A fixed plural reads "across 1 images, 1 links and 1 form fields" on a
    // small page. Each count gets its own agreement.
    const n = (count: number, one: string, many: string) =>
      `${count} ${count === 1 ? one : many}`;
    const scope = `across ${n(imgs.length, "image", "images")}, ${n(links.length, "link", "links")} and ${n(inputs.length, "form field", "form fields")}`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline:
        findings.length === 0
          ? `No markup or accessibility problems were found ${scope}.`
          : `${findings.length} markup issue${findings.length === 1 ? "" : "s"} ${scope}.`,
      findings,
      data: {
        title,
        titleLength: title?.length ?? 0,
        description,
        descriptionLength: description?.length ?? 0,
        lang,
        charset,
        viewport,
        canonical,
        robots,
        themeColor,
        headings: headings.slice(0, 60),
        headingCounts,
        images: { total: imgs.length, missingAlt: missingAlt.length, emptyAlt, samples: missingAlt.slice(0, 8) },
        links: { total: links.length, empty: emptyLinks, insecure, external },
        forms: { total: inputs.length, unlabeled },
        duplicateIds,
        inlineStyles,
        inlineScripts,
        deprecatedTags,
        positiveTabindex,
        ariaIssues,
      } satisfies MarkupData,
      ms: Math.round(performance.now() - started),
      source: page.via,
      note:
        "Contrast, focus visibility and keyboard traps need a rendered page and are not assessed here.",
    };
  },
};
