/**
 * Performance signals that can be measured without a browser run.
 *
 * There is no Lighthouse here and no field data. The check reads the fetched
 * document and the response headers, which covers what is in the markup
 * (render-blocking tags, image attributes, DOM size, inline payload) and what
 * the server says (compression, caching, validators). Anything that needs a
 * timeline is named as not measured, because a performance verdict invented
 * from a static fetch would be a lie.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { header } from "../net/document";

export type PerformanceData = {
  /** Characters in the HTML the reader returned. Not the compressed wire size. */
  documentBytes: number;
  /** Resources referenced in the document. Nothing here proves they were requested. */
  requests: { scripts: number; stylesheets: number; images: number; thirdParty: number };
  renderBlocking: { scripts: number; stylesheets: number; urls: string[] };
  images: { total: number; noDimensions: number; noLazy: number; noSrcset: number };
  encoding: string | null;
  cacheControl: string | null;
  hasEtag: boolean;
  hasLastModified: boolean;
  /** Characters of inline script and style content. */
  inlineBytes: number;
  domNodes: number;
};

// The export below is named `performance` to match the registry id, and that
// name shadows the global Performance API for the whole module. Timing is
// therefore read through globalThis explicitly. Without the qualifier the
// compiler resolves `performance.now` against CheckDefinition and fails.
export const performance: CheckDefinition = {
  id: "performance",
  title: "Page weight and loading",
  question: "What does the document ask the browser to download before it can paint, and what do the headers say about delivery?",
  group: "performance",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = globalThis.performance.now();
    const [page, snapshot] = await Promise.all([ctx.html(), ctx.headers()]);
    const doc = page.doc;

    if (!doc) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The document could not be retrieved for performance analysis.",
        findings: [],
        ms: Math.round(globalThis.performance.now() - started),
        source: page.via,
        note: "The document reader returned no HTML, so there is no markup to measure. Timings such as Largest Contentful Paint and Total Blocking Time need a real browser run and are not measured here.",
      };
    }

    const documentBytes = page.source.length;
    const head = doc.head;

    const scripts = Array.from(doc.querySelectorAll("script[src]"));
    const stylesheets = Array.from(doc.querySelectorAll('link[rel~="stylesheet" i][href]'));
    const images = Array.from(doc.querySelectorAll("img"));

    const selfHost = ctx.target.host.toLowerCase();
    const isThirdParty = (url: string): boolean => {
      try {
        const host = new URL(url, ctx.target.url).hostname.toLowerCase();
        return host !== selfHost && !host.endsWith("." + selfHost);
      } catch {
        return false;
      }
    };

    // --- render-blocking resources ---
    // A script with src blocks parsing unless it is async, defer, or a module
    // (modules are deferred by specification). A stylesheet blocks rendering
    // unless it is print-only. Both rules are decided by the tag alone.
    const blockingUrls: string[] = [];
    let blockingScripts = 0;
    let blockingStylesheets = 0;
    if (head) {
      for (const el of Array.from(head.querySelectorAll("script[src]"))) {
        const type = (el.getAttribute("type") ?? "").trim().toLowerCase();
        if (type === "module") continue;
        if (el.hasAttribute("async") || el.hasAttribute("defer")) continue;
        blockingScripts++;
        blockingUrls.push((el.getAttribute("src") ?? "").slice(0, 160));
      }
      for (const el of Array.from(head.querySelectorAll('link[rel~="stylesheet" i][href]'))) {
        const media = (el.getAttribute("media") ?? "").trim().toLowerCase();
        if (media === "print") continue;
        blockingStylesheets++;
        blockingUrls.push((el.getAttribute("href") ?? "").slice(0, 160));
      }
    }

    // --- image hygiene ---
    // Dimensions are read from attributes only. A width set in a stylesheet is
    // invisible here. The lazy count treats every image as below the fold
    // because the fold position needs a layout pass.
    let noDimensions = 0;
    let noLazy = 0;
    let noSrcset = 0;
    for (const img of images) {
      if (!img.hasAttribute("width") || !img.hasAttribute("height")) noDimensions++;
      if ((img.getAttribute("loading") ?? "").trim().toLowerCase() !== "lazy") noLazy++;
      const inPicture = img.closest("picture")?.querySelector("source[srcset]");
      if (!img.hasAttribute("srcset") && !inPicture) noSrcset++;
    }

    let thirdParty = 0;
    for (const el of scripts) if (isThirdParty(el.getAttribute("src") ?? "")) thirdParty++;
    for (const el of stylesheets) if (isThirdParty(el.getAttribute("href") ?? "")) thirdParty++;
    for (const el of images) if (isThirdParty(el.getAttribute("src") ?? "")) thirdParty++;

    // --- inline payload ---
    let inlineBytes = 0;
    for (const el of Array.from(doc.querySelectorAll("script:not([src])"))) {
      inlineBytes += (el.textContent ?? "").length;
    }
    for (const el of Array.from(doc.querySelectorAll("style"))) {
      inlineBytes += (el.textContent ?? "").length;
    }

    const domNodes = doc.querySelectorAll("*").length;

    // --- response headers ---
    // A failed header fetch must not be read as "the site sends nothing".
    const headersAvailable = snapshot.via !== "unavailable" && snapshot.status > 0;
    const encoding = headersAvailable ? header(snapshot, "content-encoding") ?? null : null;
    const cacheControl = headersAvailable ? header(snapshot, "cache-control") ?? null : null;
    const hasEtag = headersAvailable && header(snapshot, "etag") !== undefined;
    const hasLastModified = headersAvailable && header(snapshot, "last-modified") !== undefined;
    const contentType = headersAvailable ? header(snapshot, "content-type") ?? null : null;

    const findings: Finding[] = [];
    const totalBlocking = blockingScripts + blockingStylesheets;
    const kb = Math.round(documentBytes / 1024);

    if (totalBlocking > 3) {
      findings.push({
        id: "performance-render-blocking",
        title: `${totalBlocking} render-blocking resources in the head`,
        detail: `${blockingScripts} script${blockingScripts === 1 ? "" : "s"} without async or defer and ${blockingStylesheets} stylesheet${blockingStylesheets === 1 ? "" : "s"} must load before the browser can paint anything.`,
        severity: "medium",
        remediation:
          "Add defer to scripts that do not need to run before paint, and load only the critical CSS in the head. Preload the rest and apply it after first paint.",
        reference: {
          label: "MDN: Render blocking",
          url: "https://developer.mozilla.org/en-US/docs/Glossary/Render_blocking",
        },
        evidence: blockingUrls.slice(0, 8).map((url) => ({ label: "Blocking", value: url, tone: "bad" })),
      });
    }

    const isHtml = !contentType || /text\/html|application\/xhtml\+xml/i.test(contentType);
    if (headersAvailable && isHtml && !encoding && documentBytes > 8 * 1024) {
      findings.push({
        id: "performance-no-compression",
        title: "The HTML response is not compressed",
        detail: `No Content-Encoding header is set while the HTML is ${kb} KB, above the 8 KB point where compression starts to matter. Text compresses well with gzip or brotli.`,
        severity: "medium",
        remediation: "Enable gzip or brotli for text/html at the origin or the CDN in front of it.",
        reference: {
          label: "MDN: Content-Encoding",
          url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding",
        },
        evidence: contentType ? [{ label: "Content-Type", value: contentType, tone: "neutral" }] : undefined,
      });
    }

    if (headersAvailable && (!cacheControl || /\bno-store\b/i.test(cacheControl))) {
      findings.push({
        id: "performance-cache-control",
        title: cacheControl ? "Cache-Control forbids storage" : "No Cache-Control header",
        detail: cacheControl
          ? `Cache-Control is set to ${cacheControl}, so the browser cannot reuse the HTML between visits and every navigation downloads it again.`
          : "The response sends no Cache-Control header, so the browser falls back to heuristic freshness and any shared cache has no explicit instruction.",
        severity: "low",
        remediation:
          "Send Cache-Control with an explicit max-age for the HTML, and a longer max-age with a content hash for static assets.",
        reference: {
          label: "MDN: Cache-Control",
          url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
        },
      });
    }

    if (headersAvailable && !hasEtag && !hasLastModified) {
      findings.push({
        id: "performance-no-validators",
        title: "No ETag and no Last-Modified",
        detail: "The response carries neither validator, so a returning visitor cannot revalidate the page and must download it in full.",
        severity: "low",
        remediation: "Let the server emit an ETag or a Last-Modified header so a conditional request can return 304 with no body.",
        reference: {
          label: "MDN: ETag",
          url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag",
        },
      });
    }

    if (noDimensions > 0) {
      findings.push({
        id: "performance-image-dimensions",
        title: `${noDimensions} image${noDimensions === 1 ? "" : "s"} without width and height attributes`,
        detail: `${noDimensions} of ${images.length} images declare no width or height, so the browser cannot reserve their space before they load and the content below them shifts.`,
        severity: "medium",
        remediation:
          "Set the intrinsic width and height attributes on every image, or an aspect-ratio in CSS. The browser then reserves the space before the file arrives.",
        reference: { label: "web.dev: Optimize Cumulative Layout Shift", url: "https://web.dev/articles/optimize-cls" },
      });
    }

    if (images.length > 5 && noLazy === images.length) {
      findings.push({
        id: "performance-image-lazy",
        title: "No image uses loading=lazy",
        detail: `None of the ${images.length} images use loading="lazy", so all of them are fetched as the page loads. This count treats every image as below the fold, since the fold position needs a layout pass.`,
        severity: "low",
        remediation:
          'Add loading="lazy" to images below the fold. Leave images in the first viewport eager, since deferring them delays the largest paint.',
        reference: {
          label: "MDN: img loading attribute",
          url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/img#loading",
        },
      });
    }

    if (domNodes > 1500) {
      findings.push({
        id: "performance-dom-size",
        title: `${domNodes} elements in the document`,
        detail: `The document holds ${domNodes} elements. Lighthouse flags pages above 1500 nodes as having an excessive DOM size, which raises style recalculation cost and memory use. That figure is a heuristic, not a measurement of this page.`,
        severity: "low",
        remediation:
          "Remove wrapper elements that carry no style or behaviour, and render long lists in pages rather than all at once.",
        reference: {
          label: "Lighthouse: Avoid an excessive DOM size",
          url: "https://developer.chrome.com/docs/lighthouse/performance/dom-size/",
        },
      });
    }

    if (documentBytes > 250 * 1024) {
      findings.push({
        id: "performance-document-size",
        title: `The HTML document is ${kb} KB`,
        detail: `The fetched HTML is ${documentBytes} characters, above the 250 KB threshold used here. Large documents delay the first byte of parseable markup and cost more on every uncached visit.`,
        severity: "medium",
        remediation:
          "Move inline data and serialized state into a separate request, remove markup that is never shown, and confirm compression is on.",
        reference: {
          label: "Lighthouse: Total byte weight",
          url: "https://developer.chrome.com/docs/lighthouse/performance/total-byte-weight/",
        },
      });
    }

    if (images.length > 3 && noSrcset === images.length) {
      findings.push({
        id: "performance-image-srcset",
        title: "No image declares srcset",
        detail: `None of the ${images.length} images declare srcset or sit inside a picture element, so every visitor downloads the same file regardless of viewport width or pixel density.`,
        severity: "info",
        reference: {
          label: "MDN: Responsive images",
          url: "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/img#srcset",
        },
      });
    }

    const actionable = findings.filter((f) => f.severity !== "info");
    const mediums = actionable.filter(
      (f) => f.severity === "medium" || f.severity === "high" || f.severity === "critical"
    ).length;
    const status: CheckResult["status"] =
      mediums >= 3 ? "fail" : actionable.length > 0 ? "warn" : findings.length > 0 ? "info" : "pass";

    const headline =
      actionable.length === 0
        ? `${documentBytes} characters of HTML, ${totalBlocking} render-blocking resource${totalBlocking === 1 ? "" : "s"}, ${images.length} image${images.length === 1 ? "" : "s"} and ${domNodes} DOM nodes, with nothing above the reporting threshold.`
        : `${actionable.length} performance issue${actionable.length === 1 ? "" : "s"} across ${totalBlocking} render-blocking resources, ${images.length} images and ${domNodes} DOM nodes.`;

    const notes = [
      "Timings such as Largest Contentful Paint and Total Blocking Time need a real browser run and are not measured here.",
      "Document size is the character count of the HTML the reader returned, not the compressed byte count on the wire.",
    ];
    if (!headersAvailable) {
      notes.push("Response headers could not be retrieved, so compression, caching and validators were not judged.");
    }
    if (page.suspectInterstitial) {
      notes.push("The fetched document looked like a consent wall or bot check, so these figures may describe that gate rather than the page.");
    }

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        documentBytes,
        requests: {
          scripts: scripts.length,
          stylesheets: stylesheets.length,
          images: images.length,
          thirdParty,
        },
        renderBlocking: {
          scripts: blockingScripts,
          stylesheets: blockingStylesheets,
          urls: blockingUrls.slice(0, 20),
        },
        images: {
          total: images.length,
          noDimensions,
          noLazy,
          noSrcset,
        },
        encoding,
        cacheControl,
        hasEtag,
        hasLastModified,
        inlineBytes,
        domNodes,
      } satisfies PerformanceData,
      ms: Math.round(globalThis.performance.now() - started),
      source: "Fetched document and response headers",
      note: notes.join(" "),
    };
  },
};
