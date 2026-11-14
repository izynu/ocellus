/**
 * Cookies, third-party requests and privacy.
 *
 * Set-Cookie is visible in the response headers, so cookie flags can be judged
 * exactly. What cannot be seen without running the page is which trackers
 * actually execute, so the third-party list here comes from the document's own
 * script and iframe sources, matched against a known tracker list. That is a
 * lower bound and the report says so.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { headerAll } from "../net/document";
import { isSameSite } from "../target";

export type Cookie = {
  name: string;
  domain: string | null;
  path: string | null;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  maxAge: number | null;
  expires: string | null;
  /** Set by a third-party origin rather than the scanned host. */
  prefix: string | null;
};

export type TrackerHit = {
  domain: string;
  vendor: string;
  category: "analytics" | "advertising" | "session-replay" | "social" | "support" | "other";
  /** Number of references found in the document. */
  count: number;
  sample: string;
};

export type PrivacyData = {
  cookies: Cookie[];
  trackers: TrackerHit[];
  thirdPartyHosts: string[];
  /** References to plaintext http:// resources on an https page. */
  mixedContent: Array<{ tag: string; url: string }>;
  /** Scripts and stylesheets without an integrity attribute from another origin. */
  missingSri: number;
  externalScripts: number;
};

/** Tracker domains, grouped by what they do. Matched as suffix of the host. */
const TRACKERS: Array<{ domain: string; vendor: string; category: TrackerHit["category"] }> = [
  { domain: "google-analytics.com", vendor: "Google Analytics", category: "analytics" },
  { domain: "googletagmanager.com", vendor: "Google Tag Manager", category: "analytics" },
  { domain: "analytics.google.com", vendor: "Google Analytics", category: "analytics" },
  { domain: "doubleclick.net", vendor: "Google Ads", category: "advertising" },
  { domain: "googlesyndication.com", vendor: "Google AdSense", category: "advertising" },
  { domain: "googleadservices.com", vendor: "Google Ads", category: "advertising" },
  { domain: "facebook.net", vendor: "Meta Pixel", category: "advertising" },
  { domain: "connect.facebook.net", vendor: "Meta Pixel", category: "advertising" },
  { domain: "hotjar.com", vendor: "Hotjar", category: "session-replay" },
  { domain: "hotjar.io", vendor: "Hotjar", category: "session-replay" },
  { domain: "fullstory.com", vendor: "FullStory", category: "session-replay" },
  { domain: "clarity.ms", vendor: "Microsoft Clarity", category: "session-replay" },
  { domain: "mouseflow.com", vendor: "Mouseflow", category: "session-replay" },
  { domain: "smartlook.com", vendor: "Smartlook", category: "session-replay" },
  { domain: "segment.com", vendor: "Segment", category: "analytics" },
  { domain: "segment.io", vendor: "Segment", category: "analytics" },
  { domain: "mixpanel.com", vendor: "Mixpanel", category: "analytics" },
  { domain: "amplitude.com", vendor: "Amplitude", category: "analytics" },
  { domain: "heap.io", vendor: "Heap", category: "analytics" },
  { domain: "plausible.io", vendor: "Plausible", category: "analytics" },
  { domain: "matomo.cloud", vendor: "Matomo", category: "analytics" },
  { domain: "intercom.io", vendor: "Intercom", category: "support" },
  { domain: "intercomcdn.com", vendor: "Intercom", category: "support" },
  { domain: "zendesk.com", vendor: "Zendesk", category: "support" },
  { domain: "crisp.chat", vendor: "Crisp", category: "support" },
  { domain: "tawk.to", vendor: "Tawk.to", category: "support" },
  { domain: "drift.com", vendor: "Drift", category: "support" },
  { domain: "hubspot.com", vendor: "HubSpot", category: "advertising" },
  { domain: "hs-scripts.com", vendor: "HubSpot", category: "advertising" },
  { domain: "marketo.net", vendor: "Marketo", category: "advertising" },
  { domain: "pardot.com", vendor: "Pardot", category: "advertising" },
  { domain: "tiktok.com", vendor: "TikTok Pixel", category: "advertising" },
  { domain: "ads-twitter.com", vendor: "X Pixel", category: "advertising" },
  { domain: "static.ads-twitter.com", vendor: "X Pixel", category: "advertising" },
  { domain: "sc-static.net", vendor: "Snap Pixel", category: "advertising" },
  { domain: "linkedin.com", vendor: "LinkedIn Insight", category: "advertising" },
  { domain: "snap.licdn.com", vendor: "LinkedIn Insight", category: "advertising" },
  { domain: "pinterest.com", vendor: "Pinterest Tag", category: "advertising" },
  { domain: "ct.pinterest.com", vendor: "Pinterest Tag", category: "advertising" },
  { domain: "yandex.ru", vendor: "Yandex Metrica", category: "analytics" },
  { domain: "mc.yandex.ru", vendor: "Yandex Metrica", category: "analytics" },
  { domain: "newrelic.com", vendor: "New Relic", category: "other" },
  { domain: "sentry.io", vendor: "Sentry", category: "other" },
  { domain: "bugsnag.com", vendor: "Bugsnag", category: "other" },
  { domain: "cloudflareinsights.com", vendor: "Cloudflare Analytics", category: "analytics" },
  { domain: "stripe.com", vendor: "Stripe", category: "other" },
  { domain: "js.stripe.com", vendor: "Stripe", category: "other" },
  { domain: "cloudflare.com", vendor: "Cloudflare", category: "other" },
  { domain: "gstatic.com", vendor: "Google Static", category: "other" },
  { domain: "fonts.googleapis.com", vendor: "Google Fonts", category: "other" },
  { domain: "fonts.gstatic.com", vendor: "Google Fonts", category: "other" },
  { domain: "cdn.jsdelivr.net", vendor: "jsDelivr CDN", category: "other" },
  { domain: "unpkg.com", vendor: "unpkg CDN", category: "other" },
  { domain: "cdnjs.cloudflare.com", vendor: "cdnjs", category: "other" },
];

/**
 * Split one Set-Cookie header line into its cookies.
 *
 * The header source joins repeated Set-Cookie lines with ", ", and a single
 * line can legitimately carry several cookies. Splitting on every comma breaks
 * on the date in `expires=Sun, 14 Nov 2027 ...`, so a comma only starts a new
 * cookie when what follows is `name=` with no space before the equals sign.
 */
function splitSetCookieHeader(raw: string): string[] {
  return raw
    .split(/,(?=\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseSetCookie(raw: string): Cookie {
  const parts = raw.split(";").map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const eq = nameValue.indexOf("=");
  const name = eq >= 0 ? nameValue.slice(0, eq) : nameValue;
  const get = (key: string): string | null => {
    const found = attrs.find((a) => a.toLowerCase().startsWith(key + "="));
    return found ? found.slice(key.length + 1) : null;
  };
  const flag = (key: string) => attrs.some((a) => a.toLowerCase() === key);
  const maxAge = get("max-age");
  const prefix = name.startsWith("__Host-")
    ? "__Host-"
    : name.startsWith("__Secure-")
      ? "__Secure-"
      : null;
  return {
    name,
    domain: get("domain"),
    path: get("path"),
    secure: flag("secure"),
    httpOnly: flag("httponly"),
    sameSite: get("samesite"),
    maxAge: maxAge ? Number(maxAge) : null,
    expires: get("expires"),
    prefix,
  };
}

export const privacy: CheckDefinition = {
  id: "privacy",
  title: "Cookies and trackers",
  question: "What does this page set and load before a visitor has agreed to anything?",
  group: "privacy",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const [snapshot, page] = await Promise.all([ctx.headers(), ctx.html()]);

    const findings: Finding[] = [];
    // Without a header snapshot there are no Set-Cookie lines to judge. Reading
    // that absence as "this site sets no cookies" would be a clean verdict
    // awarded for a request that never succeeded, so the cookie half of the
    // check is reported as unmeasured instead.
    const headersAvailable = snapshot.via !== "unavailable" && snapshot.status !== 0;
    const rawCookies = headersAvailable
      ? headerAll(snapshot, "set-cookie").flatMap(splitSetCookieHeader)
      : [];
    const cookies = rawCookies.map(parseSetCookie);

    // --- cookie flags ---
    const insecure = cookies.filter((c) => !c.secure);
    const noHttpOnly = cookies.filter((c) => !c.httpOnly);
    const noSameSite = cookies.filter((c) => !c.sameSite);

    if (insecure.length > 0) {
      findings.push({
        id: "privacy-cookie-no-secure",
        title: `${insecure.length} cookie${insecure.length === 1 ? "" : "s"} without the Secure flag`,
        detail: `These cookies are sent over plaintext HTTP as well as HTTPS: ${insecure.slice(0, 5).map((c) => c.name).join(", ")}.`,
        severity: "high",
        remediation: "Add Secure to every cookie, or use the __Secure- prefix which requires it.",
        reference: { label: "OWASP: Secure Cookie Attribute", url: "https://owasp.org/www-community/controls/SecureCookieAttribute" },
        evidence: insecure.slice(0, 10).map((c) => ({ label: c.name, value: "no Secure", tone: "bad" })),
      });
    }
    if (noHttpOnly.length > 0) {
      findings.push({
        id: "privacy-cookie-no-httponly",
        title: `${noHttpOnly.length} cookie${noHttpOnly.length === 1 ? "" : "s"} readable from JavaScript`,
        detail: `Without HttpOnly, any injected script can read these cookies: ${noHttpOnly.slice(0, 5).map((c) => c.name).join(", ")}.`,
        severity: "medium",
        remediation: "Add HttpOnly to every cookie that the front end does not need to read.",
      });
    }
    if (noSameSite.length > 0) {
      findings.push({
        id: "privacy-cookie-no-samesite",
        title: `${noSameSite.length} cookie${noSameSite.length === 1 ? "" : "s"} without SameSite`,
        detail: "No SameSite attribute means the browser default applies, which varies by version. Being explicit is the only way to be sure.",
        severity: "low",
        remediation: "Add SameSite=Lax, or SameSite=Strict for cookies that should never travel cross-site.",
      });
    }

    // --- document-derived third parties ---
    const doc = page.doc;
    const trackerMap = new Map<string, TrackerHit>();
    const thirdPartyHosts = new Set<string>();
    const mixedContent: Array<{ tag: string; url: string }> = [];
    let missingSri = 0;
    let externalScripts = 0;

    const hostOf = (url: string): string | null => {
      try {
        return new URL(url, ctx.target.url).hostname.toLowerCase();
      } catch {
        return null;
      }
    };

    // A bare `endsWith` test calls `notexample.com` first-party on a scan of
    // `example.com`, because the string really does end with it. The label
    // boundary is what makes it a suffix of the hostname rather than of the text,
    // and same-site (not same-host) is the right question for a third-party list:
    // a static asset on cdn.example.com is still first party.
    const isFirstParty = (host: string): boolean => isSameSite(host, ctx.target);

    const record = (url: string, tag: string) => {
      const host = hostOf(url);
      if (!host) return;
      const isThirdParty = !isFirstParty(host);
      if (isThirdParty) thirdPartyHosts.add(host);

      if (ctx.target.scheme === "https" && url.startsWith("http://")) {
        mixedContent.push({ tag, url: url.slice(0, 160) });
      }

      for (const t of TRACKERS) {
        if (host === t.domain || host.endsWith("." + t.domain)) {
          const key = t.vendor;
          const existing = trackerMap.get(key);
          if (existing) existing.count++;
          else
            trackerMap.set(key, {
              domain: t.domain,
              vendor: t.vendor,
              category: t.category,
              count: 1,
              sample: url.slice(0, 160),
            });
          break;
        }
      }
    };

    if (doc) {
      for (const el of Array.from(doc.querySelectorAll("script[src]"))) {
        const src = el.getAttribute("src") ?? "";
        record(src, "script");
        const host = hostOf(src);
        if (host && !isFirstParty(host)) {
          externalScripts++;
          if (!el.getAttribute("integrity")) missingSri++;
        }
      }
      for (const el of Array.from(doc.querySelectorAll("link[rel=stylesheet][href]"))) {
        const href = el.getAttribute("href") ?? "";
        record(href, "stylesheet");
        const host = hostOf(href);
        if (host && !isFirstParty(host) && !el.getAttribute("integrity")) missingSri++;
      }
      for (const el of Array.from(doc.querySelectorAll("iframe[src]"))) {
        record(el.getAttribute("src") ?? "", "iframe");
      }
      for (const el of Array.from(doc.querySelectorAll("img[src], source[srcset]"))) {
        const src = el.getAttribute("src") ?? el.getAttribute("srcset") ?? "";
        record(src, el.tagName.toLowerCase());
      }
    }

    const trackers = [...trackerMap.values()].sort((a, b) => b.count - a.count);
    const adTrackers = trackers.filter((t) => t.category === "advertising");
    const replay = trackers.filter((t) => t.category === "session-replay");

    if (adTrackers.length > 0) {
      findings.push({
        id: "privacy-ad-trackers",
        title: `${adTrackers.length} advertising tracker${adTrackers.length === 1 ? "" : "s"} load on page load`,
        detail: `${adTrackers.map((t) => t.vendor).join(", ")} are referenced in the document. Each one receives the visitor's IP and referrer before any consent interaction.`,
        severity: "high",
        remediation:
          "Gate advertising scripts behind consent, and load them only after the visitor has agreed. Under GDPR and the ePrivacy Directive, pre-consent loading is the violation, not the cookie itself.",
        reference: { label: "EDPB Guidelines 05/2020", url: "https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en" },
        evidence: adTrackers.map((t) => ({ label: t.vendor, value: `${t.count} reference${t.count === 1 ? "" : "s"}`, tone: "bad" })),
      });
    }

    if (replay.length > 0) {
      findings.push({
        id: "privacy-session-replay",
        title: `${replay.length} session recording tool${replay.length === 1 ? "" : "s"} detected`,
        detail: `${replay.map((t) => t.vendor).join(", ")} record interaction. These capture keystrokes and page content unless explicitly masked, which makes them a data-protection risk on any page with a form.`,
        severity: "high",
        remediation:
          "Mask all input fields and any personal data in the recording config, and disclose the recording in your privacy notice.",
      });
    }

    if (mixedContent.length > 0) {
      findings.push({
        id: "privacy-mixed-content",
        title: `${mixedContent.length} resource${mixedContent.length === 1 ? "" : "s"} load over plaintext http://`,
        detail: "An HTTPS page that loads http:// resources has an unencrypted channel into the page. Browsers block active mixed content and warn on passive content.",
        severity: "high",
        remediation: "Serve every resource over https://, or add upgrade-insecure-requests to the CSP.",
        reference: { label: "MDN: Mixed content", url: "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content" },
        evidence: mixedContent.slice(0, 10).map((m) => ({ label: m.tag, value: m.url, tone: "bad" })),
      });
    }

    if (missingSri > 0 && externalScripts > 0) {
      findings.push({
        id: "privacy-no-sri",
        title: `${missingSri} cross-origin resource${missingSri === 1 ? "" : "s"} without Subresource Integrity`,
        detail: "Without an integrity hash, a compromised or malicious CDN can change the script that runs on this page.",
        severity: "medium",
        remediation: "Add integrity and crossorigin attributes to scripts and stylesheets served from third-party origins.",
        reference: { label: "MDN: Subresource Integrity", url: "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity" },
      });
    }

    const serious = findings.filter((f) => f.severity === "high" || f.severity === "critical");
    const status: CheckResult["status"] =
      serious.length >= 2
        ? "fail"
        : findings.length > 0
          ? "warn"
          : // A clean verdict needs both halves to have run. With no header
            // snapshot, only the document was inspected, so the result is
            // reported as neutral information rather than a pass.
            headersAvailable
            ? "pass"
            : "info";

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline: !headersAvailable
        ? `Response headers could not be read, so cookies are unmeasured. ${trackers.length} known tracker${trackers.length === 1 ? " is" : "s are"} referenced and ${thirdPartyHosts.size} third-party host${thirdPartyHosts.size === 1 ? " is" : "s are"} present in the document.`
        : cookies.length === 0 && trackers.length === 0
          ? "No cookies are set on the first response and no known trackers are referenced."
          : `${cookies.length} cookie${cookies.length === 1 ? "" : "s"} on the first response, ${trackers.length} known tracker${trackers.length === 1 ? "" : "s"} referenced, ${thirdPartyHosts.size} third-party host${thirdPartyHosts.size === 1 ? "" : "s"} in total.`,
      findings,
      data: {
        cookies,
        trackers,
        thirdPartyHosts: [...thirdPartyHosts].sort(),
        mixedContent,
        missingSri,
        externalScripts,
      } satisfies PrivacyData,
      ms: Math.round(performance.now() - started),
      source: "Set-Cookie response headers plus document script and frame sources",
      note: headersAvailable
        ? "Tracker detection reads the document's references. Scripts injected at runtime are not visible without executing the page, so this is a lower bound."
        : "Tracker detection reads the document's references. The header source did not answer, so no cookie could be inspected; only the document half of this check ran.",
    };
  },
};
