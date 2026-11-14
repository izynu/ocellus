/**
 * What the site is built with, inferred from headers and markup only.
 *
 * No third-party API is involved on purpose. A fingerprinting service would
 * return a longer list, but it would also be the only part of a scan that
 * depends on someone else's rate limit, and it would answer with data this page
 * cannot show the evidence for. Every entry here carries the string that
 * produced it, so a reader can check the claim.
 *
 * The output is a lower bound. A framework that ships under a neutral filename
 * and sets no header is invisible to this method, and the report says so.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { header } from "../net/document";

export type TechItem = {
  name: string;
  category: string;
  /** The literal string that matched, truncated for display. */
  evidence: string;
  confidence: "high" | "medium" | "low";
};

export type TechStackData = {
  items: TechItem[];
  /** Count of entries whose category is a client library or framework. */
  libraries: number;
  server: string | null;
  poweredBy: string | null;
};

/** Headers that name infrastructure directly. Presence alone is high confidence. */
const HEADER_TECH: Array<{ header: string; name: string; category: string; match?: RegExp }> = [
  { header: "x-vercel-id", name: "Vercel", category: "Hosting" },
  { header: "x-nf-request-id", name: "Netlify", category: "Hosting" },
  { header: "x-amz-cf-id", name: "Amazon CloudFront", category: "CDN" },
  { header: "cf-ray", name: "Cloudflare", category: "CDN" },
  { header: "x-fastly-request-id", name: "Fastly", category: "CDN" },
  { header: "x-served-by", name: "Fastly", category: "CDN", match: /cache-/i },
  { header: "x-azure-ref", name: "Microsoft Azure", category: "Hosting" },
  { header: "x-github-request-id", name: "GitHub Pages", category: "Hosting" },
  { header: "x-nextjs-cache", name: "Next.js", category: "Framework" },
  { header: "x-litespeed-cache", name: "LiteSpeed", category: "Server" },
  { header: "x-drupal-cache", name: "Drupal", category: "CMS" },
  { header: "x-shopify-stage", name: "Shopify", category: "E-commerce" },
  { header: "x-aspnet-version", name: "ASP.NET", category: "Framework" },
  { header: "x-wp-total", name: "WordPress", category: "CMS" },
  { header: "via", name: "Forwarding proxy", category: "Infrastructure" },
];

/** Server and X-Powered-By values, mapped to a product name. */
const SERVER_PATTERNS: Array<{ match: RegExp; name: string; category: string }> = [
  { match: /nginx/i, name: "nginx", category: "Server" },
  { match: /apache/i, name: "Apache HTTP Server", category: "Server" },
  { match: /litespeed/i, name: "LiteSpeed", category: "Server" },
  { match: /caddy/i, name: "Caddy", category: "Server" },
  { match: /microsoft-iis/i, name: "Microsoft IIS", category: "Server" },
  { match: /cloudflare/i, name: "Cloudflare", category: "CDN" },
  { match: /gunicorn/i, name: "Gunicorn", category: "Server" },
  { match: /envoy/i, name: "Envoy", category: "Proxy" },
  { match: /openresty/i, name: "OpenResty", category: "Server" },
  { match: /express/i, name: "Express", category: "Framework" },
  { match: /php/i, name: "PHP", category: "Language" },
  { match: /asp\.net/i, name: "ASP.NET", category: "Framework" },
  { match: /next\.js/i, name: "Next.js", category: "Framework" },
];

/**
 * Script path and markup probes. The pattern runs against the script src or the
 * class attribute; the name and category say what a match implies.
 */
const SCRIPT_PATTERNS: Array<{ match: RegExp; name: string; category: string }> = [
  { match: /wp-content|wp-includes/i, name: "WordPress", category: "CMS" },
  { match: /\/sites\/default\/files|drupal/i, name: "Drupal", category: "CMS" },
  { match: /media\/jui|joomla/i, name: "Joomla", category: "CMS" },
  { match: /magento|mage\//i, name: "Magento", category: "E-commerce" },
  { match: /cdn\.shopify\.com|shopify/i, name: "Shopify", category: "E-commerce" },
  { match: /squarespace/i, name: "Squarespace", category: "CMS" },
  { match: /wix\.com|wixstatic/i, name: "Wix", category: "CMS" },
  { match: /webflow/i, name: "Webflow", category: "CMS" },
  { match: /ghost\/|ghost\.org/i, name: "Ghost", category: "CMS" },
  { match: /_next\/static|next\/dist/i, name: "Next.js", category: "Framework" },
  { match: /__nuxt|_nuxt\//i, name: "Nuxt", category: "Framework" },
  { match: /gatsby/i, name: "Gatsby", category: "Framework" },
  { match: /astro-island|_astro\//i, name: "Astro", category: "Framework" },
  { match: /react(-dom)?[.@-]/i, name: "React", category: "Library" },
  { match: /vue(\.runtime)?[.@-]/i, name: "Vue", category: "Library" },
  { match: /angular(\.min)?\.js|@angular/i, name: "Angular", category: "Framework" },
  { match: /svelte/i, name: "Svelte", category: "Library" },
  { match: /jquery/i, name: "jQuery", category: "Library" },
  { match: /bootstrap(\.bundle)?(\.min)?\.(js|css)/i, name: "Bootstrap", category: "CSS framework" },
  { match: /tailwind/i, name: "Tailwind CSS", category: "CSS framework" },
  { match: /alpinejs/i, name: "Alpine.js", category: "Library" },
  { match: /htmx/i, name: "htmx", category: "Library" },
  { match: /lodash/i, name: "Lodash", category: "Library" },
  { match: /moment(\.min)?\.js/i, name: "Moment.js", category: "Library" },
  { match: /d3(\.min)?\.js/i, name: "D3", category: "Library" },
  { match: /three(\.min)?\.js/i, name: "three.js", category: "Library" },
  { match: /chart(\.min)?\.js/i, name: "Chart.js", category: "Library" },
  { match: /stripe\.com\/v\d|js\.stripe\.com/i, name: "Stripe", category: "Payments" },
  { match: /recaptcha|hcaptcha/i, name: "CAPTCHA", category: "Security" },
  { match: /sentry|bugsnag|rollbar/i, name: "Error reporting", category: "Analytics" },
  { match: /google-analytics|googletagmanager|gtag\/js/i, name: "Google Analytics", category: "Analytics" },
  { match: /plausible\.io|matomo|piwik/i, name: "Privacy analytics", category: "Analytics" },
  { match: /hotjar|fullstory|clarity\.ms/i, name: "Session recording", category: "Analytics" },
  { match: /fonts\.googleapis\.com/i, name: "Google Fonts", category: "Fonts" },
  { match: /font-?awesome/i, name: "Font Awesome", category: "Fonts" },
];

/**
 * Class-name probes. These catch a framework that ships no recognisable script
 * name, which is common for a bundled single-page app.
 */
const CLASS_PATTERNS: Array<{ match: RegExp; name: string; category: string }> = [
  { match: /MuiBox-root|MuiButton-root/, name: "MUI", category: "CSS framework" },
  { match: /\bant-[a-z]+/, name: "Ant Design", category: "CSS framework" },
  { match: /\bchakra-/, name: "Chakra UI", category: "CSS framework" },
  { match: /\bcdk-(overlay|focused)/, name: "Angular Material", category: "CSS framework" },
  { match: /\bv-(application|btn)\b/, name: "Vuetify", category: "CSS framework" },
  { match: /\bq-(btn|card|layout)\b/, name: "Quasar", category: "CSS framework" },
  { match: /\bbg-(white|gray-\d00)\b.*\btext-/, name: "Tailwind CSS", category: "CSS framework" },
];

const EVIDENCE_LIMIT = 90;

function clip(value: string): string {
  const trimmed = value.trim();
  return trimmed.length > EVIDENCE_LIMIT ? trimmed.slice(0, EVIDENCE_LIMIT - 3) + "..." : trimmed;
}

export const techStack: CheckDefinition = {
  id: "tech-stack",
  title: "Technology stack",
  question: "What server, framework, CMS and third-party libraries can be identified from the response and the markup?",
  group: "infrastructure",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const [snapshot, page] = await Promise.all([ctx.headers(), ctx.html()]);

    const items: TechItem[] = [];
    const seen = new Set<string>();

    const add = (name: string, category: string, evidence: string, confidence: TechItem["confidence"]) => {
      const key = `${name}|${category}`;
      if (seen.has(key)) return;
      seen.add(key);
      items.push({ name, category, evidence: clip(evidence), confidence });
    };

    // --- headers ---
    const server = header(snapshot, "server") ?? null;
    const poweredBy = header(snapshot, "x-powered-by") ?? null;

    if (server) {
      const product = SERVER_PATTERNS.find((p) => p.match.test(server));
      add(product?.name ?? "HTTP server", product?.category ?? "Server", `server: ${server}`, "high");
    }
    if (poweredBy) {
      const product = SERVER_PATTERNS.find((p) => p.match.test(poweredBy));
      add(product?.name ?? "Application framework", product?.category ?? "Framework", `x-powered-by: ${poweredBy}`, "high");
    }

    for (const probe of HEADER_TECH) {
      const value = header(snapshot, probe.header);
      if (!value) continue;
      if (probe.match && !probe.match.test(value)) continue;
      add(probe.name, probe.category, `${probe.header}: ${value}`, "high");
    }

    // X-Generator is a free-text product name, so it is matched against the
    // same probes as the meta tag rather than reported as a fixed label.
    const xGenerator = header(snapshot, "x-generator");
    if (xGenerator) {
      const product = SCRIPT_PATTERNS.find((p) => p.match.test(xGenerator));
      add(product?.name ?? xGenerator.split(/[\s/]/)[0], product?.category ?? "CMS", `x-generator: ${xGenerator}`, "high");
    }

    // --- document ---
    const doc = page.doc;
    if (doc) {
      const generator = doc.querySelector('meta[name="generator" i]')?.getAttribute("content");
      if (generator) {
        const product = SCRIPT_PATTERNS.find((p) => p.match.test(generator));
        add(product?.name ?? generator.split(/[\s/]/)[0], product?.category ?? "CMS", `meta generator: ${generator}`, "high");
      }

      const scripts = Array.from(doc.querySelectorAll("script[src]"))
        .map((el) => el.getAttribute("src") ?? "")
        .filter(Boolean);

      for (const src of scripts) {
        for (const probe of SCRIPT_PATTERNS) {
          if (probe.match.test(src)) {
            // A bundled path is weaker evidence than a named library file, but
            // it still names the product the site is built on.
            add(probe.name, probe.category, src, "medium");
            break;
          }
        }
      }

      const stylesheets = Array.from(doc.querySelectorAll('link[rel="stylesheet"][href]'))
        .map((el) => el.getAttribute("href") ?? "")
        .filter(Boolean);
      for (const href of stylesheets) {
        for (const probe of SCRIPT_PATTERNS) {
          if (probe.match.test(href)) {
            add(probe.name, probe.category, href, "medium");
            break;
          }
        }
      }

      // Class probes need a bounded sample: scanning every element in a large
      // document costs more than the answer is worth.
      const classSample = Array.from(doc.querySelectorAll("[class]"))
        .slice(0, 400)
        .map((el) => el.getAttribute("class") ?? "")
        .join(" ");
      if (classSample) {
        for (const probe of CLASS_PATTERNS) {
          const m = probe.match.exec(classSample);
          if (m) add(probe.name, probe.category, m[0], "low");
        }
      }
    }

    const findings: Finding[] = [];

    // --- version disclosure ---
    const versioned = [
      server && /\d+\.\d+/.test(server) ? { header: "server", value: server } : null,
      poweredBy && /\d+(\.\d+)+/.test(poweredBy) ? { header: "x-powered-by", value: poweredBy } : null,
    ].filter((v): v is { header: string; value: string } => v !== null);

    if (versioned.length > 0) {
      findings.push({
        id: "tech-stack-version-disclosure",
        title: "The response names an exact software version",
        detail: `${versioned.map((v) => `${v.header}: ${v.value}`).join("; ")}. A version string turns a generic scan into a list of specific bugs to try.`,
        severity: "medium",
        remediation:
          "Remove the version from the header at the proxy or in the server config. nginx has server_tokens off, Apache has ServerTokens Prod, and most frameworks have an equivalent.",
        reference: {
          label: "MDN: X-Powered-By",
          url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Powered-By",
        },
        evidence: versioned.map((v) => ({ label: v.header, value: v.value, tone: "bad" as const })),
      });
    }

    // --- library count ---
    const LIBRARY_CATEGORIES = new Set(["Library", "Framework", "CSS framework", "Analytics", "Payments", "Fonts", "Security"]);
    const libraries = items.filter((i) => LIBRARY_CATEGORIES.has(i.category)).length;

    if (libraries > 8) {
      findings.push({
        id: "tech-stack-many-libraries",
        title: `${libraries} third-party libraries detected`,
        detail: `The page loads from ${libraries} distinct client-side products. Each one is code the site does not control, and each is a dependency that needs updating and a supply-chain risk if its CDN is compromised.`,
        severity: "low",
        remediation:
          "Audit the list and remove anything that is no longer used. For what remains, pin versions and add Subresource Integrity where the CDN allows it.",
        evidence: items
          .filter((i) => LIBRARY_CATEGORIES.has(i.category))
          .slice(0, 12)
          .map((i) => ({ label: i.name, value: i.category, tone: "neutral" as const })),
      });
    }

    // --- CMS note ---
    if (items.some((i) => i.name === "WordPress")) {
      findings.push({
        id: "tech-stack-wordpress",
        title: "WordPress detected",
        detail: "The page loads assets from wp-content or wp-includes, which identifies WordPress. This is context for the reader, not a defect: WordPress is a normal choice, and the plugin and core update cadence is what decides its risk.",
        severity: "info",
      });
    }

    const status: CheckResult["status"] =
      items.length === 0
        ? findings.length > 0
          ? "warn"
          : "info"
        : findings.some((f) => f.severity !== "info")
          ? "warn"
          : "pass";

    const categories = [...new Set(items.map((i) => i.category))];
    const headline =
      items.length === 0
        ? "No server, framework or library could be identified from the response headers or the markup."
        : `${items.length} technolog${items.length === 1 ? "y" : "ies"} identified across ${categories.length} categor${categories.length === 1 ? "y" : "ies"}${server ? `, served by ${server}` : ""}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        items,
        libraries,
        server,
        poweredBy,
      } satisfies TechStackData,
      ms: Math.round(performance.now() - started),
      source: "Response headers and the parsed document",
      note:
        "Fingerprinting reads what the site volunteers. A framework served under a neutral filename with no header leaves no trace, so this list is a lower bound.",
    };
  },
};
