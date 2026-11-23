/**
 * HTTP security headers.
 *
 * This is the check with the most rules, so the rules live in a table and the
 * check itself is a loop. Each rule knows how to read a header, how to judge
 * its value, and what a correct value looks like.
 *
 * Grading follows the shape of securityheaders.com and Mozilla Observatory:
 * start at 100 and subtract per missing or weak header, with CSP weighted
 * heaviest because it is the one that limits the damage of an XSS.
 */

import type { CheckDefinition, CheckResult, Finding, Severity } from "../types";
import { header, headerAll } from "../net/document";
import type { HeaderSnapshot } from "../types";

export type HeaderRuleResult = {
  header: string;
  present: boolean;
  value: string | null;
  /** 0-100 for this header. */
  score: number;
  weight: number;
  verdict: "good" | "weak" | "missing" | "misconfigured";
  note: string;
};

export type HeadersData = {
  rules: HeaderRuleResult[];
  /** Headers that leak implementation detail. */
  disclosure: Array<{ header: string; value: string }>;
  status: number;
  chainLength: number;
  /** Server and platform headers, useful for fingerprinting. */
  fingerprint: Array<{ header: string; value: string }>;
  grade: string;
};

type Rule = {
  header: string;
  weight: number;
  severity: Severity;
  /**
   * Judge a present value. Returns score 0-100 and a note. The snapshot is
   * passed because some headers interact: frame-ancestors in the CSP overrides
   * X-Frame-Options, so one cannot be graded without seeing the other.
   */
  judge: (
    value: string,
    ctx: { snapshot: HeaderSnapshot }
  ) => { score: number; verdict: HeaderRuleResult["verdict"]; note: string };
  missing: { note: string; remediation: string; reference?: { label: string; url: string } };
};

/**
 * Parse a CSP into directive name -> source list.
 *
 * Splitting on `;` and then on whitespace is the whole grammar. Repeated
 * directives are ignored after the first, which matches the spec: a browser
 * also ignores every repeat.
 */
function parseCsp(value: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    if (!out.has(name)) out.set(name, tokens.slice(1).map((t) => t.toLowerCase()));
  }
  return out;
}

/** A bare scheme (`https:`) or `*` allows any host. Host sources do not. */
function isWildcardSource(source: string): boolean {
  return source === "*" || /^[a-z][a-z0-9+.-]*:$/.test(source);
}

function judgeCsp(value: string): ReturnType<Rule["judge"]> {
  const directives = parseCsp(value);
  const problems: string[] = [];

  const defaultSources = directives.get("default-src");
  const scriptSources =
    directives.get("script-src-elem") ??
    directives.get("script-src") ??
    directives.get("default-src");

  // Which list actually governs script execution. Reading the raw string with
  // `includes` was the bug here: "default-src 'self' https://evil.example"
  // contains "default-src 'self'" as a substring and scored 90 while allowing
  // script from any origin the attacker names.
  if (!scriptSources) {
    problems.push("no default-src or script-src directive, so script loading is unrestricted");
  }

  if (defaultSources) {
    const loose = defaultSources.filter((s) => isWildcardSource(s) && s !== "'none'");
    if (loose.length > 0) {
      problems.push(`default-src allows any origin (${loose.join(" ")})`);
    }
  }

  if (scriptSources) {
    const hasNonceOrHash = scriptSources.some(
      (s) => s.startsWith("'nonce-") || /^'sha(256|384|512)-/.test(s)
    );
    if (scriptSources.includes("*")) {
      problems.push("script-src allows any origin (*)");
    }
    const schemes = scriptSources.filter((s) => isWildcardSource(s) && s !== "*" && s !== "data:");
    if (schemes.length > 0) {
      problems.push(`script-src allows any host over ${schemes.join(", ")}`);
    }
    if (scriptSources.includes("data:")) {
      problems.push("script-src allows data: URLs, which can carry an inline script");
    }
    if (scriptSources.includes("'unsafe-inline'") && !hasNonceOrHash) {
      problems.push("'unsafe-inline' lets injected inline scripts run");
    }
    if (scriptSources.includes("'unsafe-eval'")) {
      problems.push("'unsafe-eval' turns strings into code");
    }
  }

  const unrestricted =
    !scriptSources ||
    (scriptSources ?? []).some((s) => isWildcardSource(s) || s === "data:");

  if (problems.length === 0) {
    const strict = (scriptSources ?? []).some(
      (s) => s === "'strict-dynamic'" || s.startsWith("'nonce-") || /^'sha(256|384|512)-/.test(s)
    );
    return {
      score: strict ? 100 : 90,
      verdict: "good",
      note: strict
        ? "Restrictive policy with nonce or hash-based script loading."
        : "Restrictive policy. Adding a nonce or hash would make it strict.",
    };
  }

  return {
    score: problems.length >= 3 ? 25 : problems.length === 2 ? 45 : 65,
    verdict: unrestricted || problems.length >= 2 ? "misconfigured" : "weak",
    note: problems.join("; ") + ".",
  };
}

const RULES: Rule[] = [
  {
    header: "content-security-policy",
    weight: 30,
    severity: "critical",
    judge: judgeCsp,
    missing: {
      note: "No CSP. Nothing constrains which scripts can run, so any injected script executes with full page privileges.",
      remediation:
        "Start with Content-Security-Policy: default-src 'self'; then add nonces for the scripts you actually need. Report-only first if the site is large.",
      reference: {
        label: "MDN: Content-Security-Policy",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
      },
    },
  },
  {
    header: "strict-transport-security",
    weight: 20,
    severity: "high",
    judge: (value) => {
      const maxAge = /max-age\s*=\s*"?(\d+)"?/i.exec(value);
      const hasSub = /includesubdomains/i.test(value);
      const preload = /(?:^|;)\s*preload\s*(?:;|$)/i.test(value);
      // No max-age at all is not the same as max-age=0. RFC 6797 §6.1 makes a
      // missing directive invalid, so the browser ignores the whole header and
      // the site has no HSTS protection at all. Saying "max-age is zero" for
      // that case described a configuration the site did not send.
      if (!maxAge) {
        return {
          score: 10,
          verdict: "misconfigured",
          note: "The header carries no max-age directive, so browsers ignore it entirely and HSTS is not enabled.",
        };
      }
      const age = Number(maxAge[1]);
      if (age === 0)
        return {
          score: 20,
          verdict: "misconfigured",
          note: "max-age is zero, which tells the browser to forget the policy immediately.",
        };
      if (age < 15_552_000) {
        const days = age / 86_400;
        return {
          score: 60,
          verdict: "weak",
          note: `max-age is ${days < 1 ? "under a day" : `${Math.round(days)} days`}. The recommended minimum is 180 days.`,
        };
      }
      const extras = [hasSub && "includeSubDomains", preload && "preload"].filter(Boolean);
      return {
        score: hasSub && preload ? 100 : hasSub ? 90 : 80,
        verdict: "good",
        note: `${Math.round(age / 86_400)} day max-age${extras.length ? ` with ${extras.join(" and ")}` : ""}.`,
      };
    },
    missing: {
      note: "No HSTS. A first request over plain HTTP can be intercepted before the redirect to HTTPS.",
      remediation:
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains. Add preload only once you are sure every subdomain is HTTPS.",
      reference: {
        label: "RFC 6797",
        url: "https://datatracker.ietf.org/doc/html/rfc6797",
      },
    },
  },
  {
    header: "x-content-type-options",
    weight: 10,
    severity: "medium",
    judge: (value) =>
      value.toLowerCase().includes("nosniff")
        ? { score: 100, verdict: "good", note: "MIME sniffing is disabled." }
        : { score: 0, verdict: "misconfigured", note: `Value is "${value}", which is not nosniff.` },
    missing: {
      note: "Browsers may guess a response's type, which lets an uploaded file be executed as a script.",
      remediation: "Add X-Content-Type-Options: nosniff.",
      reference: {
        label: "MDN: X-Content-Type-Options",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
      },
    },
  },
  {
    header: "x-frame-options",
    weight: 10,
    severity: "medium",
    judge: (value, { snapshot }) => {
      const v = value.toLowerCase().trim();
      if (v === "deny") return { score: 100, verdict: "good", note: "Framing is denied entirely." };
      if (v === "sameorigin")
        return { score: 90, verdict: "good", note: "Framing is limited to the same origin." };
      if (v.startsWith("allow-from"))
        return {
          score: 30,
          verdict: "weak",
          note: "ALLOW-FROM is obsolete and ignored by current browsers.",
        };
      // CSP frame-ancestors overrides X-Frame-Options wherever both are sent, so
      // a site that sends a bad XFO but a good frame-ancestors is protected and
      // grading the obsolete header alone would be wrong.
      const csp = headerAll(snapshot, "content-security-policy").join("; ");
      const ancestors = parseCsp(csp).get("frame-ancestors");
      if (ancestors) {
        const restrictive =
          ancestors.length === 1 && (ancestors[0] === "'none'" || ancestors[0] === "'self'");
        return {
          score: restrictive ? 90 : 60,
          verdict: restrictive ? "good" : "weak",
          note: `X-Frame-Options is "${value}", but the CSP frame-ancestors directive (${ancestors.join(" ")}) takes precedence in current browsers.`,
        };
      }
      return { score: 20, verdict: "misconfigured", note: `Unrecognised value "${value}".` };
    },
    missing: {
      note: "The page can be framed by any site, which is the precondition for clickjacking.",
      remediation:
        "Add X-Frame-Options: DENY, or better, frame-ancestors 'none' in the CSP. The CSP directive is the one that still works in modern browsers.",
      reference: {
        label: "OWASP: Clickjacking",
        url: "https://owasp.org/www-community/attacks/Clickjacking",
      },
    },
  },
  {
    header: "referrer-policy",
    weight: 8,
    severity: "low",
    judge: (value) => {
      // Referrer-Policy is a comma-separated fallback list and the browser uses
      // the last value it recognises. Judging the whole string marked a header
      // like "origin-when-cross-origin, strict-origin-when-cross-origin" as
      // unrecognised even though the effective policy is the strict one.
      const tokens = value
        .split(",")
        .map((t) => t.trim().toLowerCase())
        .filter(Boolean);
      const known = tokens.filter((t) =>
        [
          "no-referrer",
          "no-referrer-when-downgrade",
          "same-origin",
          "origin",
          "strict-origin",
          "origin-when-cross-origin",
          "strict-origin-when-cross-origin",
          "unsafe-url",
        ].includes(t)
      );
      const effective = known[known.length - 1];
      if (!effective) {
        return { score: 50, verdict: "weak", note: `"${value}" contains no policy a browser recognises.` };
      }
      const safe = [
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "origin",
        "origin-when-cross-origin",
      ];
      if (effective === "unsafe-url" || effective === "no-referrer-when-downgrade")
        return {
          score: 20,
          verdict: "weak",
          note: `The effective policy is "${effective}", which leaks the full URL to other origins.`,
        };
      if (safe.includes(effective))
        return {
          score: 100,
          verdict: "good",
          note: `The effective policy is "${effective}", which limits cross-origin referrer detail.`,
        };
      return { score: 50, verdict: "weak", note: `"${effective}" is a partial policy.` };
    },
    missing: {
      note: "Without a policy, the browser default sends the full URL to other origins, including any tokens in the path or query.",
      remediation:
        "Add Referrer-Policy: strict-origin-when-cross-origin. It is the modern default and the safest broadly compatible choice.",
      reference: {
        label: "MDN: Referrer-Policy",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
      },
    },
  },
  {
    header: "permissions-policy",
    weight: 6,
    severity: "low",
    judge: (value) => {
      const v = value.trim();
      if (v.length === 0)
        return { score: 0, verdict: "misconfigured", note: "Header is present but empty." };
      // "geolocation=*" is a header that exists and grants the feature to every
      // origin, which is strictly worse than the default of same-origin. The
      // old rule scored any non-empty value 100.
      const grants = v
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean);
      const open = grants.filter((g) => /=\s*\*/.test(g));
      const disabled = grants.filter((g) => /=\s*\(\s*\)/.test(g));
      if (open.length > 0) {
        return {
          score: 25,
          verdict: "misconfigured",
          note: `${open.length} directive${open.length === 1 ? " grants" : "s grant"} the feature to every origin (${open.map((g) => g.split("=")[0].trim()).join(", ")}).`,
        };
      }
      if (disabled.length === 0) {
        return {
          score: 55,
          verdict: "weak",
          note: `${grants.length} feature${grants.length === 1 ? " is" : "s are"} named but none is explicitly disabled with =().`,
        };
      }
      return {
        score: 100,
        verdict: "good",
        note: `${disabled.length} of ${grants.length} named feature${grants.length === 1 ? " is" : "s are"} explicitly disabled.`,
      };
    },
    missing: {
      note: "Camera, microphone, geolocation and payment APIs are available to any embedded frame that asks.",
      remediation:
        "Add Permissions-Policy naming only the features you use, for example: Permissions-Policy: geolocation=(), camera=(), microphone=()",
      reference: {
        label: "MDN: Permissions-Policy",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
      },
    },
  },
  {
    header: "cross-origin-opener-policy",
    weight: 6,
    severity: "low",
    judge: (value) => {
      const v = value.toLowerCase().trim();
      // `unsafe-none` is the default state written out. It provides no isolation
      // at all, and matching it with `includes("same-origin")` would grade it as
      // though it did.
      if (v === "same-origin")
        return { score: 100, verdict: "good", note: "Opener relationships are isolated to the same origin." };
      if (v === "same-origin-allow-popups")
        return { score: 85, verdict: "good", note: "Isolated, with popups allowed to keep an opener." };
      if (v === "unsafe-none")
        return {
          score: 20,
          verdict: "misconfigured",
          note: '"unsafe-none" is the browser default written out, and provides no isolation.',
        };
      return { score: 40, verdict: "weak", note: `"${value}" provides no isolation.` };
    },
    missing: {
      note: "A cross-origin opener can keep a reference to this window, which enables cross-window scripting attacks.",
      remediation: "Add Cross-Origin-Opener-Policy: same-origin.",
      reference: {
        label: "MDN: Cross-Origin-Opener-Policy",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
      },
    },
  },
  {
    header: "cross-origin-resource-policy",
    weight: 4,
    severity: "low",
    judge: (value) => {
      const v = value.toLowerCase().trim();
      // `same-site` and `same-origin` are not the same guarantee: same-site still
      // allows every sibling subdomain to embed the resource. The old rule
      // matched both with one `includes` and scored them identically.
      if (v === "same-origin")
        return { score: 100, verdict: "good", note: '"same-origin" blocks every cross-origin embed.' };
      if (v === "same-site")
        return {
          score: 75,
          verdict: "weak",
          note: '"same-site" still lets sibling subdomains embed the resource. "same-origin" is the stronger value.',
        };
      if (v === "cross-origin")
        return { score: 60, verdict: "weak", note: "Any origin may embed these resources." };
      return { score: 40, verdict: "weak", note: `Unrecognised value "${value}".` };
    },
    missing: {
      note: "Other sites can embed this origin's images and scripts, which leaks content and enables some side channels.",
      remediation: "Add Cross-Origin-Resource-Policy: same-origin.",
      reference: {
        label: "MDN: Cross-Origin-Resource-Policy",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
      },
    },
  },
];

/** Headers that name the stack and should be removed in production. */
const DISCLOSURE_HEADERS = [
  "server",
  "x-powered-by",
  "x-aspnet-version",
  "x-aspnetmvc-version",
  "x-generator",
  "x-drupal-cache",
  "x-drupal-dynamic-cache",
  "x-runtime",
  "x-version",
  "x-debug-token",
  "x-debug-token-link",
];

const FINGERPRINT_HEADERS = [
  "server",
  "via",
  "cf-ray",
  "x-vercel-id",
  "x-amz-cf-id",
  "x-cache",
  "x-served-by",
  "x-fastly-request-id",
  "x-github-request-id",
  "x-azure-ref",
  "x-proxy-cache",
  "x-timer",
  "age",
  "x-pantheon-styx-hostname",
];

function gradeFromScore(score: number): string {
  if (score >= 95) return "A+";
  if (score >= 85) return "A";
  if (score >= 75) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  if (score >= 35) return "E";
  return "F";
}

export const securityHeaders: CheckDefinition = {
  id: "security-headers",
  title: "HTTP security headers",
  question: "Which protective response headers are set, and are their values correct?",
  group: "headers",
  weight: 2,
  needsDocument: true,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const snapshot: HeaderSnapshot = await ctx.headers();

    if (snapshot.via === "unavailable" || snapshot.status === 0) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "Response headers could not be retrieved for this host.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "api.hackertarget.com",
        note: "The header source is a public proxy and rate limits by IP. Re-running usually works.",
      };
    }

    // An edge refusal is not the page. The proxy fetches from its own address,
    // and when that address is challenged it relays the challenge's headers as
    // though they were the site's. Grading them awarded a live scan of
    // example.com a Grade F for missing HSTS and CSP that the site actually
    // sends. A refusal says nothing about the visitor-facing policy, so the
    // check declines to grade rather than inventing a verdict from it.
    if (snapshot.challenge) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: `The response was an edge refusal (HTTP ${snapshot.status}), not the page, so the headers were not graded.`,
        findings: [],
        data: {
          rules: [],
          disclosure: [],
          status: snapshot.status,
          chainLength: snapshot.chain.length,
          fingerprint: [],
          grade: "n/a",
        } satisfies HeadersData,
        ms: Math.round(performance.now() - started),
        source: "api.hackertarget.com header proxy",
        note: "The site's edge challenged the header source's own request, so what came back describes the challenge, not the page a visitor receives. Open the site in a browser to read its real headers. A site that blocks automated requests entirely cannot be graded here.",
      };
    }

    const rules: HeaderRuleResult[] = [];
    const findings: Finding[] = [];

    for (const rule of RULES) {
      const values = headerAll(snapshot, rule.header);
      const reportOnly = headerAll(snapshot, rule.header + "-report-only");

      // A report-only CSP is worth noting but does not protect anything.
      if (rule.header === "content-security-policy" && values.length === 0 && reportOnly.length > 0) {
        rules.push({
          header: rule.header,
          present: false,
          value: reportOnly[0],
          score: 0,
          weight: rule.weight,
          verdict: "misconfigured",
          note: "A report-only policy is present. It reports violations but blocks nothing.",
        });
        findings.push({
          id: `header-${rule.header}-report-only`,
          title: "Content-Security-Policy is report-only",
          detail:
            "The site sends Content-Security-Policy-Report-Only, which logs violations without stopping them. Injected scripts still run.",
          severity: "high",
          remediation:
            "Once the report shows no legitimate breakage, send the same policy as Content-Security-Policy to enforce it.",
          reference: rule.missing.reference,
        });
        continue;
      }

      if (values.length === 0) {
        // X-Frame-Options is the legacy half of clickjacking protection. A site
        // that sends only the CSP frame-ancestors directive is protected in every
        // current browser, so reporting a missing XFO as a defect would be a
        // false finding. The directive is graded here instead.
        if (rule.header === "x-frame-options") {
          const cspValue = headerAll(snapshot, "content-security-policy").join("; ");
          const ancestors = parseCsp(cspValue).get("frame-ancestors");
          if (ancestors && ancestors.length > 0) {
            const restrictive =
              ancestors.length === 1 && (ancestors[0] === "'none'" || ancestors[0] === "'self'");
            rules.push({
              header: rule.header,
              present: false,
              value: null,
              score: restrictive ? 90 : 60,
              weight: rule.weight,
              verdict: restrictive ? "good" : "weak",
              note: `Not set, but the CSP frame-ancestors directive (${ancestors.join(" ")}) covers this in current browsers.`,
            });
            if (!restrictive) {
              findings.push({
                id: `header-${rule.header}-weak`,
                title: "Framing is restricted by CSP, but loosely",
                detail: `X-Frame-Options is not set and the CSP frame-ancestors directive allows ${ancestors.join(" ")}.`,
                severity: "low",
                remediation:
                  "Narrow frame-ancestors to 'none' or 'self' unless a named origin genuinely needs to frame the page.",
                reference: rule.missing.reference,
              });
            }
            continue;
          }
        }

        rules.push({
          header: rule.header,
          present: false,
          value: null,
          score: 0,
          weight: rule.weight,
          verdict: "missing",
          note: rule.missing.note,
        });
        findings.push({
          id: `header-${rule.header}-missing`,
          title: `${rule.header} is not set`,
          detail: rule.missing.note,
          severity: rule.severity,
          remediation: rule.missing.remediation,
          reference: rule.missing.reference,
        });
        continue;
      }

      // Multiple values for one header is itself a bug for most of these.
      const value = values.join(", ");
      const judged = rule.judge(value, { snapshot });
      rules.push({
        header: rule.header,
        present: true,
        value,
        score: judged.score,
        weight: rule.weight,
        verdict: judged.verdict,
        note: judged.note,
      });
      if (judged.verdict !== "good") {
        findings.push({
          id: `header-${rule.header}-weak`,
          title: `${rule.header} is present but ${judged.verdict}`,
          detail: `${judged.note} Current value: ${value.length > 200 ? value.slice(0, 200) + "…" : value}`,
          severity: judged.verdict === "misconfigured" ? rule.severity : "low",
          remediation: rule.missing.remediation,
          reference: rule.missing.reference,
        });
      }
    }

    const disclosure: Array<{ header: string; value: string; versioned: boolean }> = [];
    for (const name of DISCLOSURE_HEADERS) {
      const v = header(snapshot, name);
      if (!v) continue;
      // A bare product name ("cloudflare", "nginx") names the stack but reveals
      // no version. Only a version string tells an attacker which specific bugs
      // to try, so the two cases are not reported as the same finding.
      const versioned = /\d+\.\d+/.test(v) || /\d{3,}/.test(v);
      disclosure.push({ header: name, value: v, versioned });
    }
    const versionedDisclosure = disclosure.filter((d) => d.versioned);

    if (versionedDisclosure.length > 0) {
      findings.push({
        id: "header-version-disclosure",
        title: `${versionedDisclosure.length} header${versionedDisclosure.length === 1 ? " publishes a version number" : "s publish version numbers"}`,
        detail: `The server volunteers ${versionedDisclosure.map((d) => `${d.header}: ${d.value}`).join("; ")}. A version number tells an attacker which specific bugs to try first.`,
        severity: "medium",
        remediation:
          "Remove the version from Server and X-Powered-By at the proxy. Most frameworks have a setting for this.",
        evidence: versionedDisclosure.map((d) => ({ label: d.header, value: d.value, tone: "bad" as const })),
      });
    }

    const nameOnlyDisclosure = disclosure.filter((d) => !d.versioned);
    if (nameOnlyDisclosure.length > 0) {
      findings.push({
        id: "header-name-disclosure",
        title: `${nameOnlyDisclosure.length} header${nameOnlyDisclosure.length === 1 ? " names" : "s name"} the stack`,
        detail: `The server volunteers ${nameOnlyDisclosure.map((d) => `${d.header}: ${d.value}`).join("; ")}. No version is published, so this is a fingerprint rather than a direct weakness: it saves an attacker a guess about which tooling to target.`,
        severity: "low",
        remediation:
          "Optional. Removing the product name slows down fingerprinting, but it is not a defect on its own.",
        evidence: nameOnlyDisclosure.map((d) => ({ label: d.header, value: d.value, tone: "neutral" as const })),
      });
    }

    const fingerprint: Array<{ header: string; value: string }> = [];
    for (const name of FINGERPRINT_HEADERS) {
      const v = header(snapshot, name);
      if (v) fingerprint.push({ header: name, value: v });
    }

    // Weighted score: only over headers that were actually judged.
    const totalWeight = rules.reduce((sum, r) => sum + r.weight, 0);
    const earned = rules.reduce((sum, r) => sum + (r.score / 100) * r.weight, 0);
    const score = totalWeight > 0 ? Math.round((earned / totalWeight) * 100) : 0;
    const grade = gradeFromScore(score);

    const missingCount = rules.filter((r) => r.verdict === "missing").length;
    const weakCount = rules.filter((r) => r.verdict === "weak" || r.verdict === "misconfigured").length;

    const status: CheckResult["status"] =
      missingCount >= 4 || rules.some((r) => r.header === "content-security-policy" && r.score === 0)
        ? "fail"
        : missingCount > 0 || weakCount > 0
          ? "warn"
          : "pass";

    // Compose the headline from the parts that are actually non-zero, so it
    // never reads "0 of 8 are missing and 1 are misconfigured" or "1 are".
    // "1 of 8 protective headers is missing" keeps "headers" plural: the noun
    // agrees with the count after "of", the verb with the leading number.
    const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);
    const parts: string[] = [];
    if (missingCount > 0) {
      parts.push(
        `${missingCount} of ${rules.length} protective headers ${plural(missingCount, "is", "are")} missing`
      );
    }
    if (weakCount > 0) {
      // weakCount covers both `weak` (present but too loose) and
      // `misconfigured` (present but wrong), so the wording has to cover both.
      parts.push(
        `${weakCount} ${plural(weakCount, "header is", "headers are")} present but weak or misconfigured`
      );
    }

    const headline =
      parts.length === 0
        ? `All ${rules.length} protective headers are present and correctly configured. Grade ${grade}.`
        : `${parts.join(" and ")}. Grade ${grade}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        rules,
        disclosure,
        status: snapshot.status,
        chainLength: snapshot.chain.length,
        fingerprint,
        grade,
      } satisfies HeadersData,
      ms: Math.round(performance.now() - started),
      source: "api.hackertarget.com header proxy",
    };
  },
};
