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
  /** Judge a present value. Returns score 0-100 and a note. */
  judge: (value: string) => { score: number; verdict: HeaderRuleResult["verdict"]; note: string };
  missing: { note: string; remediation: string; reference?: { label: string; url: string } };
};

const CSP_UNSAFE = ["'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:"];

function judgeCsp(value: string): ReturnType<Rule["judge"]> {
  const lower = value.toLowerCase();
  const reportOnly = false; // caller handles the report-only variant
  const problems: string[] = [];

  if (lower.includes("default-src 'none'") || lower.includes("default-src 'self'")) {
    // A restrictive default is the single biggest win.
  } else if (lower.includes("default-src")) {
    problems.push("default-src is broader than 'self'");
  } else {
    problems.push("no default-src directive");
  }

  if (lower.includes("'unsafe-inline'")) problems.push("'unsafe-inline' allows injected scripts");
  if (lower.includes("'unsafe-eval'")) problems.push("'unsafe-eval' allows string-to-code execution");
  if (/\bscript-src[^;]*\*/.test(lower) || /\bdefault-src[^;]*\*/.test(lower))
    problems.push("a wildcard source allows any origin");
  if (lower.includes("http://")) problems.push("an http: source allows plaintext script loading");

  if (problems.length === 0) {
    const strict = lower.includes("'strict-dynamic'") || lower.includes("'nonce-") || lower.includes("'sha256-");
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
    verdict: problems.length >= 2 ? "weak" : "weak",
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
      const maxAge = /max-age\s*=\s*(\d+)/i.exec(value);
      const age = maxAge ? Number(maxAge[1]) : 0;
      const hasSub = /includeSubDomains/i.test(value);
      const preload = /preload/i.test(value);
      if (age === 0)
        return { score: 20, verdict: "misconfigured", note: "max-age is zero, which disables HSTS." };
      if (age < 15_552_000)
        return {
          score: 60,
          verdict: "weak",
          note: `max-age is ${Math.round(age / 86_400)} days. The recommended minimum is 180 days.`,
        };
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
    judge: (value) => {
      const v = value.toLowerCase();
      if (v.includes("deny")) return { score: 100, verdict: "good", note: "Framing is denied entirely." };
      if (v.includes("sameorigin"))
        return { score: 90, verdict: "good", note: "Framing is limited to the same origin." };
      if (v.includes("allow-from"))
        return {
          score: 30,
          verdict: "weak",
          note: "ALLOW-FROM is obsolete and ignored by current browsers.",
        };
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
      const v = value.toLowerCase().trim();
      const safe = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin"];
      if (v === "unsafe-url" || v === "no-referrer-when-downgrade")
        return {
          score: 20,
          verdict: "weak",
          note: `"${value}" leaks the full URL to other origins.`,
        };
      if (safe.includes(v)) return { score: 100, verdict: "good", note: `"${value}" limits cross-origin referrer detail.` };
      return { score: 50, verdict: "weak", note: `"${value}" is a partial or unrecognised policy.` };
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
    judge: (value) =>
      value.trim().length > 0
        ? {
            score: 100,
            verdict: "good",
            note: `${value.split(",").length} features are explicitly scoped.`,
          }
        : { score: 0, verdict: "misconfigured", note: "Header is present but empty." },
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
      const v = value.toLowerCase();
      if (v.includes("same-origin"))
        return { score: 100, verdict: "good", note: "Opener relationships are isolated to the same origin." };
      if (v.includes("same-origin-allow-popups"))
        return { score: 85, verdict: "good", note: "Isolated, with popups allowed to keep an opener." };
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
      const v = value.toLowerCase();
      if (v.includes("same-origin") || v.includes("same-site"))
        return { score: 100, verdict: "good", note: `"${value}" blocks cross-origin embedding.` };
      if (v.includes("cross-origin"))
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
      const judged = rule.judge(value);
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
