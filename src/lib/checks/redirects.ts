/**
 * The redirect chain.
 *
 * Every hop is a full round trip before the first byte of the page arrives, so
 * on a mobile connection a long chain is felt directly. Two hops can also change
 * the security properties of the request: a hop that lands on http:// drops TLS
 * for the rest of the chain, and a hop that lands on another registrable domain
 * means the visitor is now reading a page a different organisation controls.
 *
 * The chain comes from the header source, which prints every response it saw.
 * When it reports no hops there is nothing honest to say, so the check reports
 * unavailable rather than assuming a clean single response.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { registrableDomain } from "../target";

export type RedirectHop = {
  status: number;
  location: string | null;
};

export type RedirectsData = {
  chain: RedirectHop[];
  hops: number;
  finalUrl: string;
  finalStatus: number;
  /** True when any hop moved the request from https to http. */
  downgraded: boolean;
  /** Registrable domain of the last URL in the chain. */
  finalDomain: string | null;
  crossDomain: boolean;
};

function schemeOf(url: string): string {
  try {
    return new URL(url).protocol;
  } catch {
    return "";
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

export const redirects: CheckDefinition = {
  id: "redirects",
  title: "Redirect chain",
  question: "How many hops does the request take, and does any hop weaken the connection or change owner?",
  group: "transport",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const snapshot = await ctx.headers();

    if (snapshot.via === "unavailable" || snapshot.status === 0) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The header source did not return a response for this host.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "api.hackertarget.com",
        note: "The header source is a public proxy and rate limits by IP. Re-running the scan usually works.",
      };
    }

    if (snapshot.chain.length === 0) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The header source returned no parseable redirect hops.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: snapshot.via,
        note: "Without a hop list the redirect count and any scheme or domain change cannot be measured. This is not evidence that the site does not redirect.",
      };
    }

    // Resolve each Location against the URL that produced it, so relative hops
    // are judged against the real absolute target rather than the raw header.
    const chain: RedirectHop[] = [];
    let current = ctx.target.url;
    let downgraded = false;

    for (const hop of snapshot.chain) {
      const raw = hop.location ?? null;
      let absolute: string | null = null;
      if (raw) {
        try {
          absolute = new URL(raw, current).toString();
        } catch {
          absolute = null;
        }
        if (absolute) {
          if (schemeOf(current) === "https:" && schemeOf(absolute) === "http:") {
            downgraded = true;
          }
          current = absolute;
        }
      }
      chain.push({ status: hop.status, location: absolute });
    }

    const finalUrl = chain[chain.length - 1]?.location ?? current;
    const finalHost = hostOf(finalUrl);
    const finalDomain = finalHost ? registrableDomain(finalHost) : null;
    const crossDomain = Boolean(finalDomain && finalDomain !== ctx.target.domain);

    // Redirect hops are every entry that moved the request somewhere else. The
    // last entry is the final response, which is not a hop.
    const hopCount = chain.filter((h) => h.location !== null).length;
    const finalHop = chain[chain.length - 1];
    const danglingRedirect =
      finalHop.status >= 300 && finalHop.status < 400 && finalHop.location === null;

    const findings: Finding[] = [];

    if (downgraded) {
      findings.push({
        id: "redirects-https-to-http",
        title: "The chain downgrades from https to http",
        detail: `A hop from ${ctx.target.url} lands on a plaintext http:// URL. Everything after that point, including any credentials or session cookie, crosses the network unencrypted.`,
        severity: "critical",
        remediation:
          "Change the redirect target to https:// and keep HSTS enabled so a future downgrade cannot be followed silently.",
        reference: {
          label: "OWASP: Transport layer security",
          url: "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
        },
        evidence: chain
          .filter((h) => h.location && schemeOf(h.location) === "http:")
          .map((h) => ({ label: `${h.status}`, value: h.location ?? "", tone: "bad" as const })),
      });
    }

    if (hopCount > 2) {
      findings.push({
        id: "redirects-long-chain",
        title: `${hopCount} redirects before the page loads`,
        detail: `The request passes through ${hopCount} redirects. Each one is a full round trip, and on a slow mobile connection they add up before a single byte of HTML arrives.`,
        severity: "low",
        remediation:
          "Collapse the chain to at most one hop: send visitors straight to the final URL, and update internal links and marketing material to point at it directly.",
      });
    }

    if (crossDomain) {
      findings.push({
        id: "redirects-cross-domain",
        title: "The chain ends on a different registrable domain",
        detail: `The request for ${ctx.target.domain} ends at ${finalDomain}. This is normal for an affiliate or regional redirect, and it is also what a hijacked or expired domain looks like.`,
        severity: "medium",
        remediation:
          "Confirm the final domain is one you control. If it is not, treat the redirect as a possible hijack and check the DNS and registrar records for the original domain.",
        evidence: [
          { label: "Requested", value: ctx.target.domain },
          { label: "Final", value: finalDomain ?? "unknown", tone: "neutral" },
        ],
      });
    }

    if (danglingRedirect) {
      findings.push({
        id: "redirects-dangling",
        title: "The chain ends on a redirect with no Location",
        detail: `The last response is a ${finalHop.status} with no Location header. A browser cannot follow it, so the visitor sees an error page instead of the site.`,
        severity: "medium",
        remediation: "Return a 200 with the final content, or a 3xx that names a Location the browser can follow.",
      });
    }

    const status: CheckResult["status"] = findings.some(
      (f) => f.severity === "high" || f.severity === "critical"
    )
      ? "fail"
      : findings.length > 0
        ? "warn"
        : "pass";

    const headline =
      hopCount === 0
        ? `The request reaches ${finalDomain ?? ctx.target.domain} in a single response with no redirects.`
        : `${hopCount} redirect${hopCount === 1 ? "" : "s"} before the final response${crossDomain ? `, ending on ${finalDomain}` : ""}${downgraded ? ", including an https to http downgrade" : ""}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        chain,
        hops: hopCount,
        finalUrl,
        finalStatus: finalHop.status,
        downgraded,
        finalDomain,
        crossDomain,
      } satisfies RedirectsData,
      ms: Math.round(performance.now() - started),
      source: snapshot.via,
      note: "The hop list is what the header source observed for this host. A redirect that only applies to a specific path, or to a mobile user agent, may not appear here.",
    };
  },
};
