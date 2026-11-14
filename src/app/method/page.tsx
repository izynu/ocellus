import type { CSSProperties } from "react";
import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { checks, GROUP_ORDER } from "@/lib/checks";
import { SITE, asset } from "@/lib/site";

/**
 * The method page.
 *
 * This is where a technical reader decides whether to trust the tool, so it
 * names every source, reproduces the scoring rules exactly as they are coded,
 * and states the limits without softening them.
 */

export const metadata = {
  title: "Method",
  description:
    "Where every value in an Ocellus report comes from, how the score and grade are computed, why an unavailable source is never scored as a pass, and the specifications each finding is judged against.",
  alternates: { canonical: asset("/method") },
};

const SOURCES = [
  {
    name: "Google Public DNS",
    href: "https://dns.google/",
    what: "Every DNS answer: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, DS, DNSKEY, TLSA and HTTPS records.",
    how: "DNS over HTTPS, JSON API. Queried first.",
  },
  {
    name: "Cloudflare 1.1.1.1",
    href: "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
    what: "The same DNS answers, used as the fallback when Google does not respond.",
    how: "DNS over HTTPS, JSON API. Queried second, only on failure.",
  },
  {
    name: "crt.sh",
    href: "https://crt.sh/",
    what: "Certificates issued for the domain, their issuers, validity windows, and the hostnames they name.",
    how: "Certificate Transparency index, JSON output.",
  },
  {
    name: "api.hackertarget.com",
    href: "https://api.hackertarget.com/",
    what: "The raw response headers of the target, including every redirect hop, as a status line and header block.",
    how: "Plain-text header proxy.",
  },
  {
    name: "Shodan InternetDB",
    href: "https://internetdb.shodan.io/",
    what: "Open ports observed on the address, the hostnames and CPEs linked to it, and the CVEs associated with those services.",
    how: "Keyless JSON endpoint, one address per request.",
  },
  {
    name: "ipwho.is",
    href: "https://ipwho.is/",
    what: "Geolocation and the autonomous system announcing the address.",
    how: "Keyless JSON endpoint.",
  },
  {
    name: "AlienVault OTX",
    href: "https://otx.alienvault.com/",
    what: "Threat pulses that name the domain or the address.",
    how: "Public indicator endpoint.",
  },
  {
    name: "r.jina.ai",
    href: "https://r.jina.ai/",
    what: "The target document as HTML, which the content, privacy and SEO checks read. Also used to retrieve robots.txt and sitemap.xml.",
    how: "Reader service that sends CORS headers, which most sites do not.",
  },
  {
    name: "api.microlink.io",
    href: "https://api.microlink.io/",
    what: "Title, description, language and Open Graph fields. A fallback used only when the reader fails, and never treated as a full document.",
    how: "Keyless metadata endpoint.",
  },
  {
    name: "The document's own markup",
    href: "https://www.w3.org/TR/WCAG22/",
    what: "Headings, alternative text, form labels, language, duplicate identifiers, canonical and robots directives, script and iframe sources.",
    how: "Parsed from the HTML the reader returned, without rendering or executing it.",
  },
] as const;

const FRACTIONS = [
  { status: "pass", value: "1.0", note: "The rule was met." },
  { status: "info", value: "0.85", note: "An observation, not a judgement. Scored just below a pass." },
  { status: "warn", value: "0.55", note: "Worth fixing, not severe alone." },
  { status: "fail", value: "0.1", note: "The rule was broken. Not zero, because the check did run." },
  { status: "unavailable", value: "removed", note: "Dropped from numerator and denominator." },
  { status: "skipped", value: "removed", note: "Dropped from numerator and denominator." },
] as const;

const GRADES = [
  { grade: "A", band: "90 and above" },
  { grade: "B", band: "78 to 89" },
  { grade: "C", band: "64 to 77" },
  { grade: "D", band: "50 to 63" },
  { grade: "E", band: "32 to 49" },
  { grade: "F", band: "below 32" },
] as const;

const SPECS = [
  {
    label: "RFC 7208, Sender Policy Framework",
    href: "https://www.rfc-editor.org/rfc/rfc7208.html",
    used: "SPF record syntax, lookup limits and the all mechanism.",
  },
  {
    label: "RFC 7489, DMARC",
    href: "https://www.rfc-editor.org/rfc/rfc7489.html",
    used: "DMARC policy, alignment and reporting addresses.",
  },
  {
    label: "RFC 6376, DKIM",
    href: "https://www.rfc-editor.org/rfc/rfc6376.html",
    used: "Selector records and key material published in DNS.",
  },
  {
    label: "RFC 6797, HTTP Strict Transport Security",
    href: "https://www.rfc-editor.org/rfc/rfc6797.html",
    used: "HSTS max-age, includeSubDomains and preload.",
  },
  {
    label: "RFC 8659, CAA",
    href: "https://www.rfc-editor.org/rfc/rfc8659.html",
    used: "Which certificate authorities may issue for the domain.",
  },
  {
    label: "RFC 9116, security.txt",
    href: "https://www.rfc-editor.org/rfc/rfc9116.html",
    used: "The format and location of a security contact file.",
  },
  {
    label: "RFC 9309, robots exclusion protocol",
    href: "https://www.rfc-editor.org/rfc/rfc9309.html",
    used: "robots.txt directives and how a crawler must read them.",
  },
  {
    label: "WCAG 2.2",
    href: "https://www.w3.org/TR/WCAG22/",
    used: "Success criteria for names, roles, language, headings and alternative text.",
  },
  {
    label: "CA/Browser Forum baseline requirements",
    href: "https://cabforum.org/working-groups/server/baseline-requirements/",
    used: "Certificate lifetime, key strength and issuance rules.",
  },
] as const;

export default function MethodPage() {
  return (
    <SiteShell>
      <div className="container-page">
      <header className="rise pt-14 pb-2 md:pt-20">
        <p className="eyebrow">Method</p>
        <h1 className="mt-4" style={{ fontSize: "clamp(1.9rem, 4.4vw, 2.7rem)", maxWidth: "26ch" }}>
          Where the data comes from, and how the score is computed.
        </h1>
        <p
          className="mt-5"
          style={{ fontSize: 16.5, maxWidth: "60ch", color: "var(--muted-foreground)" }}
        >
          Nothing in a report is inferred or generated. Each value is either what a named source
          returned or an explicit statement that the source could not be reached.
        </p>
      </header>

      <div className="prose mt-10">
        <h2>Where the data comes from</h2>
        <p>
          A scan makes requests from your browser to the public services below. None of them
          requires an API key, and none of them is operated by this site. The report shows the
          source next to each check, so a value can always be traced back to the service that
          supplied it.
        </p>
      </div>

      <div className="sheet mt-5 overflow-x-auto">
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontSize: 14.5,
            minWidth: 560,
          }}
        >
          <caption className="sr-only">Data sources, what each supplies, and how it is queried</caption>
          <thead>
            <tr>
              <th scope="col" style={thStyle}>
                Source
              </th>
              <th scope="col" style={thStyle}>
                Used for
              </th>
              <th scope="col" style={thStyle}>
                Access
              </th>
            </tr>
          </thead>
          <tbody>
            {SOURCES.map((source) => (
              <tr key={source.name}>
                <td style={tdStyle}>
                  <a
                    href={source.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: "var(--primary)" }}
                  >
                    {source.name}
                  </a>
                </td>
                <td style={{ ...tdStyle, color: "var(--muted-foreground)" }}>{source.what}</td>
                <td style={{ ...tdStyle, color: "var(--muted-foreground)" }}>{source.how}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="prose mt-10">
        <h2>How the score is computed</h2>
        <p>
          Each of the {checks.length} checks carries a weight of 1, 2 or 3. A status maps to a
          fixed fraction of that weight. The score is the sum of the fractions earned divided by
          the sum of the weights that were actually scored, multiplied by 100 and rounded to the
          nearest integer.
        </p>
        <p>
          A check whose status is <code>unavailable</code> or <code>skipped</code> is removed
          from both the numerator and the denominator. It contributes nothing and costs nothing.
          If no check produced a verdict, the score is 0 and the grade is F, and the report says
          that nothing could be measured.
        </p>
        <table>
          <thead>
            <tr>
              <th scope="col">Status</th>
              <th scope="col">Fraction of weight</th>
              <th scope="col">Meaning</th>
            </tr>
          </thead>
          <tbody>
            {FRACTIONS.map((row) => (
              <tr key={row.status}>
                <td className="mono">{row.status}</td>
                <td className="tabular">{row.value}</td>
                <td>{row.note}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p>
          The resulting score maps to a grade by fixed bands. There are no curves, no
          per-site adjustments and no hidden bonuses.
        </p>
        <table>
          <thead>
            <tr>
              <th scope="col">Grade</th>
              <th scope="col">Score</th>
            </tr>
          </thead>
          <tbody>
            {GRADES.map((row) => (
              <tr key={row.grade}>
                <td style={{ fontWeight: 600 }}>{row.grade}</td>
                <td className="tabular">{row.band}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <h2>Why unavailable is not a pass</h2>
        <p>
          A pass is a claim that a source answered and the answer was correct. If the source did
          not answer, there is nothing to claim. Counting an unreachable source as a pass would
          mean a site behind a strict firewall, or one that rate limits the proxy, scores better
          than a site that answers honestly and has a weak header. It would also make the score
          rise as the scan learned less. So an unavailable check is removed from the arithmetic
          entirely, the report prints the count of checks that could not run, and the score is
          described as being computed over the checks that did. A site with four passes and
          twelve unavailable checks gets an A on four checks, not an A on sixteen.
        </p>

        <h2>The limits</h2>
        <p>
          <strong>CORS.</strong> A static page can only read a cross-origin response that sends
          an <code>Access-Control-Allow-Origin</code> header. Most sites do not, which is why the
          document is read through a proxy that does. Where a source omits the header, the check
          reports unavailable rather than guessing at the body.
        </p>
        <p>
          <strong>Bot walls.</strong> A Cloudflare interstitial, a consent wall or a CAPTCHA is
          not the page. The document layer recognises the common markers and flags the document
          as an interstitial instead of analysing it, because analysing a challenge page and
          reporting on it would be a silent lie about the site.
        </p>
        <p>
          <strong>Rate limits.</strong> Several sources limit by IP. The header proxy and crt.sh
          are the two that fail most often under load. A rate-limited response is reported as
          unavailable with a note, and re-running the scan usually succeeds.
        </p>
        <p>
          <strong>Staleness.</strong> Shodan InternetDB and crt.sh are indexes, not live probes.
          Shodan reports ports it observed at some earlier crawl; a port opened or closed since
          then will not be reflected. crt.sh reports certificates that were logged, which can lag
          issuance by minutes to hours. Neither is a port scan or a live TLS handshake.
        </p>
        <p>
          <strong>One document, one moment.</strong> The content checks read a single fetched
          document. A page that varies by user agent, by geography or after JavaScript runs is
          read as the proxy saw it. Nothing is rendered, so no value that requires layout,
          computed style or script execution is claimed.
        </p>

        <h2>What a finding is judged against</h2>
        <p>
          Every finding can carry a reference. These are the specifications the checks cite, and
          the part of each that a finding is measured against.
        </p>
      </div>

      <div className="sheet mt-5 overflow-x-auto">
        <table
          style={{ width: "100%", borderCollapse: "collapse", fontSize: 14.5, minWidth: 520 }}
        >
          <caption className="sr-only">Specifications cited by checks</caption>
          <thead>
            <tr>
              <th scope="col" style={thStyle}>
                Specification
              </th>
              <th scope="col" style={thStyle}>
                Applied to
              </th>
            </tr>
          </thead>
          <tbody>
            {SPECS.map((spec) => (
              <tr key={spec.href}>
                <td style={tdStyle}>
                  <a
                    href={spec.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: "var(--primary)" }}
                  >
                    {spec.label}
                  </a>
                </td>
                <td style={{ ...tdStyle, color: "var(--muted-foreground)" }}>{spec.used}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="prose mt-10">
        <p>
          Where no specification covers a check, the report says so and the finding stands on the
          measured value alone. The catalogue of {checks.length} checks in {GROUP_ORDER.length}{" "}
          groups is on the <Link href="/checks">checks page</Link>. The scoring code itself is in
          the repository at <a href={SITE.repo}>the source</a>.
        </p>
      </div>
      </div>
    </SiteShell>
  );
}

const thStyle: CSSProperties = {
  textAlign: "left",
  fontWeight: 600,
  fontSize: 11.5,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  color: "var(--muted-foreground)",
  padding: "12px 16px",
  borderBottom: "1px solid var(--border)",
  whiteSpace: "nowrap",
};

const tdStyle: CSSProperties = {
  padding: "12px 16px",
  borderBottom: "1px solid color-mix(in oklab, var(--border) 60%, transparent)",
  verticalAlign: "top",
  lineHeight: 1.55,
};
