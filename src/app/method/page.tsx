import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { checks, GROUP_ORDER } from "@/lib/checks";
import { SITE, pageMeta } from "@/lib/site";

/**
 * The method page.
 *
 * This is where a technical reader decides whether to trust the tool, so it
 * names every source, reproduces the scoring rules exactly as they are coded,
 * and states the limits without softening them.
 */

export const metadata = pageMeta({
  title: "Method",
  description:
    "Where every value in an Ocellus report comes from, how the score and grade are computed, why an unavailable source is never scored as a pass, and the specifications each finding is judged against.",
  path: "/method",
});

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
    name: "rdap.org",
    href: "https://rdap.org/",
    what: "The registration record: when the domain was registered, when it expires, the registrar, the registry status flags and the nameservers.",
    how: "RDAP, the JSON successor to WHOIS, redirected to the registry for the TLD.",
  },
  {
    name: "archive.org Wayback",
    href: "https://web.archive.org/",
    what: "The earliest and most recent capture of the address, which bounds how long the site has existed in public.",
    how: "Availability API, one query for each end of the range.",
  },
  {
    name: "Tranco",
    href: "https://tranco-list.eu/",
    what: "The domain's daily rank in a research list built from four providers, used as context rather than as a verdict.",
    how: "Keyless JSON endpoint.",
  },
  {
    name: "CISA Known Exploited Vulnerabilities",
    href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    what: "Whether the product named in the response appears in the catalogue of vulnerabilities with confirmed exploitation in the wild.",
    how: "Single JSON feed, matched by product name.",
  },
  {
    name: "FIRST EPSS",
    href: "https://www.first.org/epss/",
    what: "The estimated probability that a matched CVE is exploited in the next 30 days, with its percentile.",
    how: "Keyless JSON endpoint, queried in one batch per scan.",
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
    label: "RFC 9460, SVCB and HTTPS records",
    href: "https://datatracker.ietf.org/doc/html/rfc9460",
    used: "The apex HTTPS record that tells a client which protocols and endpoints the origin supports.",
  },
  {
    label: "RFC 8460, TLS reporting",
    href: "https://datatracker.ietf.org/doc/html/rfc8460",
    used: "The _smtp._tls record that reports failed TLS negotiation to mail hosts.",
  },
  {
    label: "RFC 9083, RDAP",
    href: "https://datatracker.ietf.org/doc/html/rfc9083",
    used: "The registration record format used in place of WHOIS.",
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

      <ul className="box-grid box-grid--wide mt-5">
        {SOURCES.map((source, index) => (
          <li
            key={source.name}
            className="box rise"
            style={{ ["--i" as string]: Math.min(index, 10) }}
          >
            <div className="box__head">
              <span className="dot tone-info" aria-hidden="true" />
              <h3 className="box__title">
                <a
                  href={source.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: "var(--primary)", textDecoration: "none" }}
                >
                  {source.name}
                </a>
              </h3>
            </div>
            <p className="box__body">{source.what}</p>
            <div className="box__meta">
              <span>{source.how}</span>
            </div>
          </li>
        ))}
      </ul>

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
        <ul className="box-grid not-prose mt-4">
          {FRACTIONS.map((row, index) => (
            <li
              key={row.status}
              className="box box--railed rise tone-idle"
              style={{ ["--i" as string]: index }}
            >
              <div className="box__head">
                <span className="box__title mono">{row.status}</span>
                <span className="chip tabular" style={{ marginLeft: "auto" }}>
                  {row.value}
                </span>
              </div>
              <p className="box__body">{row.note}</p>
            </li>
          ))}
        </ul>
        <p>
          The resulting score maps to a grade by fixed bands. There are no curves, no
          per-site adjustments and no hidden bonuses.
        </p>
        <ul className="box-grid not-prose mt-4">
          {GRADES.map((row, index) => (
            <li key={row.grade} className="box rise" style={{ ["--i" as string]: index }}>
              <div className="flex items-baseline justify-between gap-3">
                <span className="stat" style={{ fontSize: 24 }}>
                  {row.grade}
                </span>
                <span
                  className="tabular"
                  style={{ fontSize: 13, color: "var(--muted-foreground)" }}
                >
                  {row.band}
                </span>
              </div>
            </li>
          ))}
        </ul>

        <h2>Why unavailable is not a pass</h2>
        <p>
          A pass is a claim that a source answered and the answer was correct. If the source did
          not answer, there is nothing to claim. Counting an unreachable source as a pass would
          mean a site behind a strict firewall, or one that rate limits the proxy, scores better
          than a site that answers honestly and has a weak header. It would also make the score
          rise as the scan learned less. So an unavailable check is removed from the arithmetic
          entirely, the report prints the count of checks that could not run, and the score is
          described as being computed over the checks that did. A scan where four checks answered
          and the rest could not run is an A on four checks, not an A on the full set.
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

      <ul className="box-grid box-grid--wide mt-5">
        {SPECS.map((spec, index) => (
          <li key={spec.href} className="box rise" style={{ ["--i" as string]: Math.min(index, 10) }}>
            <div className="box__head">
              <span className="dot tone-idle" aria-hidden="true" />
              <h3 className="box__title">
                <a
                  href={spec.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: "var(--primary)", textDecoration: "none" }}
                >
                  {spec.label}
                </a>
              </h3>
            </div>
            <p className="box__body">{spec.used}</p>
          </li>
        ))}
      </ul>

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
