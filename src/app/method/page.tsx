import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { checks, GROUP_ORDER } from "@/lib/checks";
import { SOURCES, ACCESS_BARRIER_NOTE, nativeTotal } from "@/lib/recon/sources";
import { SITE, pageMeta } from "@/lib/site";

/**
 * The method page.
 *
 * This is where a technical reader decides whether to trust the tool, so it
 * reproduces the scoring rules exactly as they are coded, states the limits
 * without softening them, and names the specifications a finding is judged
 * against.
 *
 * It does not restate the source list. That lives in `src/lib/recon/sources.ts`
 * and is rendered in full on /sources, so there is one place to keep correct
 * rather than two that can disagree.
 */

export const metadata = pageMeta({
  title: "Method",
  description:
    "Where every value in an Ocellus report comes from, how the score and grade are computed, why an unavailable source is never scored as a pass, and the specifications each finding is judged against.",
  path: "/method",
});

const FRACTIONS = [
  { status: "pass", value: "1.00", note: "The source answered and the rule was met." },
  { status: "info", value: "0.85", note: "An observation rather than a judgement. Scored just below a pass." },
  { status: "warn", value: "0.55", note: "Worth fixing, but not severe on its own." },
  { status: "fail", value: "0.10", note: "The rule was broken. Not zero, because the check did run." },
  { status: "unavailable", value: "removed", note: "Dropped from the numerator and the denominator." },
  { status: "skipped", value: "removed", note: "Dropped from the numerator and the denominator." },
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
    used: "SPF record syntax, the DNS lookup limit, and the all mechanism.",
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
    label: "RFC 8460, TLS reporting",
    href: "https://datatracker.ietf.org/doc/html/rfc8460",
    used: "The _smtp._tls record that reports failed TLS negotiation to mail hosts.",
  },
  {
    label: "RFC 8461, MTA-STS",
    href: "https://www.rfc-editor.org/rfc/rfc8461.html",
    used: "The policy host, the policy file and the DNS record that announces it.",
  },
  {
    label: "RFC 9460, SVCB and HTTPS records",
    href: "https://datatracker.ietf.org/doc/html/rfc9460",
    used: "The apex HTTPS record that advertises supported protocols and endpoints.",
  },
  {
    label: "RFC 9083, RDAP",
    href: "https://datatracker.ietf.org/doc/html/rfc9083",
    used: "The registration record format used in place of WHOIS.",
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
          <p className="mt-5" style={{ fontSize: 16.5, maxWidth: "62ch", color: "var(--muted-foreground)" }}>
            Nothing in a report is inferred or generated. Each value is either what a named
            source returned or an explicit statement that the source could not be reached.
          </p>
        </header>

        <section className="section" aria-labelledby="sources">
          <div className="split">
            <div>
              <h2 id="sources" style={{ fontSize: 22 }}>
                Where the data comes from
              </h2>
              <div className="prose mt-3">
                <p>
                  A scan makes requests from your browser to public services. None of them is
                  operated by this site, and none of the {checks.length} checks depends on a key
                  you do not hold. The report names the source next to every check, so a value can
                  always be traced back to the service that supplied it.
                </p>
                <p>
                  The full catalogue lists {SOURCES.length} sources across 20 categories,{" "}
                  {nativeTotal()} of which this product queries itself. Each row states why a
                  source it does not query cannot be queried, whether that is a missing
                  cross-origin header, an API key, or a socket a browser cannot open.
                </p>
              </div>
              <p className="mt-5 flex flex-wrap gap-2">
                <Link href="/sources" className="btn btn-primary btn-sm">
                  Open the source catalogue
                </Link>
                <Link href="/checks" className="btn btn-quiet btn-sm">
                  See every check
                </Link>
              </p>
            </div>

            <aside className="rail">
              <div className="box box--raised">
                <p className="eyebrow">Access methods</p>
                <ul className="mt-3 flex flex-col gap-3" style={{ listStyle: "none", padding: 0, margin: 0 }}>
                  {(Object.keys(ACCESS_BARRIER_NOTE) as Array<keyof typeof ACCESS_BARRIER_NOTE>).map(
                    (barrier) => (
                      <li key={barrier}>
                        <p className="mono" style={{ fontSize: 12, color: "var(--foreground)" }}>
                          {barrier}
                        </p>
                        <p style={{ marginTop: 2, fontSize: 12.5, color: "var(--muted-foreground)", lineHeight: 1.5 }}>
                          {ACCESS_BARRIER_NOTE[barrier]}
                        </p>
                      </li>
                    )
                  )}
                </ul>
              </div>
            </aside>
          </div>
        </section>

        <section className="section" aria-labelledby="score">
          <h2 id="score" style={{ fontSize: 22 }}>
            How the score is computed
          </h2>
          <div className="prose mt-3">
            <p>
              Each of the {checks.length} checks carries a weight of 1, 2 or 3. A status maps to a
              fixed fraction of that weight. The score is the sum of the fractions earned divided
              by the sum of the weights that were actually scored, multiplied by 100 and rounded to
              the nearest integer.
            </p>
            <p>
              A check whose status is <code>unavailable</code> or <code>skipped</code> is removed
              from both the numerator and the denominator. It contributes nothing and costs
              nothing. If no check produced a verdict, the score is 0 and the grade is F, and the
              report says that nothing could be measured.
            </p>
          </div>

          <ul className="box-grid mt-5">
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

          <p className="prose mt-6" style={{ maxWidth: "68ch" }}>
            The resulting score maps to a grade by fixed bands. There are no curves, no per-site
            adjustments and no hidden bonuses.
          </p>
          <ul className="box-grid box-grid--narrow mt-4">
            {GRADES.map((row, index) => (
              <li key={row.grade} className="box rise" style={{ ["--i" as string]: index }}>
                <div className="flex items-baseline justify-between gap-3">
                  <span className="stat" style={{ fontSize: 24 }}>
                    {row.grade}
                  </span>
                  <span className="tabular" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
                    {row.band}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </section>

        <section className="section" aria-labelledby="unavailable">
          <h2 id="unavailable" style={{ fontSize: 22 }}>
            Why unavailable is not a pass
          </h2>
          <div className="box box--raised prose" style={{ marginTop: 14, padding: "20px 22px" }}>
            <p style={{ marginTop: 0 }}>
              A pass is a claim that a source answered and the answer was correct. If the source
              did not answer, there is nothing to claim.
            </p>
            <p>
              Counting an unreachable source as a pass would mean a site behind a strict firewall,
              or one that rate limits the reader, scores better than a site that answers honestly
              and has a weak header. It would also make the score rise as the scan learned less.
            </p>
            <p style={{ marginBottom: 0 }}>
              So an unavailable check is removed from the arithmetic entirely, the report prints
              how many checks could not run, and the score is described as being computed over the
              checks that did. A scan where four checks answered and the rest could not run is an A
              on four checks, not an A on the full set.
            </p>
          </div>
        </section>

        <section className="section" aria-labelledby="limits">
          <h2 id="limits" style={{ fontSize: 22 }}>
            The limits
          </h2>
          <div className="split" style={{ marginTop: 14 }}>
            <div className="prose" style={{ maxWidth: "none" }}>
              <p>
                <strong>CORS.</strong> A static page can only read a cross-origin response that
                sends an <code>Access-Control-Allow-Origin</code> header. Most sites do not, which
                is why the document is read through a reader service that does. Where a source
                omits the header and has no reader route, the check reports unavailable rather than
                guessing at the body.
              </p>
              <p>
                <strong>Bot walls.</strong> A Cloudflare interstitial, a consent wall or a CAPTCHA
                is not the page. The document layer recognises the common markers and flags the
                document as an interstitial rather than analysing it, because analysing a challenge
                page and reporting on it would be a silent lie about the site.
              </p>
              <p>
                <strong>Rate limits.</strong> Several sources limit by address. A rate-limited
                response is reported as unavailable with a note, and re-running the scan usually
                succeeds.
              </p>
              <p>
                <strong>Staleness.</strong> Shodan InternetDB is an index, not a live probe. It
                reports ports it observed at an earlier crawl, so a port opened or closed since
                then will not be reflected. It is not a port scan.
              </p>
              <p>
                <strong>One document, one moment.</strong> The content checks read a single fetched
                document. A page that varies by user agent, by geography or after JavaScript runs
                is read as the reader saw it. Nothing is rendered, so no value that requires
                layout, computed style or script execution is claimed.
              </p>
            </div>

            <aside className="rail">
              <div className="box box--raised">
                <p className="eyebrow">What a clean report means</p>
                <p className="box__body" style={{ fontSize: 13 }}>
                  It means the checks that ran found nothing they look for. It does not mean the
                  site is secure, and the report says so on every export.
                </p>
              </div>
            </aside>
          </div>
        </section>

        <section className="section" aria-labelledby="specs">
          <h2 id="specs" style={{ fontSize: 22 }}>
            What a finding is judged against
          </h2>
          <p className="prose mt-3">
            Every finding can carry a reference. These are the specifications the checks cite, and
            the part of each that a finding is measured against.
          </p>
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
          <p className="prose mt-8">
            Where no specification covers a check, the report says so and the finding stands on the
            measured value alone. The catalogue of {checks.length} checks in {GROUP_ORDER.length}{" "}
            groups is on the <Link href="/checks">checks page</Link>. The scoring code itself is in
            the repository at <a href={SITE.repo}>the source</a>.
          </p>
        </section>
      </div>
    </SiteShell>
  );
}
