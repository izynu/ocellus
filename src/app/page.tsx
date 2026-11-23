import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { checks, GROUP_LABEL, GROUP_ORDER, groupOf } from "@/lib/checks";
import type { CheckGroup } from "@/lib/types";
import {
  ACCESS_BARRIER_LABEL,
  SOURCES,
  SOURCE_CATEGORY_LABEL,
  nativeCount,
  nativeTotal,
  sourcesIn,
  type AccessBarrier,
  type SourceCategory,
} from "@/lib/recon/sources";
import { RECON_PHASES, browserPhaseCount } from "@/lib/recon/methodology";
import { DORK_TEMPLATES } from "@/lib/recon/dorks";
import { SITE, asset } from "@/lib/site";

/**
 * The landing page.
 *
 * It describes the instrument rather than advertising it: what it measures,
 * how a result reads, where the numbers come from, and what it deliberately
 * cannot do. Every count below is read from the registry, the source catalogue
 * or the recon modules, so no sentence here can drift from the code.
 */

export const metadata = {
  title: { absolute: `${SITE.name}: website audit` },
  description: `A browser-side audit of ${checks.length} checks against one hostname: DNS, certificates, response headers, email authentication, exposure, privacy, markup, performance, crawlability, reputation and interface friction.`,
  alternates: { canonical: asset("/") },
};

/**
 * One sentence per group, stating what the checks in that group determine.
 * Keyed by `CheckGroup`, so adding a group to the type without writing a
 * sentence here fails the type check rather than shipping a blank card.
 */
const GROUP_NOTE: Record<CheckGroup, string> = {
  transport:
    "Every certificate issued for the domain, its issuer, whether any were revoked, and each redirect hop between the address you typed and the page that answered.",
  dns: "The records the zone publishes for address, mail and name service, whether the resolver validated them with DNSSEC, and when the registration began and expires.",
  headers:
    "Which protective response headers are set and whether each value is correct, whether security.txt is published, and which CDN or firewall sits in front of the origin.",
  email:
    "Whether mail claiming to be from the domain passes SPF, DKIM and DMARC, and whether anyone else can forge it.",
  infrastructure:
    "The address behind the host, the network that announces it, the ports an outside index has seen open, and which other hostnames share that address.",
  recon:
    "Hostnames that passive DNS and certificate logs record under the domain, and prior public captures of the URL made by other parties.",
  privacy:
    "What the response sets as cookies and what the document loads before a visitor has agreed to anything.",
  content:
    "Document structure as assistive technology reads it: headings, alternative text, form labels, language and duplicate identifiers.",
  performance:
    "What the document weighs, what the server says about compression and caching, and an estimate of the carbon cost of one page view.",
  seo: "Whether a crawler can reach the site, what robots.txt and the sitemap declare, and what a search result or link preview will show.",
  threat:
    "Whether public feeds list the domain for malware or phishing, whether the operator appears in a disclosed breach, and how widely the site is seen in traffic.",
  ux: "Interface patterns in the markup that obstruct or mislead a person, such as forced consent, hidden costs or a decoy control.",
};

const STATUSES = [
  {
    name: "pass",
    tone: "tone-pass",
    meaning: "The source answered and the answer met the rule.",
    counted: true,
  },
  {
    name: "warn",
    tone: "tone-warn",
    meaning: "The source answered and something is worth fixing, though not severe on its own.",
    counted: true,
  },
  {
    name: "fail",
    tone: "tone-fail",
    meaning: "The source answered and the rule was broken.",
    counted: true,
  },
  {
    name: "info",
    tone: "tone-info",
    meaning: "The check returned an observation rather than a judgement.",
    counted: true,
  },
  {
    name: "unavailable",
    tone: "tone-idle",
    meaning: "The source could not be reached, so no verdict is claimed. Excluded from the score.",
    counted: false,
  },
  {
    name: "skipped",
    tone: "tone-idle",
    meaning: "The check does not apply to this target. Excluded from the score.",
    counted: false,
  },
] as const;

const LIMITS = [
  "It does not render the page. There is no layout engine and no script execution, so it cannot compute colour contrast ratios, measure Core Web Vitals timings, or observe what a page does after load.",
  "It does not test for exploits. A finding describes a configuration or a missing control, not a working attack.",
  "It does not log in, submit a form, or follow links. One document is fetched, not a crawl.",
  "It does not run an active scan. DNS resolution and one HTTP fetch aside, it sends nothing to the target; the port list comes from an index another party built.",
  "It does not decide whether a site is secure. It reports what public sources say about one hostname at one moment, and the report shows where each value came from.",
];

const BARRIER_ORDER: AccessBarrier[] = [
  "cors-open",
  "reader-proxied",
  "api-key",
  "raw-socket",
  "web-only",
  "paid-plan",
];

const SOURCE_CATEGORIES = Object.keys(SOURCE_CATEGORY_LABEL) as SourceCategory[];

const SECTIONS = [
  { id: "measures", label: "What it measures" },
  { id: "reads", label: "How a result reads" },
  { id: "sources", label: "Source catalogue" },
  { id: "recon", label: "Recon workflow" },
  { id: "dorks", label: "Dorks" },
  { id: "export", label: "Export" },
  { id: "limits", label: "Limits" },
];

/** Barriers across the whole catalogue, computed rather than typed. */
function barrierCounts(): Record<AccessBarrier, number> {
  const counts = Object.fromEntries(
    BARRIER_ORDER.map((barrier) => [barrier, 0])
  ) as Record<AccessBarrier, number>;
  for (const entry of SOURCES) counts[entry.barrier]++;
  return counts;
}

export default function HomePage() {
  const barriers = barrierCounts();
  const native = nativeTotal();

  return (
    <SiteShell>
      <div className="container-page">
        {/* ---------------------------------------------------------- opening -- */}
        <section className="rise pt-14 pb-4 md:pt-24">
          <p className="eyebrow">Website audit and reconnaissance</p>
          <h1
            className="mt-4"
            style={{ fontSize: "clamp(2.1rem, 5.4vw, 3.4rem)", maxWidth: "21ch" }}
          >
            What a hostname gives away, measured from public sources.
          </h1>
          <p
            className="mt-6"
            style={{ fontSize: 17.5, maxWidth: "58ch", color: "var(--muted-foreground)" }}
          >
            Ocellus runs {checks.length} fixed checks against one hostname, using public data
            sources that your browser queries directly. It reports what each source answered,
            groups the findings by area so they never blur together, and keeps what it could not
            reach separate from what it measured.
          </p>

          {/*
            `action` is a literal attribute, so Next does not apply basePath to
            it. asset() adds the prefix once, or the Pages build would post to
            /scan instead of /ocellus/scan and the primary control would 404.
          */}
          <form
            action={asset("/scan")}
            method="get"
            className="mt-9 flex flex-col gap-2.5 sm:flex-row"
          >
            <label htmlFor="url" className="sr-only">
              Website address
            </label>
            <input
              id="url"
              name="url"
              type="text"
              inputMode="url"
              autoComplete="url"
              required
              placeholder="example.com"
              spellCheck={false}
              className="field sm:flex-1"
            />
            <button type="submit" className="btn btn-primary">
              Run the checks
            </button>
          </form>

          <p className="mt-4" style={{ fontSize: 13.5, color: "var(--muted-foreground)" }}>
            {checks.length} checks in {GROUP_ORDER.length} categories, drawing on{" "}
            {SOURCES.length} catalogued sources, {native} of which run natively from the page. No
            account, no API key, and no server of ours in between.
          </p>
        </section>

        <div className="split section">
          <div style={{ minWidth: 0 }}>
            {/* --------------------------------------------- what it measures -- */}
            <section aria-labelledby="measures">
              <div className="flex flex-wrap items-baseline justify-between gap-3">
                <h2 id="measures" style={{ fontSize: 24 }}>
                  What it measures, by category
                </h2>
                <p
                  className="tabular"
                  style={{ fontSize: 13.5, color: "var(--muted-foreground)" }}
                >
                  {checks.length} checks in {GROUP_ORDER.length} categories
                </p>
              </div>
              <p
                className="mt-3"
                style={{ fontSize: 15, maxWidth: "62ch", color: "var(--muted-foreground)" }}
              >
                The cards below are generated from the check registry, so this list matches the
                scan exactly. Each sentence states what the checks in that category determine,
                not what they might imply.
              </p>

              <ul className="box-grid box-grid--wide mt-7">
                {GROUP_ORDER.map((group, index) => {
                  const members = groupOf(group);
                  const examples = members.slice(0, 3);
                  return (
                    <li key={group}>
                      <Link
                        href={`/checks#group-${group}`}
                        className={`box box--raised box--area rise area-${group}`}
                        style={{
                          ["--i" as string]: index,
                          display: "block",
                          height: "100%",
                          color: "var(--foreground)",
                        }}
                      >
                        <div className="area-head">
                          <span className="dot" aria-hidden="true" />
                          <h3 className="box__title">{GROUP_LABEL[group]}</h3>
                        </div>
                        <p className="box__body">{GROUP_NOTE[group]}</p>
                        <div className="box__meta">
                          <span className="chip tabular">
                            {members.length} {members.length === 1 ? "check" : "checks"}
                          </span>
                        </div>
                        {examples.length > 0 ? (
                          <ul
                            className="mt-3"
                            style={{
                              listStyle: "none",
                              padding: 0,
                              marginBottom: 0,
                              display: "grid",
                              gap: 4,
                              fontSize: 12.5,
                              color: "var(--muted-foreground)",
                            }}
                          >
                            {examples.map((check) => (
                              <li key={check.id} className="truncate-1">
                                <span className="mono" style={{ fontSize: 11 }}>
                                  {check.id}
                                </span>{" "}
                                {check.title}
                              </li>
                            ))}
                          </ul>
                        ) : null}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </section>

            {/* -------------------------------------------- how a result reads -- */}
            <section className="section" aria-labelledby="reads">
              <h2 id="reads" style={{ fontSize: 24 }}>
                How a result reads
              </h2>
              <p
                className="mt-3"
                style={{ fontSize: 15, maxWidth: "62ch", color: "var(--muted-foreground)" }}
              >
                Every check ends in one of six states. The first four carry a verdict or an
                observation. The last two are not verdicts, and they are the two that matter most
                for an honest score.
              </p>

              <ul className="box-grid mt-7">
                {STATUSES.map((status, index) => (
                  <li
                    key={status.name}
                    className={`box box--railed rise ${status.tone}`}
                    style={{ ["--i" as string]: index }}
                  >
                    <div className="box__head">
                      <span className="dot" aria-hidden="true" />
                      <span className={`box__title mono ${status.tone}`}>{status.name}</span>
                    </div>
                    <p className="box__body">{status.meaning}</p>
                  </li>
                ))}
              </ul>

              <p
                className="mt-4"
                style={{ fontSize: 14.5, maxWidth: "64ch", color: "var(--muted-foreground)" }}
              >
                A source that is blocked, rate limited or offline produces{" "}
                <span className="mono">unavailable</span>, never a pass. Both{" "}
                <span className="mono">unavailable</span> and <span className="mono">skipped</span>{" "}
                are removed from the score denominator, so they can neither raise nor lower it. A
                report with nine reachable sources and three blocked ones is scored on nine and
                says so on its face.
              </p>
            </section>

            {/* ---------------------------------------------- source catalogue -- */}
            <section className="section" aria-labelledby="sources">
              <div className="flex flex-wrap items-baseline justify-between gap-3">
                <h2 id="sources" style={{ fontSize: 24 }}>
                  The source catalogue, summarised
                </h2>
                <p className="tabular" style={{ fontSize: 13.5, color: "var(--muted-foreground)" }}>
                  {native} of {SOURCES.length} run natively
                </p>
              </div>
              <p
                className="mt-3"
                style={{ fontSize: 15, maxWidth: "62ch", color: "var(--muted-foreground)" }}
              >
                Every index, API and scanner this project knows about is catalogued with what it
                answers and, when a browser cannot call it, the actual reason. "Needs an API key",
                "no cross-origin header" and "needs a raw socket" are different facts, and the
                catalogue gives the true one.{" "}
                <Link href="/sources">Read the full catalogue</Link>.
              </p>

              <div className="mt-6 grid gap-3 sm:grid-cols-2">
                {BARRIER_ORDER.map((barrier, index) => (
                  <div
                    key={barrier}
                    className="box rise"
                    style={{ ["--i" as string]: index }}
                  >
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="box__title">{ACCESS_BARRIER_LABEL[barrier]}</span>
                      <span className="mono tabular" style={{ fontSize: 13 }}>
                        {barriers[barrier]}
                      </span>
                    </div>
                    <div
                      className="meter mt-3 tone-info"
                      role="img"
                      aria-label={`${ACCESS_BARRIER_LABEL[barrier]}: ${barriers[barrier]} of ${SOURCES.length} sources`}
                    >
                      <div
                        className="meter__fill"
                        style={{
                          width: `${Math.round((barriers[barrier] / SOURCES.length) * 100)}%`,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>

              <h3 className="mt-10" style={{ fontSize: 17 }}>
                Native coverage by source category
              </h3>
              <p className="mt-2" style={{ fontSize: 13.5, color: "var(--muted-foreground)" }}>
                Native means a check in this codebase queries that source from the browser. The
                rest are catalogued as references, each with the barrier that rules it out.
              </p>
              <div className="box mt-4" style={{ padding: 0 }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5 }}>
                  <caption className="sr-only">
                    Native and total source counts by category
                  </caption>
                  <thead>
                    <tr>
                      <th
                        scope="col"
                        style={{
                          textAlign: "left",
                          padding: "11px 14px",
                          fontSize: 11,
                          letterSpacing: "0.07em",
                          textTransform: "uppercase",
                          color: "var(--muted-foreground)",
                          borderBottom: "1px solid var(--border)",
                          fontWeight: 600,
                        }}
                      >
                        Category
                      </th>
                      <th
                        scope="col"
                        style={{
                          textAlign: "right",
                          padding: "11px 14px",
                          fontSize: 11,
                          letterSpacing: "0.07em",
                          textTransform: "uppercase",
                          color: "var(--muted-foreground)",
                          borderBottom: "1px solid var(--border)",
                          fontWeight: 600,
                          width: 96,
                        }}
                      >
                        Native
                      </th>
                      <th
                        scope="col"
                        style={{
                          textAlign: "right",
                          padding: "11px 14px",
                          fontSize: 11,
                          letterSpacing: "0.07em",
                          textTransform: "uppercase",
                          color: "var(--muted-foreground)",
                          borderBottom: "1px solid var(--border)",
                          fontWeight: 600,
                          width: 72,
                        }}
                      >
                        Total
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {SOURCE_CATEGORIES.map((category) => {
                      const total = sourcesIn(category).length;
                      if (total === 0) return null;
                      const count = nativeCount(category);
                      return (
                        <tr key={category}>
                          <td
                            style={{
                              padding: "9px 14px",
                              borderBottom: "1px solid color-mix(in oklab, var(--border) 55%, transparent)",
                            }}
                          >
                            {SOURCE_CATEGORY_LABEL[category]}
                          </td>
                          <td
                            className="mono tabular"
                            style={{
                              padding: "9px 14px",
                              textAlign: "right",
                              borderBottom: "1px solid color-mix(in oklab, var(--border) 55%, transparent)",
                              color: count > 0 ? "var(--foreground)" : "var(--muted-foreground)",
                            }}
                          >
                            {count}
                          </td>
                          <td
                            className="mono tabular"
                            style={{
                              padding: "9px 14px",
                              textAlign: "right",
                              borderBottom: "1px solid color-mix(in oklab, var(--border) 55%, transparent)",
                              color: "var(--muted-foreground)",
                            }}
                          >
                            {total}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>

            {/* -------------------------------------------------- recon workflow -- */}
            <section className="section" aria-labelledby="recon">
              <h2 id="recon" style={{ fontSize: 24 }}>
                The recon workflow, compressed
              </h2>
              <p
                className="mt-3"
                style={{ fontSize: 15, maxWidth: "62ch", color: "var(--muted-foreground)" }}
              >
                The checks sit inside a published reconnaissance sequence: learn the address
                space, then the hostnames, then fingerprint what answers, then read the content,
                parameters and software. Ocellus carries out {browserPhaseCount()} of the{" "}
                {RECON_PHASES.length} phases in the browser, and names the terminal tool for each
                phase it cannot run rather than implying the scan does it.{" "}
                <Link href="/recon">See the phases and their tools</Link>.
              </p>
            </section>

            {/* --------------------------------------------------------- dorks -- */}
            <section className="section" aria-labelledby="dorks">
              <h2 id="dorks" style={{ fontSize: 24 }}>
                Dorks, and why they are yours to run
              </h2>
              <p
                className="mt-3"
                style={{ fontSize: 15, maxWidth: "62ch", color: "var(--muted-foreground)" }}
              >
                A dork is a search-engine query built from operators instead of words, for
                finding files, admin panels and debug output a site published by accident.
                Ocellus generates {DORK_TEMPLATES.length} of them for your target and opens the
                query in your browser. It never runs one itself: every engine forbids automated
                querying without a key, and a report that claimed otherwise would describe a
                request nobody made. <Link href="/dorks">Browse the dork catalogue</Link>.
              </p>
            </section>

            {/* --------------------------------------------------------- export -- */}
            <section className="section" aria-labelledby="export">
              <h2 id="export" style={{ fontSize: 24 }}>
                Every report leaves with you
              </h2>
              <div className="box box--raised mt-6" style={{ padding: "20px 22px" }}>
                <p style={{ fontSize: 15.5, maxWidth: "66ch" }}>
                  Any finished report exports to a print-ready PDF, through the browser&apos;s own
                  print dialog, and to a JSON file holding the full result: each check, its
                  status, the value measured, the source that answered and the rule it was judged
                  against. Both are produced in your tab. Nothing is uploaded to produce either.
                </p>
                <div className="box__meta" style={{ marginTop: 12 }}>
                  <span className="chip">PDF</span>
                  <span className="chip">JSON</span>
                  <span className="chip">schema {SITE.reportVersion}</span>
                  <span>client-side only</span>
                </div>
              </div>
            </section>

            {/* --------------------------------------------------------- limits -- */}
            <section className="section" aria-labelledby="limits">
              <h2 id="limits" style={{ fontSize: 24 }}>
                What it cannot do
              </h2>
              <div className="box box--raised mt-6" style={{ padding: "20px 22px" }}>
                <ul className="m-0 list-none space-y-4 p-0">
                  {LIMITS.map((limit) => (
                    <li key={limit} className="flex gap-3">
                      <span
                        className="dot tone-idle"
                        style={{ marginTop: 9 }}
                        aria-hidden="true"
                      />
                      <span style={{ fontSize: 15.5, maxWidth: "66ch" }}>{limit}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </section>

            {/* -------------------------------------------------------- closing -- */}
            <section className="section" aria-labelledby="closing">
              <div className="box box--raised" style={{ padding: "20px 22px" }}>
                <h2 id="closing" style={{ fontSize: 19 }}>
                  The rules are published, not implied.
                </h2>
                <p className="mt-3" style={{ fontSize: 15.5, maxWidth: "66ch" }}>
                  The <Link href="/method">method page</Link> names every source, reproduces the
                  scoring formula and its grade bands, and lists the specifications each finding
                  is judged against. The <Link href="/checks">check catalogue</Link> lists every
                  check, the question it asks and the weight it carries. The{" "}
                  <Link href="/sources">source catalogue</Link> accounts for every index and
                  scanner that answers the same questions, and why the browser cannot reach the
                  ones it cannot.
                </p>
              </div>
            </section>
          </div>

          {/* ------------------------------------------------------------- rail -- */}
          <aside className="rail hidden lg:block" aria-label="On this page">
            <nav
              className="box"
              aria-label="Sections on this page"
              style={{ padding: "14px 15px" }}
            >
              <p className="eyebrow">On this page</p>
              <ul className="mt-3" style={{ listStyle: "none", padding: 0, margin: 0 }}>
                {SECTIONS.map((section) => (
                  <li key={section.id} style={{ marginBlock: 6 }}>
                    <a
                      href={`#${section.id}`}
                      style={{
                        fontSize: 13.5,
                        color: "var(--muted-foreground)",
                        textDecoration: "none",
                      }}
                    >
                      {section.label}
                    </a>
                  </li>
                ))}
              </ul>
              <hr className="hairline" style={{ marginBlock: 14 }} />
              <Link
                href="/scan"
                className="btn btn-primary btn-sm"
                style={{ width: "100%" }}
              >
                Run a scan
              </Link>
            </nav>
          </aside>
        </div>
      </div>
    </SiteShell>
  );
}
