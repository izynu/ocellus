import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { checks, GROUP_LABEL, GROUP_ORDER, groupOf } from "@/lib/checks";
import type { CheckGroup } from "@/lib/types";
import { SITE, asset } from "@/lib/site";

/**
 * The landing page.
 *
 * It describes the tool rather than advertising it: what it measures, how to
 * read a result, and what it deliberately does not do. Every number on the page
 * comes from the registry, so the copy cannot drift from the code.
 */

export const metadata = {
  title: { absolute: `${SITE.name}: website audit` },
  description: `A browser-side audit of ${checks.length} checks against one hostname: DNS, certificates, response headers, email authentication, exposure, privacy, markup, performance, crawlability, reputation and interface friction.`,
  alternates: { canonical: asset("/") },
};

/**
 * One sentence per group, describing what the checks in that group actually
 * determine. Keyed by `CheckGroup`, so adding a group to the type without
 * writing a sentence here fails the build rather than shipping a blank cell.
 */
const GROUP_NOTE: Record<CheckGroup, string> = {
  transport:
    "Which certificates have been issued for the domain, by which authorities, which of them were revoked, and every hop between the address you typed and the page that answered.",
  dns: "The records the zone publishes for address, mail and name service, when the registration began and expires, whether a wildcard answers for names nobody registered, and whether the resolver validated them with DNSSEC.",
  headers:
    "Which protective response headers are set and whether each value is correct, whether the site publishes a current security contact, and which CDN, proxy or firewall sits in front of the origin.",
  email:
    "Whether mail claiming to be from this domain can be authenticated, and whether anyone else can forge it.",
  infrastructure:
    "The address behind the host, the network that announces it, the ports an outside index has seen open, the hostnames under the domain, and whether the software the response names appears in the catalogue of exploited vulnerabilities.",
  privacy: "What the response sets and the document loads before a visitor has agreed to anything.",
  content:
    "Document structure as assistive technology reads it: headings, alternative text, form labels, language and duplicate identifiers.",
  performance: "What the document weighs and what the server says about compression and caching.",
  seo: "Whether a crawler can reach the site, and what a search result or a link preview will show.",
  threat:
    "Threat intelligence that names the domain, whether a filtering resolver refuses to resolve it, how widely it is seen in traffic, and whether the operator has appeared in a disclosed breach.",
  ux: "Interface patterns that obstruct or mislead a person, as far as they can be read from markup alone.",
};

const STATUSES = [
  {
    name: "pass",
    tone: "tone-pass",
    meaning: "The source answered and the answer met the rule.",
  },
  {
    name: "warn",
    tone: "tone-warn",
    meaning: "The source answered and something is worth fixing, though not severe on its own.",
  },
  {
    name: "fail",
    tone: "tone-fail",
    meaning: "The source answered and the rule was broken.",
  },
  {
    name: "unavailable",
    tone: "tone-idle",
    meaning: "The source could not be reached, so no verdict is claimed.",
  },
] as const;

const LIMITS = [
  "It does not render the page. There is no layout engine and no script execution, so it cannot compute colour contrast ratios, measure Core Web Vitals timings, or observe what a page does after load.",
  "It does not test for exploits. A finding describes a configuration or a missing control, not a working attack.",
  "It does not log in, submit a form, or follow links. One document is fetched, not a crawl.",
  "It does not decide whether a site is secure. It reports what public sources say about one hostname at one moment, and the report shows where each value came from.",
];

const STEPS = [
  {
    title: "The browser queries the sources",
    body: "DNS, certificate, header and reputation data come from public APIs that send CORS headers, so each request starts and ends in your browser. No server of this site is in the path.",
  },
  {
    title: "Each check answers one question",
    body: "Every check states the question it asks, the value it measured, and the source that answered. A finding carries the rule it was judged against.",
  },
  {
    title: "The report separates measured from missing",
    body: "A source that fails produces an explicit unavailable result, never a pass. The score is computed only over the checks that returned a verdict, and says so.",
  },
];

export default function HomePage() {
  return (
    <SiteShell>
      <div className="container-page">
      {/* ---------------------------------------------------------- opening -- */}
      <section className="rise pt-14 pb-4 md:pt-24">
        <p className="eyebrow">Website audit</p>
        <h1
          className="mt-4"
          style={{ fontSize: "clamp(2.1rem, 5.4vw, 3.4rem)", maxWidth: "19ch" }}
        >
          What a hostname gives away, measured from public sources.
        </h1>
        <p
          className="mt-6"
          style={{ fontSize: 17.5, maxWidth: "58ch", color: "var(--muted-foreground)" }}
        >
          Ocellus runs {checks.length} fixed checks against one hostname, using public data
          sources that your browser queries directly. It reports what each source answered and
          keeps what it could not reach separate from what it measured.
        </p>

        {/*
          `action` is a literal attribute, not a `next/link`, so Next does not
          apply basePath to it. Without asset() the Pages build posts to
          /scan instead of /ocellus/scan and the primary CTA 404s there while
          working fine on cPanel, which is the worst kind of bug to find in
          production.
        */}
        <form action={asset("/scan")} method="get" className="mt-9 flex flex-col gap-2.5 sm:flex-row">
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
        <p className="mt-3" style={{ fontSize: 13.5, color: "var(--muted-foreground)" }}>
          {checks.length} checks. No account, and no server of ours in between: your browser queries
          each public source directly.
        </p>
      </section>

      {/* -------------------------------------------------- what it measures -- */}
      <section className="mt-16 md:mt-24" aria-labelledby="measures">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 id="measures" style={{ fontSize: 24 }}>
            What it measures
          </h2>
          <p className="tabular" style={{ fontSize: 13.5, color: "var(--muted-foreground)" }}>
            {checks.length} checks in {GROUP_ORDER.length} groups
          </p>
        </div>
        <p
          className="mt-3"
          style={{ fontSize: 15, maxWidth: "62ch", color: "var(--muted-foreground)" }}
        >
          The groups below are generated from the check registry, so this list matches the
          scan. Each sentence states what the checks in that group determine, not what they
          might imply.
        </p>

        <ul className="box-grid box-grid--wide mt-7">
          {GROUP_ORDER.map((group, index) => {
            const members = groupOf(group);
            return (
              <li
                key={group}
                className="box box--raised rise"
                style={{ ["--i" as string]: index }}
              >
                <div className="box__head">
                  <span className="dot tone-info" aria-hidden="true" />
                  <h3 className="box__title">{GROUP_LABEL[group]}</h3>
                </div>
                <p className="box__body">{GROUP_NOTE[group]}</p>
                <div className="box__meta">
                  <span className="tabular">
                    {members.length} {members.length === 1 ? "check" : "checks"}
                  </span>
                </div>
              </li>
            );
          })}
        </ul>
      </section>

      {/* ------------------------------------------------ how a result reads -- */}
      <section className="mt-16 md:mt-24" aria-labelledby="reads">
        <h2 id="reads" style={{ fontSize: 24 }}>
          How a result reads
        </h2>
        <p
          className="mt-3"
          style={{ fontSize: 15, maxWidth: "62ch", color: "var(--muted-foreground)" }}
        >
          Every check ends in one of six states. Four of them appear as a verdict, and the
          difference between the last two matters more than the first three.
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
          style={{ fontSize: 14.5, maxWidth: "62ch", color: "var(--muted-foreground)" }}
        >
          Two further states exist and are not verdicts. <span className="mono">info</span>{" "}
          means the check returned an observation rather than a judgement.{" "}
          <span className="mono">skipped</span> means the check does not apply to this target.
          Neither <span className="mono">unavailable</span> nor{" "}
          <span className="mono">skipped</span> is counted in the score, and neither can raise
          it.
        </p>
      </section>

      {/* --------------------------------------------------- what it cannot -- */}
      <section className="mt-16 md:mt-24" aria-labelledby="cannot">
        <h2 id="cannot" style={{ fontSize: 24 }}>
          What it cannot do
        </h2>
        <div className="box box--raised mt-7" style={{ padding: "20px 22px" }}>
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

      {/* ------------------------------------------------------ how it works -- */}
      <section className="mt-16 md:mt-24" aria-labelledby="works">
        <h2 id="works" style={{ fontSize: 24 }}>
          How it works
        </h2>
        <ol className="box-grid mt-7">
          {STEPS.map((step, index) => (
            <li
              key={step.title}
              className="box box--raised rise"
              style={{ ["--i" as string]: index }}
            >
              <div className="flex items-center gap-3">
                <span
                  className="mono tabular"
                  style={{ fontSize: 12, color: "var(--muted-foreground)" }}
                >
                  {String(index + 1).padStart(2, "0")}
                </span>
                <hr className="hairline m-0 flex-1" />
              </div>
              <h3 className="box__title" style={{ marginTop: 10 }}>
                {step.title}
              </h3>
              <p className="box__body">{step.body}</p>
            </li>
          ))}
        </ol>
      </section>

      {/* ----------------------------------------------------------- closing -- */}
      <section className="mt-16 md:mt-24" aria-labelledby="closing">
        <div className="box box--raised mt-7" style={{ padding: "20px 22px" }}>
          <h2 id="closing" style={{ fontSize: 19 }}>
            The rules are published, not implied.
          </h2>
          <p className="mt-3" style={{ fontSize: 15.5, maxWidth: "66ch" }}>
            The <Link href="/method">method page</Link> names every source, reproduces the
            scoring formula and its grade bands, and lists the specifications each finding is
            judged against. The <Link href="/checks">check catalogue</Link> lists every check,
            the question it asks and the weight it carries in the score.
          </p>
        </div>
      </section>
      </div>
    </SiteShell>
  );
}
