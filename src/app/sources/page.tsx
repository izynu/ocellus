import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { SourceCatalogue } from "@/components/recon/source-catalogue";
import { checks } from "@/lib/checks";
import {
  ACCESS_BARRIER_LABEL,
  ACCESS_BARRIER_NOTE,
  SOURCES,
  nativeTotal,
  type AccessBarrier,
} from "@/lib/recon/sources";
import { pageMeta } from "@/lib/site";

/**
 * The coverage page.
 *
 * For every tool a visitor has heard of, this page answers one question: does a
 * check in this product query it from the browser, and if not, what exactly
 * stops it. The second half is the part that makes the page worth publishing:
 * "needs an API key", "sends no cross-origin header" and "needs a raw socket"
 * are different facts, and each one points at a real limit of a static page.
 *
 * Counts are printed from the data module and the live registry, so the summary
 * cannot drift from the rows beneath it. The registry's check ids are resolved
 * to a set here and passed to the client catalogue, which marks any native row
 * that names a missing check as unverified instead of linking to a check page
 * that does not describe it.
 */

export const metadata = pageMeta({
  title: "Sources",
  description: `The ${SOURCES.length} sources this project knows about, and which ones a browser can query: ${nativeTotal()} answered by a check in Ocellus, the rest listed with the exact barrier that stops a page, from an API key to a raw socket.`,
  path: "/sources",
});

const BARRIERS = Object.keys(ACCESS_BARRIER_LABEL) as AccessBarrier[];

const KNOWN_CHECK_IDS = checks.map((check) => check.id);

export default function SourcesPage() {
  const total = SOURCES.length;
  const native = nativeTotal();
  const barriers = BARRIERS.map((barrier) => ({
    barrier,
    count: SOURCES.filter((entry) => entry.barrier === barrier).length,
  }));

  return (
    <SiteShell>
      <div className="container-page">
        <header className="rise pt-14 pb-2 md:pt-20">
          <p className="eyebrow">Coverage</p>
          <h1 className="mt-4" style={{ fontSize: "clamp(1.9rem, 4.4vw, 2.7rem)", maxWidth: "28ch" }}>
            Every source, and exactly what a browser can reach.
          </h1>
          <div className="prose mt-6" style={{ maxWidth: "68ch" }}>
            <p>
              This page lists {total} sources: the indexes, registries and scanners people reach
              for when they audit a site. For each one it says whether a check in Ocellus queries
              it from your browser, and when it does not, the specific reason it cannot.
            </p>
            <p>
              {native} of the {total} are answered by a check that runs in this tab. The rest are
              listed because a person looking for a tool deserves a signpost rather than a blank
              space, and every one of them names the barrier that a static page cannot cross.
            </p>
          </div>
          <p className="tabular" style={{ marginTop: 18, fontSize: 14, color: "var(--muted-foreground)" }}>
            {native} answered in the browser, {total - native} listed as references.
          </p>
        </header>

        <section className="mt-12 md:mt-16" aria-labelledby="barriers">
          <h2 id="barriers" style={{ fontSize: 22 }}>
            What each barrier means
          </h2>
          <p className="mt-3" style={{ fontSize: 14.5, color: "var(--muted-foreground)", maxWidth: "64ch" }}>
            A row that is not native carries one of six barriers. They are different limits, and
            the count beside each is how many rows in the catalogue it applies to.
          </p>
          <ul className="box-grid mt-5">
            {barriers.map(({ barrier, count }, index) => (
              <li key={barrier} className="box rise" style={{ ["--i" as string]: index }}>
                <div className="box__head">
                  <span className="box__title">{ACCESS_BARRIER_LABEL[barrier]}</span>
                  <span className="chip tabular" style={{ marginLeft: "auto" }}>
                    {count}
                  </span>
                </div>
                <p className="box__body">{ACCESS_BARRIER_NOTE[barrier]}</p>
              </li>
            ))}
          </ul>
        </section>

        <section className="mt-12 md:mt-16" aria-labelledby="catalogue">
          <h2 id="catalogue" style={{ fontSize: 22 }}>
            The catalogue
          </h2>
          <p className="mt-3" style={{ fontSize: 14.5, color: "var(--muted-foreground)", maxWidth: "64ch" }}>
            Filter by name, by the question a source answers, by coverage, or by the barrier that
            applies. Filtering happens in this tab. Nothing typed here is sent anywhere.
          </p>
          <SourceCatalogue knownCheckIds={KNOWN_CHECK_IDS} />
        </section>

        <section className="mt-16 md:mt-20" aria-labelledby="reference-rows">
          <h2 id="reference-rows" style={{ fontSize: 22 }}>
            A reference row is not a defect
          </h2>
          <div className="box box--raised" style={{ marginTop: 14, padding: "18px 20px" }}>
            <p className="prose" style={{ margin: 0, maxWidth: "72ch" }}>
              A port scan, a content fuzz and a live TLS handshake all need a host that opens
              connections the browser is not permitted to open. Ocellus reads the public indexes
              those tools also read, reports what they say, and stops where a page has to stop.
              The <Link href="/recon">recon page</Link> places each source in a workflow and marks
              which phases run here and which need a terminal. The{" "}
              <Link href="/method">method page</Link> names every source a scan actually queries
              and the rules each finding is judged against.
            </p>
          </div>
        </section>
      </div>
    </SiteShell>
  );
}
