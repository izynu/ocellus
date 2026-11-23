import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { checks } from "@/lib/checks";
import { SOURCES, nativeTotal } from "@/lib/recon/sources";
import { SITE, pageMeta } from "@/lib/site";

/**
 * About.
 *
 * Short on purpose: what the tool is, who maintains it, where the source is,
 * and why it exists. The last part is the honest history, because a reader
 * deciding whether to trust a measurement tool deserves to know what it was
 * before.
 */

export const metadata = pageMeta({
  title: "About",
  description: `${SITE.name} is a browser-side website audit maintained by ${SITE.author}. What it is, where the source lives, and why it reports a gap instead of a guess.`,
  path: "/about",
});

export default function AboutPage() {
  return (
    <SiteShell>
      <div className="container-page">
        <header className="rise pt-14 pb-2 md:pt-20">
          <p className="eyebrow">About</p>
          <h1 className="mt-4" style={{ fontSize: "clamp(1.9rem, 4.4vw, 2.7rem)", maxWidth: "24ch" }}>
            An audit tool that shows its sources and its gaps.
          </h1>
        </header>

        <div className="split section-tight">
          <div className="prose">
            <p>
              {SITE.name} runs {checks.length} checks against one hostname and reports the answer
              each public source gave. It runs entirely in the browser, stores no report on a
              server, and has no account system. The output is a list of measured values, the
              source behind each one, and an explicit gap wherever a source could not be reached.
            </p>
            <p>
              It is built and maintained by{" "}
              <a href={SITE.authorUrl} target="_blank" rel="noopener noreferrer">
                {SITE.author}
              </a>
              . The full source is at{" "}
              <a href={SITE.repo} target="_blank" rel="noopener noreferrer">
                {SITE.repo}
              </a>
              , including the check registry, the scoring code and the static build that produces
              this site.
            </p>

            <h2>Why it exists</h2>
            <p>
              It began as a user experience audit tool, and the first version of that tool did not
              measure anything. It generated its scores from a seed derived from the URL, so the
              same address always produced the same report, with contrast failures, dark patterns
              and grades that no browser had observed. It looked like a measurement and was not one.
            </p>
            <p>
              This version replaces every generated value with one of two things: a value a named
              source actually returned, or an explicit statement that the value is not available. A
              check that cannot run is reported as unavailable and removed from the score, rather
              than filled in. The result is a narrower tool that claims less, and everything it
              claims can be traced to the service that supplied it.
            </p>

            <h2>What changed in this revision</h2>
            <p>
              The scan engine was rebuilt around sources that actually answer a browser. Two
              certificate checks had depended on an index that now refuses cross-origin reads and
              returns errors under load, so they were moved to a certificate index that permits
              them, rather than left to report unavailable forever. A subdomain check was flagging a
              domain as failing whenever a hostname happened to contain a fragment such as{" "}
              <code>dev</code> or <code>s1</code>; it now matches whole labels and treats a passive
              DNS record as a lead rather than a verdict.
            </p>
            <p>
              The catalogue of the wider scanner landscape was rebuilt from a list of names into a
              set of {SOURCES.length} rows, {nativeTotal()} of them answered here, each stating why
              the rest cannot be. A name with no reason attached is a directory entry; a name with
              the real constraint attached is a map.
            </p>
          </div>

          <aside className="rail">
            <div className="box box--raised">
              <p className="eyebrow">At a glance</p>
              <dl className="facts" style={{ marginTop: 10 }}>
                <dt>Checks</dt>
                <dd className="tabular">{checks.length}</dd>
                <dt>Sources catalogued</dt>
                <dd className="tabular">{SOURCES.length}</dd>
                <dt>Answered in browser</dt>
                <dd className="tabular">{nativeTotal()}</dd>
                <dt>Backend</dt>
                <dd>none</dd>
                <dt>Account</dt>
                <dd>none</dd>
                <dt>API key</dt>
                <dd>not required</dd>
              </dl>
              <p className="mt-4 flex flex-wrap gap-2">
                <Link href="/scan" className="btn btn-primary btn-sm">
                  Run a scan
                </Link>
                <Link href="/method" className="btn btn-quiet btn-sm">
                  Method
                </Link>
              </p>
            </div>
          </aside>
        </div>
      </div>
    </SiteShell>
  );
}
