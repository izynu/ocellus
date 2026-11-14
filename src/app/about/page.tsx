import { SiteShell } from "@/components/site/site-shell";
import { checks } from "@/lib/checks";
import { SITE, asset } from "@/lib/site";

/**
 * About.
 *
 * Short on purpose. What the tool is, who maintains it, where the source is,
 * and why it exists. The last part is the honest history: an earlier version of
 * this idea generated its results instead of measuring them, and this version
 * replaces every generated value with a measured one or an explicit gap.
 */

export const metadata = {
  title: "About",
  description: `${SITE.name} is a browser-side website audit maintained by ${SITE.author}. What it is, where the source lives, and why it was rebuilt around measured values.`,
  alternates: { canonical: asset("/about") },
};

export default function AboutPage() {
  return (
    <SiteShell>
      <div className="container-page">
      <header className="rise pt-14 pb-2 md:pt-20">
        <p className="eyebrow">About</p>
        <h1 className="mt-4" style={{ fontSize: "clamp(1.9rem, 4.4vw, 2.7rem)", maxWidth: "24ch" }}>
          A small audit tool that reports what it measured.
        </h1>
      </header>

      <div className="prose mt-8">
        <p>
          {SITE.name} runs {checks.length} checks against one hostname and reports the answer
          each public source gave. It runs entirely in the browser, stores no report on a server,
          and has no account system. The output is a list of measured values, the source behind
          each one, and an explicit gap wherever a source could not be reached.
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
          measure anything. It generated its scores from a seed derived from the URL, so the same
          address always produced the same report, with contrast failures, dark patterns and
          grades that no browser had observed. It looked like a measurement and was not one.
        </p>
        <p>
          This version replaces every generated value with one of two things: a value a named
          source actually returned, or an explicit statement that the value is not available. A
          check that cannot run is reported as unavailable and removed from the score, rather
          than filled in. The result is a narrower tool that claims less, and everything it
          claims can be traced to the service that supplied it on the{" "}
          <a href={asset("/method")}>method page</a>.
        </p>
        <p>
          The rewrite is dated November 2026. Where a capability was dropped in the process, such
          as rendered layout analysis, the report says what it cannot see rather than estimating
          it.
        </p>
      </div>
      </div>
    </SiteShell>
  );
}
