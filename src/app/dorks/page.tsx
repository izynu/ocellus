import { SiteShell } from "@/components/site/site-shell";
import { DorkCatalogue } from "@/components/recon/dork-catalogue";
import { DORK_CATEGORY_LABEL, DORK_TEMPLATES } from "@/lib/recon/dorks";
import { pageMeta } from "@/lib/site";

/**
 * The dork catalogue.
 *
 * The page is a server component so its metadata and framing ship as static
 * HTML; the catalogue itself is a client component because the target domain is
 * chosen in the page rather than at build time. The claim this page has to get
 * right is the one in its first paragraph: Ocellus generates queries and does
 * not run them, and the engines see the visitor rather than this site.
 *
 * Every count is read from the catalogue, so the framing cannot drift from the
 * templates it describes.
 */

const TEMPLATE_COUNT = DORK_TEMPLATES.length;
const CATEGORY_COUNT = Object.keys(DORK_CATEGORY_LABEL).length;

export const metadata = pageMeta({
  title: "Dorks",
  description: `A catalogue of ${TEMPLATE_COUNT} search-engine dork queries across ${CATEGORY_COUNT} categories for auditing your own site: exposed files, cloud storage, API surface, admin panels, debug output, committed code, leaked secrets and indexed content, generated for any domain and run in your browser.`,
  path: "/dorks",
});

export default function DorksPage() {
  return (
    <SiteShell>
      <div className="container-page">
        <header className="rise pt-14 pb-2 md:pt-20">
          <p className="eyebrow">Search-engine discovery</p>
          <h1 className="mt-4" style={{ fontSize: "clamp(1.9rem, 4.4vw, 2.7rem)", maxWidth: "26ch" }}>
            Dork queries, generated for your domain and run by you.
          </h1>
          <div className="prose mt-6" style={{ maxWidth: "66ch" }}>
            <p>
              A dork is a search-engine query written with operators instead of words. It finds
              what a site has already published and the engine has already indexed: a backup left
              in an upload folder, an admin panel reached by a guessed path, a stack trace that
              names a library version.
            </p>
            <p>
              The catalogue below holds {TEMPLATE_COUNT} queries across {CATEGORY_COUNT}{" "}
              categories. Type your domain once and every query fills in. Ocellus builds the query
              and stops there. You copy it or open it in an engine, so the search is made by your
              browser and your account, not by this site.
            </p>
            <p>
              The queries run against six sources. Google, Bing and DuckDuckGo index pages; Shodan
              indexes hosts and their services; GitHub searches committed code; Censys indexes
              certificates. Each template names the source whose operators it actually uses, and
              the filter above the catalogue narrows by category and by engine.
            </p>
          </div>
        </header>

        <DorkCatalogue />
      </div>
    </SiteShell>
  );
}
