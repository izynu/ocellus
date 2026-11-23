import { SiteShell } from "@/components/site/site-shell";
import { DorkCatalogue } from "@/components/recon/dork-catalogue";
import { DORK_TEMPLATES } from "@/lib/recon/dorks";
import { pageMeta } from "@/lib/site";

/**
 * The dork catalogue.
 *
 * The page is a server component so its metadata and framing ship as static
 * HTML; the catalogue itself is a client component because the target domain is
 * chosen in the page rather than at build time. The claim this page has to get
 * right is the one in its first paragraph: Ocellus generates queries and does
 * not run them, and the engines see the visitor rather than this site.
 */

export const metadata = pageMeta({
  title: "Dorks",
  description: `A catalogue of ${DORK_TEMPLATES.length} search-engine dork queries for auditing your own site: exposed files, admin panels, debug output, leaked secrets and indexed content, generated for any domain and run in your browser.`,
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
              The catalogue below holds {DORK_TEMPLATES.length} queries across six categories. Type
              your domain once and every query fills in. Ocellus builds the query and stops there.
              You copy it or open it in an engine, so the search is made by your browser and your
              account, not by this site.
            </p>
          </div>
        </header>

        <DorkCatalogue />
      </div>
    </SiteShell>
  );
}
