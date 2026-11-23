import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { ROUTES } from "@/lib/site";

/**
 * The 404.
 *
 * A static export writes this as `404.html` at the site root, which both hosts
 * serve for an unmatched path. It offers the real routes rather than a single
 * "go home" button, because the common cause of a 404 here is a hand-edited scan
 * URL, and the useful next step is a fresh scan, not the landing page.
 */

export const metadata = {
  title: "Not found",
  robots: { index: false, follow: false },
};

export default function NotFound() {
  return (
    <SiteShell>
      <div className="container-page">
        <div className="mx-auto max-w-[62ch] py-20 md:py-28">
          <p className="eyebrow">Error 404</p>
          <h1 className="mt-4" style={{ fontSize: "clamp(1.8rem, 4.2vw, 2.5rem)" }}>
            That page does not exist.
          </h1>
          <p className="mt-4" style={{ fontSize: 16, color: "var(--muted-foreground)" }}>
            The address may have been mistyped, or a page may have moved. If you arrived here from a
            saved scan link, the scan itself is not stored: a report lives only in the tab that ran
            it, so it has to be run again.
          </p>

          <p className="mt-7 flex flex-wrap gap-2">
            <Link href="/scan" className="btn btn-primary">
              Run a scan
            </Link>
            <Link href="/" className="btn btn-quiet">
              Home
            </Link>
          </p>

          <hr className="hairline my-9" />

          <p className="eyebrow">Every page</p>
          <ul className="mt-3 flex flex-wrap gap-2" style={{ listStyle: "none", padding: 0 }}>
            {ROUTES.map((route) => (
              <li key={route.href}>
                <Link href={route.href} className="chip">
                  {route.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </SiteShell>
  );
}
