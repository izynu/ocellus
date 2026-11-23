import { SiteShell } from "@/components/site/site-shell";
import { SOURCES, nativeTotal } from "@/lib/recon/sources";
import { SITE, pageMeta } from "@/lib/site";

/**
 * Privacy.
 *
 * A real policy for a static, browser-side tool. It states what the pages load,
 * what a scan sends and to whom, and what is stored on the device. It invents
 * nothing: there is no company, no email address and no postal address because
 * none exists for this site.
 *
 * The last-updated date is fixed rather than generated, because a date that
 * changes on every build tells a reader nothing about when the policy changed.
 */

export const metadata = pageMeta({
  title: "Privacy",
  description:
    "What Ocellus stores and what it sends: no account, no cookies of its own, no analytics, no third-party scripts, and a scan that queries public services directly from your browser.",
  path: "/privacy",
});

export default function PrivacyPage() {
  return (
    <SiteShell>
      <div className="container-page">
        <header className="rise pt-14 pb-2 md:pt-20">
          <p className="eyebrow">Legal</p>
          <h1 className="mt-4" style={{ fontSize: "clamp(1.9rem, 4.4vw, 2.7rem)" }}>
            Privacy policy
          </h1>
          <p className="mt-4" style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
            Last updated: 23 November 2026
          </p>
        </header>

        <div className="prose mt-8">
          <p>
            {SITE.name} is a static site. There is no server application behind it, no database and
            no account system. This page states exactly what that means for your data.
          </p>

          <h2>What this site does not do</h2>
          <ul>
            <li>No account is required, and none can be created.</li>
            <li>No cookies are set by this site&apos;s own code.</li>
            <li>No analytics, telemetry or error reporting service is loaded.</li>
            <li>
              No third-party scripts are loaded by these pages. The fonts are self-hosted and
              served from this origin, so no font CDN sees a page view.
            </li>
            <li>No tracking pixels, no fingerprinting, no advertising identifiers.</li>
          </ul>

          <h2>What happens when you run a scan</h2>
          <p>
            Your browser sends the hostname you entered to the public services listed in the{" "}
            <a href="/sources">source catalogue</a>. Those services see the scanned hostname and
            your IP address, in the same way any website you visit sees them. Their own handling of
            that request is governed by their policies, not by this one.
          </p>
          <p>
            Nothing is sent to a server operated by this site, because there is no such server. The
            requests are made by your browser directly to each source, and the answers are processed
            in the page.
          </p>
          <p>
            A few sources do not permit a direct cross-origin read, so their content is retrieved
            through a reader service. The scan names that service per check, on the check itself, so
            you can always see when a third party was in the path. Of the {SOURCES.length}{" "}
            catalogued sources, {nativeTotal()} are queried by this product, and only the reader
            route involves an intermediary.
          </p>

          <h2>What is stored on your device</h2>
          <p>Two values are written to browser storage, and both stay on your device:</p>
          <ul>
            <li>
              The last report, in <code>sessionStorage</code> under the key{" "}
              <code>ocellus.report.v1</code>, so that reloading the results page still shows the
              report you just ran. Session storage is cleared when the tab or browser is closed.
            </li>
            <li>
              Your theme choice, in <code>localStorage</code> under the key{" "}
              <code>ocellus.theme</code>, so the site does not flash the wrong theme on the next
              visit. You can clear it at any time through your browser settings, and the site will
              follow your system preference again.
            </li>
          </ul>
          <p>
            Both are readable only by this site in your browser. Neither is transmitted anywhere. If
            storage is blocked or unavailable, the scan still runs; it simply cannot restore the
            report after a reload.
          </p>

          <h2>Personal data</h2>
          <p>
            No personal data is collected, stored, sold or shared by this site. There is no database
            of scans, no list of visitors and no profile of anyone. A scanned hostname is not
            personal data in the hands of this site, because this site never receives it.
          </p>
          <p>
            The one exception is outside this site&apos;s control and worth naming: GitHub serves
            the page you are reading, and GitHub collects standard request logs in the ordinary
            course of serving a website. That is governed by GitHub&apos;s privacy statement.
          </p>

          <h2>Contact</h2>
          <p>
            There is no email address for this project. Any question, correction or data request can
            be raised as an issue at{" "}
            <a href={SITE.issues} target="_blank" rel="noopener noreferrer">
              {SITE.issues}
            </a>
            , which is public by design.
          </p>

          <h2>Changes</h2>
          <p>
            If this policy changes, the date at the top of the page changes with it. Because the
            site stores nothing about you, a change is unlikely to affect data already held: there
            is none.
          </p>
        </div>
      </div>
    </SiteShell>
  );
}
