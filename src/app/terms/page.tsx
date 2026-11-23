import { SiteShell } from "@/components/site/site-shell";
import { SITE, pageMeta } from "@/lib/site";

/**
 * Terms.
 *
 * Plain terms for a free, static tool, offered by an individual maintainer. No
 * invented legal entity, no jurisdiction clause that cannot be justified, and no
 * licence name guessed at: the repository holds the licence, and this page
 * points there rather than naming one.
 */

export const metadata = pageMeta({
  title: "Terms",
  description:
    "Terms of use for Ocellus: provided as is, results are automated observations from public sources and not a security assessment, and only scan hosts you own or are authorised to scan.",
  path: "/terms",
});

export default function TermsPage() {
  return (
    <SiteShell>
      <div className="container-page">
        <header className="rise pt-14 pb-2 md:pt-20">
          <p className="eyebrow">Legal</p>
          <h1 className="mt-4" style={{ fontSize: "clamp(1.9rem, 4.4vw, 2.7rem)" }}>
            Terms of use
          </h1>
          <p className="mt-4" style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
            Last updated: 23 November 2026
          </p>
        </header>

        <div className="prose mt-8">
          <p>
            These terms are offered by the maintainer of this site. They cover the use of{" "}
            {SITE.name}, a free static tool that reports what public data sources say about a
            hostname. By using the site you accept them.
          </p>

          <h2>Provided as is</h2>
          <p>
            The site and its reports are provided as is, without warranty of any kind, express or
            implied, including any warranty of accuracy, fitness for a particular purpose or
            non-infringement. The tool may be unavailable, may change, and may be withdrawn at any
            time.
          </p>

          <h2>What a report is, and what it is not</h2>
          <p>
            A report is a set of automated observations drawn from public sources at one moment. It
            is not a security assessment, not a penetration test, and not professional advice of
            any kind. Specifically:
          </p>
          <ul>
            <li>
              A clean report does not mean a site is secure. It means the checks that ran did not
              find what they look for.
            </li>
            <li>
              A finding may be a false positive, a stale index entry, or a correct observation of a
              deliberate choice.
            </li>
            <li>
              Checks that could not run are reported as unavailable and are excluded from the
              score, so a report always states how much of the picture it actually covers.
            </li>
            <li>
              Port lists and any other value sourced from a third-party index describe an earlier
              crawl, not a scan performed now.
            </li>
          </ul>
          <p>
            Verify anything you intend to act on against the source, the specification or the site
            itself before acting.
          </p>

          <h2>Which sites you may scan</h2>
          <p>
            You may only scan sites you own or have permission to scan. The tool queries public
            sources about the hostname you enter, and doing that to a third party without
            authorisation may breach their terms of service or the law where you are. That
            responsibility rests with you, not with the maintainer of this site.
          </p>
          <p>
            The scan is passive by design: it reads public records and indexes and does not send
            probe traffic, fuzz paths, or attempt to authenticate. The dork page generates
            search-engine queries for you to run yourself, and running one against a third party is
            your act, not this site&apos;s.
          </p>

          <h2>Fair use of the underlying services</h2>
          <p>
            A scan queries third-party public services. Running repeated or automated scans against
            this page to exhaust those services is not permitted. Each service has its own fair-use
            and rate-limit terms, and your use of this tool does not exempt you from them.
          </p>

          <h2>No liability</h2>
          <p>
            To the extent permitted by law, the maintainer is not liable for any loss or damage
            arising from the use of this site or from any action taken on the basis of a report,
            whether direct, indirect or consequential. If a jurisdiction does not allow part of this
            exclusion, that part does not apply and the rest stands.
          </p>

          <h2>Source and licence</h2>
          <p>
            The source of this site is at{" "}
            <a href={SITE.repo} target="_blank" rel="noopener noreferrer">
              {SITE.repo}
            </a>
            . See the licence file in the repository for the terms under which it may be used,
            modified and redistributed. Nothing on this page adds to or replaces that licence.
          </p>

          <h2>Changes</h2>
          <p>
            If these terms change, the date at the top of the page changes with them. Continued use
            after a change means the updated terms apply.
          </p>
        </div>
      </div>
    </SiteShell>
  );
}
