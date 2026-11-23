import { SiteShell } from "@/components/site/site-shell";
import { UrlScanner } from "@/components/scan/url-scanner";
import { pageMeta } from "@/lib/site";

/**
 * The URL scanner page.
 *
 * A working scanner, not a description of one: type a URL and it queries the
 * keyless reputation feeds and reads the page. A file tab hashes a file locally
 * so it can be checked without being uploaded.
 */

export const metadata = pageMeta({
  title: "URL and file scanner",
  description:
    "Check a URL against Google Safe Browsing and OpenPhish, read the page it returns, and hash a file locally so it can be checked against VirusTotal without uploading it.",
  path: "/url-scan",
});

export default function UrlScanPage() {
  return (
    <SiteShell>
      <div className="container-page">
        <header className="rise pt-14 pb-2 md:pt-20">
          <p className="eyebrow">URL and file scanning</p>
          <h1 className="mt-4" style={{ maxWidth: "26ch" }}>
            Is this link or file safe?
          </h1>
          <p className="mt-5" style={{ fontSize: "1.02em", maxWidth: "64ch", color: "var(--muted-foreground)" }}>
            A URL is checked against the live reputation feeds and read through a proxy, so you see the
            final address, the server and the title. A file is hashed in this tab and looked up by hash,
            so the file itself is never uploaded.
          </p>
        </header>

        <section className="section-tight">
          <UrlScanner />
        </section>

        <section className="section">
          <h2>What is checked, and what is not</h2>
          <ul className="box-grid box-grid--wide mt-5">
            <li className="box box--railed tone-pass">
              <div className="box__head">
                <span className="dot" aria-hidden="true" />
                <span className="box__title">Google Safe Browsing</span>
              </div>
              <p className="box__body">
                The keyless transparency report returns a per-URL malware and phishing flag. A reply with
                no verdict is reported as no answer, never as clean.
              </p>
            </li>
            <li className="box box--railed tone-pass">
              <div className="box__head">
                <span className="dot" aria-hidden="true" />
                <span className="box__title">OpenPhish</span>
              </div>
              <p className="box__body">
                A live feed of about 300 phishing URLs, matched by hostname. It catches a URL that is
                currently phishing and nothing more.
              </p>
            </li>
            <li className="box box--railed tone-pass">
              <div className="box__head">
                <span className="dot" aria-hidden="true" />
                <span className="box__title">The page itself</span>
              </div>
              <p className="box__body">
                One fetch through a reader returns the final URL after redirects, the server and the page
                title. It is the page as the reader saw it, not as a browser would run it.
              </p>
            </li>
            <li className="box box--railed tone-warn">
              <div className="box__head">
                <span className="dot" aria-hidden="true" />
                <span className="box__title">Not a live sandbox</span>
              </div>
              <p className="box__body">
                A page cannot execute a file or run a multi-engine scan. A clean hash means no engine has
                flagged that exact file, not that it is safe.
              </p>
            </li>
          </ul>
        </section>
      </div>
    </SiteShell>
  );
}
