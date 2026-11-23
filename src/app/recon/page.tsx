import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { checks } from "@/lib/checks";
import { RECON_PHASES, browserPhaseCount } from "@/lib/recon/methodology";
import { pageMeta } from "@/lib/site";

/**
 * The reconnaissance methodology, and which of its phases Ocellus runs.
 *
 * The phases are a published workflow, and the page's job is to place the tool
 * honestly inside it. The column that separates a phase a scan performs from one
 * that needs a terminal is the whole point of the page: a walkthrough that
 * implied Ocellus did all of it would describe software that does not exist.
 *
 * The check ids on each phase are resolved against the live registry, so a
 * phase can never link to a check that has been renamed or removed.
 */

export const metadata = pageMeta({
  title: "Recon",
  description: `The reconnaissance workflow Ocellus was built around: ${RECON_PHASES.length} phases from address space to reputation, with the ${browserPhaseCount()} a browser can run and the ones that need a terminal.`,
  path: "/recon",
});

const KNOWN_CHECK = new Set(checks.map((check) => check.id));

function StatusBadge({ inBrowser }: { inBrowser: boolean }) {
  return (
    <span
      className={`chip ${inBrowser ? "tone-pass" : "tone-idle"}`}
      style={{
        borderColor: inBrowser
          ? "color-mix(in oklab, var(--signal-pass) 45%, var(--border))"
          : "var(--border)",
      }}
    >
      {inBrowser ? "Runs in Ocellus" : "Needs a terminal"}
    </span>
  );
}

export default function ReconPage() {
  const total = RECON_PHASES.length;
  const inBrowser = browserPhaseCount();

  return (
    <SiteShell>
      <div className="container-page">
        <header className="rise pt-14 pb-2 md:pt-20">
          <p className="eyebrow">Methodology</p>
          <h1 className="mt-4" style={{ fontSize: "clamp(1.9rem, 4.4vw, 2.7rem)", maxWidth: "26ch" }}>
            Recon in order, and what a browser can actually reach.
          </h1>
          <div className="prose mt-6" style={{ maxWidth: "66ch" }}>
            <p>
              Reconnaissance is a sequence of questions, each answered before the next is worth
              asking: which networks, then which hosts, then what answers on them, then what they
              publish, then what the software is. The order is the one the bug-bounty community
              settled on, and this page names its source rather than presenting it as new.
            </p>
            <p>
              Of the {total} phases, {inBrowser} run in Ocellus. The rest are listed because the
              workflow is incomplete without them, and each of those is marked as needing a
              terminal: a static page cannot open a socket, send a packet or fuzz a wordlist, and
              this one does not pretend to.
            </p>
          </div>
          <p
            className="tabular"
            style={{ marginTop: 18, fontSize: 14, color: "var(--muted-foreground)" }}
          >
            {inBrowser} of {total} phases run in the browser. {total - inBrowser} need a tool on
            your own machine.
          </p>
        </header>

        <ol className="box-grid box-grid--wide mt-10" style={{ counterReset: "step 0" }}>
          {RECON_PHASES.map((phase, index) => {
            const linked = phase.checks.filter((id) => KNOWN_CHECK.has(id));
            return (
              <li
                key={phase.id}
                className={`box box--raised box--railed rise ${
                  phase.inBrowser ? "tone-pass" : "tone-idle"
                }`}
                style={{ ["--i" as string]: Math.min(index, 10), padding: "18px 20px" }}
              >
                <div className="flex items-center gap-3">
                  <span
                    className="mono tabular"
                    style={{ fontSize: 12.5, color: "var(--muted-foreground)" }}
                  >
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <StatusBadge inBrowser={phase.inBrowser} />
                  <hr className="hairline m-0 flex-1" />
                </div>

                <h2 className="box__title" style={{ fontSize: 19, marginTop: 12 }}>
                  {phase.title}
                </h2>
                <p
                  className="mono"
                  style={{ marginTop: 6, fontSize: 12.5, color: "var(--muted-foreground)" }}
                >
                  {phase.question}
                </p>
                <p className="box__body" style={{ marginTop: 10, fontSize: 14 }}>
                  {phase.body}
                </p>

                <div style={{ marginTop: 14 }}>
                  <p className="eyebrow" style={{ marginBottom: 7 }}>
                    Tools for this step
                  </p>
                  <ul
                    style={{
                      listStyle: "none",
                      padding: 0,
                      margin: 0,
                      display: "flex",
                      flexWrap: "wrap",
                      gap: 6,
                    }}
                  >
                    {phase.tools.map((tool) => (
                      <li key={tool}>
                        <span className="chip chip--wrap">{tool}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {linked.length > 0 && (
                  <div style={{ marginTop: 12 }}>
                    <p className="eyebrow" style={{ marginBottom: 7 }}>
                      Checks in this scan
                    </p>
                    <ul
                      style={{
                        listStyle: "none",
                        padding: 0,
                        margin: 0,
                        display: "flex",
                        flexWrap: "wrap",
                        gap: 6,
                      }}
                    >
                      {linked.map((id) => (
                        <li key={id}>
                          <Link href="/checks" className="chip mono chip--wrap">
                            {id}
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="box__meta" style={{ marginTop: 12 }}>
                  <a
                    href={phase.sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: "var(--primary)" }}
                  >
                    {phase.source}
                  </a>
                </div>
              </li>
            );
          })}
        </ol>

        <section className="mt-16 md:mt-20" aria-labelledby="recon-honesty">
          <h2 id="recon-honesty" style={{ fontSize: 21 }}>
            Why the terminal-only phases are listed
          </h2>
          <div className="box box--raised" style={{ marginTop: 14, padding: "18px 20px" }}>
            <ul className="prose" style={{ margin: 0, maxWidth: "70ch" }}>
              <li>
                A complete recon workflow includes content and parameter discovery and a live port
                scan. Leaving them out would produce a list that looks complete and is not.
              </li>
              <li>
                Ocellus does not perform those steps. It reads what a public index already
                recorded and stops there. The badge on each phase says which it is.
              </li>
              <li>
                Where a phase is partly in the browser, the phase text names the part the check
                covers and the part it does not. A certificate list, for example, is public and
                readable; a live TLS handshake audit needs a host that can negotiate with the
                target.
              </li>
            </ul>
          </div>
          <p style={{ marginTop: 12, fontSize: 13.5, color: "var(--muted-foreground)" }}>
            The <Link href="/scanners" style={{ color: "var(--primary)" }}>scanner coverage page</Link>{" "}
            lists the named tools by category and marks which ones Ocellus answers itself. The{" "}
            <Link href="/dorks" style={{ color: "var(--primary)" }}>dork page</Link> generates the
            search-engine step for any domain.
          </p>
        </section>
      </div>
    </SiteShell>
  );
}
