import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { checks } from "@/lib/checks";
import { TOOLS, TOOL_CATEGORIES, nativeCount, type ToolCategoryKey } from "@/lib/recon/tools";
import { pageMeta } from "@/lib/site";

/**
 * Scanner coverage.
 *
 * The page answers one question per row: does Ocellus answer this, or does it
 * not? A directory of tool names would be padding, so every entry carries a
 * coverage badge, and the ones Ocellus does not replace say what a static page
 * cannot do. The badge is the honest part of the page, and it is the reason the
 * page is worth publishing at all.
 *
 * The counts come from the data module, not from prose, so the summary cannot
 * drift from the rows below it.
 */

export const metadata = pageMeta({
  title: "Scanners",
  description: `Where Ocellus sits among the web scanners people already use: ${TOOLS.filter((tool) => tool.coverage === "native").length} of ${TOOLS.length} tools across eight categories, marked by whether the same question is answered in the browser.`,
  path: "/scanners",
});

const NATIVE_TOTAL = TOOLS.filter((tool) => tool.coverage === "native").length;

const KNOWN_CHECK = new Set(checks.map((check) => check.id));

function checkTitle(id: string): string {
  return checks.find((check) => check.id === id)?.title ?? id;
}

function CoverageBadge({ coverage }: { coverage: "native" | "reference" }) {
  const native = coverage === "native";
  return (
    <span
      className={`chip ${native ? "tone-pass" : "tone-idle"}`}
      style={{
        borderColor: native
          ? "color-mix(in oklab, var(--signal-pass) 45%, var(--border))"
          : "var(--border)",
      }}
      title={native ? "Ocellus answers this in the browser" : "Ocellus does not answer this"}
    >
      {native ? "In Ocellus" : "Reference"}
    </span>
  );
}

export default function ScannersPage() {
  return (
    <SiteShell>
      <div className="container-page">
        <header className="rise pt-14 pb-2 md:pt-20">
          <p className="eyebrow">Coverage</p>
          <h1 className="mt-4" style={{ fontSize: "clamp(1.9rem, 4.4vw, 2.7rem)", maxWidth: "28ch" }}>
            The scanners people already use, and which of them this one replaces.
          </h1>
          <div className="prose mt-6" style={{ maxWidth: "68ch" }}>
            <p>
              For each kind of question a scan asks, there is a tool most people reach for. This
              page lists {TOOLS.length} of them across {TOOL_CATEGORIES.length} categories and says,
              for every one, whether Ocellus answers the same question in the browser.
            </p>
            <p>
              {NATIVE_TOTAL} of the {TOOLS.length} are answered by a check in this product. The
              rest need a binary, an API key the visitor holds, or network access a page cannot
              make, and each of those says plainly what it does that a static page cannot. This is
              a reference, not a claim of parity: several of these tools do things a browser-only
              scan never will.
            </p>
          </div>
          <p className="tabular" style={{ marginTop: 18, fontSize: 14, color: "var(--muted-foreground)" }}>
            {NATIVE_TOTAL} answered in the browser, {TOOLS.length - NATIVE_TOTAL} listed as
            references.
          </p>
        </header>

        {TOOL_CATEGORIES.map((category, categoryIndex) => {
          const members = TOOLS.filter((tool) => tool.category === category.key);
          if (members.length === 0) return null;
          const headingId = `scanner-${category.key}`;
          const native = nativeCount(category.key as ToolCategoryKey);
          return (
            <section key={category.key} className="mt-12 md:mt-16" aria-labelledby={headingId}>
              <div className="flex flex-wrap items-baseline justify-between gap-3">
                <h2 id={headingId} style={{ fontSize: 21 }}>
                  {category.label}
                </h2>
                <p className="tabular" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
                  {native} of {members.length} in Ocellus
                </p>
              </div>
              <p className="mt-2" style={{ fontSize: 14, color: "var(--muted-foreground)", maxWidth: "68ch" }}>
                {category.note}
              </p>

              <ul className="box-grid mt-4">
                {members.map((tool, index) => (
                  <li
                    key={tool.name}
                    className={`box rise ${tool.coverage === "native" ? "box--railed tone-pass" : ""}`}
                    style={{ ["--i" as string]: Math.min(index + categoryIndex, 8) }}
                  >
                    <div className="box__head">
                      <h3 className="box__title">
                        <a
                          href={tool.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ color: "var(--foreground)", textDecoration: "none" }}
                        >
                          {tool.name}
                        </a>
                      </h3>
                      <span style={{ marginLeft: "auto" }}>
                        <CoverageBadge coverage={tool.coverage} />
                      </span>
                    </div>

                    <p className="box__body">{tool.purpose}</p>

                    <div className="box__meta">
                      <span className="chip">{tool.cost}</span>
                    </div>

                    {tool.coverage === "native" && tool.checkId && KNOWN_CHECK.has(tool.checkId) && (
                      <p style={{ marginTop: 8, fontSize: 12.5 }}>
                        <span style={{ color: "var(--muted-foreground)" }}>Answered by </span>
                        <Link
                          href="/checks"
                          className="mono"
                          style={{ color: "var(--primary)" }}
                        >
                          {tool.checkId}
                        </Link>
                        <span style={{ color: "var(--muted-foreground)" }}>
                          {" "}
                          ({checkTitle(tool.checkId)})
                        </span>
                      </p>
                    )}

                    {tool.gap && (
                      <p
                        style={{
                          marginTop: 8,
                          fontSize: 12.5,
                          color: "var(--muted-foreground)",
                          lineHeight: 1.5,
                        }}
                      >
                        {tool.gap}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          );
        })}

        <section className="mt-16 md:mt-20" aria-labelledby="scanners-limits">
          <h2 id="scanners-limits" style={{ fontSize: 21 }}>
            What the reference rows are telling you
          </h2>
          <div className="box box--raised" style={{ marginTop: 14, padding: "18px 20px" }}>
            <p className="prose" style={{ margin: 0, maxWidth: "72ch" }}>
              A reference row is not a flaw to fix. A port scan, a content fuzz and a live TLS
              handshake all need a host that opens connections the browser is not permitted to
              open. Ocellus reads the public indexes those tools also read, reports what they say,
              and stops where a page has to stop. Use this page to know which question to take to
              which tool, and which ones this scan already answered.
            </p>
          </div>
          <p style={{ marginTop: 12, fontSize: 13.5, color: "var(--muted-foreground)" }}>
            The <Link href="/recon" style={{ color: "var(--primary)" }}>recon page</Link> puts these
            tools in workflow order, and the{" "}
            <Link href="/method" style={{ color: "var(--primary)" }}>method page</Link> names every
            source a scan queries.
          </p>
        </section>
      </div>
    </SiteShell>
  );
}
