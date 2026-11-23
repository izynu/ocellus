import Link from "next/link";
import { SiteShell } from "@/components/site/site-shell";
import { checks, GROUP_ORDER } from "@/lib/checks";
import { DORK_TEMPLATES } from "@/lib/recon/dorks";
import { RECON_PHASES } from "@/lib/recon/methodology";
import { NMAP_PROFILES } from "@/lib/recon/nmap";
import { SOURCES, nativeTotal } from "@/lib/recon/sources";
import { SITE, asset } from "@/lib/site";

/**
 * The landing page.
 *
 * It is organised by what you can do, not by how the engine is built. Each of
 * the features below is a working tool behind its own link, so the page reads as
 * a set of doors rather than a brochure: scan a site, check a URL or a file,
 * read an address's ports and write the nmap command, enumerate subdomains,
 * generate dorks, or look up any source in the catalogue.
 *
 * Every count is read from the module that owns it, so no sentence here can
 * drift from the code.
 */

export const metadata = {
  title: { absolute: `${SITE.name}: website audit and recon` },
  description: `Scan a site, check a URL or file, read an address's ports and generate nmap commands, enumerate subdomains and generate dorks. ${checks.length} checks across ${GROUP_ORDER.length} categories and ${SOURCES.length} catalogued public sources, all from your browser with no account and no key of ours.`,
  alternates: { canonical: asset("/") },
};

type Feature = {
  href: string;
  label: string;
  title: string;
  body: string;
  /** What the tool actually does when you open it. */
  works: string;
  metric: string;
  cta: string;
  live: boolean;
};

const FEATURES: Feature[] = [
  {
    href: "/scan",
    label: "Scan",
    title: "Full site scan",
    body: "One hostname, every question at once: DNS, certificates, headers, email, exposure, reputation, privacy, accessibility and performance, grouped so nothing blurs together.",
    works: "Type a domain and results stream in as each source answers.",
    metric: `${checks.length} checks, ${GROUP_ORDER.length} categories`,
    cta: "Scan a site",
    live: true,
  },
  {
    href: "/url-scan",
    label: "URL scan",
    title: "URL and file scanner",
    body: "Check a link against Google Safe Browsing and OpenPhish, read the page it returns, or hash a file locally to look it up without uploading it.",
    works: "Paste a URL for a live verdict, or choose a file to hash it in the tab.",
    metric: "2 live reputation feeds, plus a hash lookup",
    cta: "Check a URL",
    live: true,
  },
  {
    href: "/ports",
    label: "Ports",
    title: "Ports and Nmap",
    body: "Read the ports Shodan recorded for an address, and get the exact nmap and nmapAutomator command that scans it for real from your own machine.",
    works: "Enter a host to read its observed ports, then copy the command that finds the rest.",
    metric: `${NMAP_PROFILES.length} nmap profiles, one keyless index`,
    cta: "Read ports",
    live: true,
  },
  {
    href: "/recon",
    label: "Recon",
    title: "Reconnaissance workflow",
    body: "The address, the hostnames, the fingerprint, the content, then the software. Each phase names the checks that run it in the browser and the tool that finishes it.",
    works: "Read the phases, then jump to the check that carries each one out.",
    metric: `${RECON_PHASES.length} phases, ${RECON_PHASES.filter((p) => p.inBrowser).length} run in the browser`,
    cta: "Open the workflow",
    live: true,
  },
  {
    href: "/dorks",
    label: "Dorks",
    title: "Dork generator",
    body: "Search-engine queries for your own domain, across Google, Bing, DuckDuckGo, Shodan, GitHub and Censys. Generated for you, opened in your browser, never run by this site.",
    works: "Type a domain and every query fills in. Filter by category or engine, then copy or open.",
    metric: `${DORK_TEMPLATES.length} queries across the whole set`,
    cta: "Generate dorks",
    live: true,
  },
  {
    href: "/sources",
    label: "Sources",
    title: "Source catalogue",
    body: "Every index, API and scanner worth knowing, and exactly what a browser can reach of each. Filter by the reason a source cannot be queried.",
    works: "Filter by name, category or access method, and read what each source answers.",
    metric: `${SOURCES.length} sources, ${nativeTotal()} read by this product`,
    cta: "Browse sources",
    live: true,
  },
];

const ALSO = [
  { href: "/checks", title: "Check catalogue", body: "Every check, the question it asks and the weight it carries." },
  { href: "/method", title: "Method", body: "Where each value comes from and how the score is computed." },
  { href: "/about", title: "About", body: "Why the tool exists and what it refuses to do." },
];

export default function HomePage() {
  const native = nativeTotal();

  return (
    <SiteShell>
      <div className="container-page">
        {/* ------------------------------------------------------------ hero -- */}
        <section className="rise pt-12 pb-2 md:pt-20">
          <p className="eyebrow">Website audit and reconnaissance</p>
          <h1 className="mt-3" style={{ maxWidth: "22ch" }}>
            What a hostname gives away, and the tools to ask.
          </h1>
          <p
            className="mt-5"
            style={{ fontSize: "1.04em", maxWidth: "62ch", color: "var(--muted-foreground)" }}
          >
            Six working tools in one page: a full site scan, a URL and file scanner, a ports and Nmap
            console, a recon workflow, a dork generator and a source catalogue. Everything runs in your
            browser against public sources, with no account and no key of ours.
          </p>

          <form
            action={asset("/scan")}
            method="get"
            className="mt-7 flex flex-col gap-2.5 sm:flex-row"
            style={{ maxWidth: 620 }}
          >
            <label htmlFor="url" className="sr-only">
              Website address
            </label>
            <input
              id="url"
              name="url"
              type="text"
              inputMode="url"
              autoComplete="url"
              required
              placeholder="example.com"
              spellCheck={false}
              className="field sm:flex-1"
            />
            <button type="submit" className="btn btn-primary">
              Scan this site
            </button>
          </form>

          <p className="mt-3" style={{ fontSize: "0.86em", color: "var(--muted-foreground)" }}>
            {checks.length} checks in {GROUP_ORDER.length} categories, {native} of {SOURCES.length}{" "}
            catalogued sources read directly. Your browser queries each one; no server of ours is in the
            path.
          </p>
        </section>

        {/* ---------------------------------------------------- the six tools -- */}
        <section className="section" aria-labelledby="tools">
          <div className="flex flex-wrap items-baseline justify-between gap-3">
            <h2 id="tools">What you can do here</h2>
            <p className="tabular" style={{ fontSize: "0.84em", color: "var(--muted-foreground)" }}>
              Tap a tool to open it
            </p>
          </div>

          <ul className="box-grid box-grid--wide mt-6">
            {FEATURES.map((feature, index) => (
              <li key={feature.href}>
                <Link
                  href={feature.href}
                  className="box box--raised rise"
                  style={{
                    ["--i" as string]: index,
                    display: "flex",
                    flexDirection: "column",
                    height: "100%",
                    color: "var(--foreground)",
                  }}
                >
                  <div className="box__head">
                    <span className="chip tone-pass">{feature.label}</span>
                    {feature.live && (
                      <span className="chip" style={{ marginLeft: "auto" }} title="This tool works now">
                        live
                      </span>
                    )}
                  </div>
                  <h3 className="box__title" style={{ fontSize: "1.06em", marginTop: 10 }}>
                    {feature.title}
                  </h3>
                  <p className="box__body" style={{ flex: 1 }}>
                    {feature.body}
                  </p>
                  <p style={{ marginTop: 10, fontSize: "0.82em", color: "var(--foreground)", lineHeight: 1.5 }}>
                    {feature.works}
                  </p>
                  <div
                    className="box__meta"
                    style={{ marginTop: 12, justifyContent: "space-between", width: "100%" }}
                  >
                    <span className="tabular">{feature.metric}</span>
                    <span className="btn btn-primary btn-sm">{feature.cta}</span>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        </section>

        {/* ------------------------------------------------- how the scan reads -- */}
        <section className="section" aria-labelledby="reads">
          <h2 id="reads">How a result reads</h2>
          <p className="mt-3" style={{ fontSize: "0.94em", maxWidth: "64ch", color: "var(--muted-foreground)" }}>
            Every check ends in one of six states. The difference between a pass and an unavailable is
            the point: a source that could not be reached is never counted as a clean result.
          </p>

          <ul className="box-grid box-grid--dense mt-5">
            {[
              { name: "pass", tone: "tone-pass", meaning: "The source answered and the rule was met." },
              { name: "warn", tone: "tone-warn", meaning: "Something worth fixing, not severe on its own." },
              { name: "fail", tone: "tone-fail", meaning: "The rule was broken." },
              { name: "info", tone: "tone-info", meaning: "An observation, not a judgement." },
              {
                name: "unavailable",
                tone: "tone-idle",
                meaning: "The source could not be reached. Excluded from the score, never a pass.",
              },
              { name: "skipped", tone: "tone-idle", meaning: "Does not apply here. Also excluded from the score." },
            ].map((status, index) => (
              <li
                key={status.name}
                className={`box box--railed rise ${status.tone}`}
                style={{ ["--i" as string]: index }}
              >
                <div className="box__head">
                  <span className="dot" aria-hidden="true" />
                  <span className="box__title mono">{status.name}</span>
                </div>
                <p className="box__body">{status.meaning}</p>
              </li>
            ))}
          </ul>
        </section>

        {/* ---------------------------------------------------------- also -- */}
        <section className="section" aria-labelledby="also">
          <h2 id="also">Reference</h2>
          <ul className="box-grid mt-5">
            {ALSO.map((item, index) => (
              <li key={item.href}>
                <Link
                  href={item.href}
                  className="box rise"
                  style={{ display: "block", height: "100%", color: "var(--foreground)", ["--i" as string]: index }}
                >
                  <span className="box__title">{item.title}</span>
                  <p className="box__body">{item.body}</p>
                </Link>
              </li>
            ))}
          </ul>
        </section>

        {/* --------------------------------------------------------- limits -- */}
        <section className="section" aria-labelledby="limits">
          <h2 id="limits">What it does not do</h2>
          <div className="box box--raised mt-4" style={{ padding: "18px 20px" }}>
            <ul className="prose" style={{ margin: 0, maxWidth: "74ch" }}>
              <li>
                It does not render a page or run its scripts, so it cannot measure layout, contrast or
                Core Web Vitals.
              </li>
              <li>It does not test for exploits. A finding is a configuration, not a working attack.</li>
              <li>
                It does not run an active scan. A port scan is a command you run yourself; this page
                reads what an index already saw.
              </li>
              <li>It does not decide whether a site is secure, and every export says so.</li>
            </ul>
          </div>
        </section>
      </div>
    </SiteShell>
  );
}
