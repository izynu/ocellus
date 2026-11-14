import Link from "next/link";
import { SITE, ROUTES, LEGAL_ROUTES } from "@/lib/site";
import { ThemeToggle } from "./theme-toggle";
import { Scene } from "./scene";

/**
 * The wordmark.
 *
 * An ocellus is the simple eye of an insect: a single lens that resolves light
 * and dark rather than an image. The mark is that lens, drawn as one filled
 * pupil inside one ring. No gradient, no shadow, no letterspacing trick.
 */
export function Mark({ size = 26 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      role="img"
      aria-label={SITE.name}
      className="flex-none"
    >
      <circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" strokeOpacity="0.32" strokeWidth="2" />
      <circle cx="16" cy="16" r="8.5" fill="none" stroke="currentColor" strokeWidth="2" />
      <circle cx="16" cy="16" r="3.6" fill="currentColor" />
    </svg>
  );
}

function Wordmark() {
  return (
    <Link href="/" className="flex items-center gap-2.5 no-underline" style={{ color: "var(--foreground)" }}>
      <Mark />
      <span style={{ fontSize: 17, fontWeight: 600, letterSpacing: "-0.02em" }}>{SITE.name}</span>
    </Link>
  );
}

function NavLinks() {
  return (
    <nav aria-label="Primary" className="hidden items-center gap-1 md:flex">
      {ROUTES.filter((r) => r.href !== "/").map((r) => (
        <Link
          key={r.href}
          href={r.href}
          className="btn btn-ghost btn-sm"
          style={{ fontWeight: 500 }}
        >
          {r.label}
        </Link>
      ))}
    </nav>
  );
}

/**
 * Site header. Glass, because it floats over the scene and content scrolls
 * beneath it. Sticky rather than fixed so it never covers the top of a page.
 */
export function SiteHeader() {
  return (
    <header
      className="sticky top-0 z-40"
      style={{
        background: "color-mix(in oklab, var(--background) 72%, transparent)",
        backdropFilter: "blur(18px) saturate(1.3)",
        WebkitBackdropFilter: "blur(18px) saturate(1.3)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <div className="container-page flex h-16 items-center justify-between gap-4">
        <Wordmark />
        <div className="flex items-center gap-1.5">
          <NavLinks />
          <ThemeToggle />
          <Link href="/scan" className="btn btn-primary btn-sm ml-1">
            Run a scan
          </Link>
        </div>
      </div>
      {/* Below the breakpoint the nav collapses to a single row of links. */}
      <div className="container-page flex gap-1 overflow-x-auto pb-2 md:hidden">
        {ROUTES.filter((r) => r.href !== "/").map((r) => (
          <Link key={r.href} href={r.href} className="btn btn-ghost btn-sm">
            {r.label}
          </Link>
        ))}
      </div>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer style={{ borderTop: "1px solid var(--border)", marginTop: 96 }}>
      <div className="container-page py-12">
        <div className="flex flex-col gap-10 md:flex-row md:justify-between">
          <div style={{ maxWidth: 340 }}>
            <div className="flex items-center gap-2.5" style={{ color: "var(--foreground)" }}>
              <Mark size={22} />
              <span style={{ fontSize: 15, fontWeight: 600 }}>{SITE.name}</span>
            </div>
            <p style={{ marginTop: 12, fontSize: 14, color: "var(--muted-foreground)", lineHeight: 1.6 }}>
              {SITE.tagline}
            </p>
          </div>

          <div className="flex gap-14">
            <nav aria-label="Product" className="flex flex-col gap-2.5">
              <span className="eyebrow">Product</span>
              {ROUTES.map((r) => (
                <Link key={r.href} href={r.href} style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
                  {r.label}
                </Link>
              ))}
            </nav>
            <nav aria-label="Legal" className="flex flex-col gap-2.5">
              <span className="eyebrow">Legal</span>
              {LEGAL_ROUTES.map((r) => (
                <Link key={r.href} href={r.href} style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
                  {r.label}
                </Link>
              ))}
              <a
                href={SITE.repo}
                rel="noopener noreferrer"
                target="_blank"
                style={{ fontSize: 14, color: "var(--muted-foreground)" }}
              >
                Source
              </a>
            </nav>
          </div>
        </div>

        <hr className="hairline" style={{ marginBlock: 28 }} />

        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <p style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
            {SITE.year} {SITE.name}. Built and maintained by{" "}
            <a href={SITE.authorUrl} rel="noopener noreferrer" target="_blank" style={{ color: "var(--foreground)" }}>
              {SITE.author}
            </a>
            .
          </p>
          <p style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
            Every scan runs in your browser. Nothing is uploaded.
          </p>
        </div>
      </div>
    </footer>
  );
}

/**
 * Page shell. One component so every route shares the scene, the skip target
 * and the same vertical rhythm.
 */
export function SiteShell({ children }: { children: React.ReactNode }) {
  return (
    <>
      <Scene />
      <SiteHeader />
      <main id="main">{children}</main>
      <SiteFooter />
    </>
  );
}
