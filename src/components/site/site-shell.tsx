import Link from "next/link";
import {
  FOOTER_PRODUCT,
  FOOTER_REFERENCE,
  LEGAL_ROUTES,
  NAV_ROUTES,
  SITE,
} from "@/lib/site";
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
      <circle
        cx="16"
        cy="16"
        r="14"
        fill="none"
        stroke="currentColor"
        strokeOpacity="0.32"
        strokeWidth="2"
      />
      <circle cx="16" cy="16" r="8.5" fill="none" stroke="currentColor" strokeWidth="2" />
      <circle cx="16" cy="16" r="3.6" fill="currentColor" />
    </svg>
  );
}

function Wordmark() {
  return (
    <Link
      href="/"
      className="flex items-center gap-2.5 no-underline"
      style={{ color: "var(--foreground)" }}
    >
      <Mark />
      <span style={{ fontSize: 17, fontWeight: 600, letterSpacing: "-0.02em" }}>
        {SITE.name}
      </span>
    </Link>
  );
}

/**
 * Site header. Liquid glass, because it floats over the scene and content
 * scrolls beneath it. Sticky rather than fixed so it never covers the top of a
 * page. The blur and the hairline are the whole effect: nothing moves, nothing
 * follows the pointer.
 *
 * The nav is the product surface only (`NAV_ROUTES`); the reference and legal
 * pages live in the footer, so the bar stays readable at any width.
 */
export function SiteHeader() {
  return (
    <header
      className="sticky top-0 z-40 glass--liquid"
      style={{
        background: "color-mix(in oklab, var(--background) 78%, transparent)",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <div className="container-page flex h-16 items-center justify-between gap-4">
        <Wordmark />

        <div className="flex items-center gap-1.5">
          <nav aria-label="Primary" className="hidden items-center gap-0.5 md:flex">
            {NAV_ROUTES.map((route) => (
              <Link
                key={route.href}
                href={route.href}
                className="btn btn-ghost btn-sm"
                style={{ fontWeight: 500 }}
              >
                {route.label}
              </Link>
            ))}
          </nav>
          <ThemeToggle />
          <Link href="/scan" className="btn btn-primary btn-sm" style={{ marginLeft: 4 }}>
            Run a scan
          </Link>
        </div>
      </div>

      {/* Below the breakpoint the nav collapses to a scrollable glass dock. */}
      <div className="container-page md:hidden" style={{ paddingBottom: 10 }}>
        <nav aria-label="Sections" className="dock scroller p-1">
          {NAV_ROUTES.map((route) => (
            <Link
              key={route.href}
              href={route.href}
              className="btn btn-ghost btn-sm"
              style={{ flex: "none" }}
            >
              {route.label}
            </Link>
          ))}
        </nav>
      </div>
    </header>
  );
}

function FooterColumn({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <nav aria-label={label} className="flex flex-col gap-2.5">
      <span className="eyebrow">{label}</span>
      {children}
    </nav>
  );
}

const footerLinkStyle = { fontSize: 14, color: "var(--muted-foreground)" } as const;

export function SiteFooter() {
  return (
    <footer style={{ borderTop: "1px solid var(--border)", marginTop: 96 }}>
      <div className="container-page py-12">
        <div className="grid gap-10 md:grid-cols-[minmax(0,1fr)_auto]">
          <div style={{ maxWidth: 340 }}>
            <div className="flex items-center gap-2.5" style={{ color: "var(--foreground)" }}>
              <Mark size={22} />
              <span style={{ fontSize: 15, fontWeight: 600 }}>{SITE.name}</span>
            </div>
            <p
              style={{
                marginTop: 12,
                fontSize: 14,
                color: "var(--muted-foreground)",
                lineHeight: 1.6,
              }}
            >
              {SITE.tagline}
            </p>
          </div>

          <div className="grid grid-cols-2 gap-x-10 gap-y-8 sm:grid-cols-3">
            <FooterColumn label="Product">
              {FOOTER_PRODUCT.map((route) => (
                <Link key={route.href} href={route.href} style={footerLinkStyle}>
                  {route.label}
                </Link>
              ))}
            </FooterColumn>

            <FooterColumn label="Reference">
              {FOOTER_REFERENCE.map((route) => (
                <Link key={route.href} href={route.href} style={footerLinkStyle}>
                  {route.label}
                </Link>
              ))}
              <a
                href={SITE.repo}
                rel="noopener noreferrer"
                target="_blank"
                style={footerLinkStyle}
              >
                Source
              </a>
            </FooterColumn>

            <FooterColumn label="Legal">
              {LEGAL_ROUTES.map((route) => (
                <Link key={route.href} href={route.href} style={footerLinkStyle}>
                  {route.label}
                </Link>
              ))}
            </FooterColumn>
          </div>
        </div>

        <hr className="hairline" style={{ marginBlock: 28 }} />

        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <p style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
            {SITE.year} {SITE.name}. Built and maintained by{" "}
            <a
              href={SITE.authorUrl}
              rel="noopener noreferrer"
              target="_blank"
              style={{ color: "var(--foreground)" }}
            >
              {SITE.author}
            </a>
            .
          </p>
          <p style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
            Every scan runs in your browser. Nothing is uploaded to this site.
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
