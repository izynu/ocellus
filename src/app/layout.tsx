import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import "./globals.css";
import { KEYWORDS, SITE, asset } from "@/lib/site";

/*
 * Fonts are self-hosted. The site's own subject is third-party requests, so
 * loading a stylesheet from a font CDN on every page would be a poor example.
 */
const sans = localFont({
  src: [
    { path: "../fonts/inter-400.woff2", weight: "400", style: "normal" },
    { path: "../fonts/inter-500.woff2", weight: "500", style: "normal" },
    { path: "../fonts/inter-600.woff2", weight: "600", style: "normal" },
    { path: "../fonts/inter-700.woff2", weight: "700", style: "normal" },
  ],
  variable: "--font-sans-loaded",
  display: "swap",
  fallback: ["ui-sans-serif", "system-ui", "Segoe UI", "sans-serif"],
});

const mono = localFont({
  src: [
    { path: "../fonts/mono-400.woff2", weight: "400", style: "normal" },
    { path: "../fonts/mono-500.woff2", weight: "500", style: "normal" },
  ],
  variable: "--font-mono-loaded",
  display: "swap",
  fallback: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
});

export const metadata: Metadata = {
  // The origin only. Every literal path below goes through `asset()`, which
  // adds the base path exactly once. Putting the base path here as well
  // produced /ocellus/ocellus/og.png on the Pages build.
  metadataBase: new URL(SITE.origin),
  title: {
    default: `${SITE.name}: website audit`,
    template: `%s · ${SITE.name}`,
  },
  description: SITE.tagline,
  applicationName: SITE.name,
  authors: [{ name: SITE.author, url: SITE.authorUrl }],
  creator: SITE.author,
  keywords: [...KEYWORDS],
  alternates: { canonical: asset("/") },
  openGraph: {
    type: "website",
    siteName: SITE.name,
    title: `${SITE.name}: website audit`,
    description: SITE.tagline,
    url: SITE.url,
    images: [
      { url: asset("/og.png"), width: 1200, height: 630, alt: `${SITE.name} website audit` },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: `${SITE.name}: website audit`,
    description: SITE.tagline,
    images: [asset("/og.png")],
  },
  robots: { index: true, follow: true },
  icons: {
    icon: [
      { url: asset("/icon.svg"), type: "image/svg+xml" },
      { url: asset("/favicon.ico"), sizes: "32x32" },
    ],
    apple: [{ url: asset("/apple-icon.png"), sizes: "180x180" }],
  },
  manifest: asset("/manifest.webmanifest"),
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#080c10" },
    { media: "(prefers-color-scheme: light)", color: "#f3f6f7" },
  ],
  width: "device-width",
  initialScale: 1,
  colorScheme: "dark light",
};

/**
 * The theme is applied before first paint so the page never flashes the wrong
 * surface. An inline script rather than a provider because it must run before
 * React hydrates, and reading the system preference only on the first visit
 * means an explicit choice always wins afterwards.
 */
const THEME_BOOT = `(function(){try{var t=localStorage.getItem("ocellus.theme");if(t!=="light"&&t!=="dark"){t=window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";}document.documentElement.setAttribute("data-theme",t);}catch(e){document.documentElement.setAttribute("data-theme","dark");}})();`;

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT }} />
        {/* The scan's first request goes to a DoH resolver; warming the
            connection saves a round trip on the page where it matters most. */}
        <link rel="preconnect" href="https://dns.google" />
      </head>
      <body className={`${sans.variable} ${mono.variable}`}>
        <a href="#main" className="skip-link">
          Skip to content
        </a>
        {children}
      </body>
    </html>
  );
}
