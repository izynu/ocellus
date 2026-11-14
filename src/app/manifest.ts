import type { MetadataRoute } from "next";
import { SITE, asset } from "@/lib/site";

/**
 * The web app manifest, generated rather than served from `public/` so the
 * icon and start URLs carry the base path. A static file in `public/` would
 * keep pointing at /icon.svg and break under the GitHub Pages prefix.
 */
export const dynamic = "force-static";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: SITE.name,
    short_name: SITE.name,
    description: SITE.tagline,
    start_url: asset("/"),
    scope: asset("/"),
    display: "standalone",
    background_color: "#0b0e13",
    theme_color: "#0b0e13",
    icons: [
      { src: asset("/icon.svg"), type: "image/svg+xml", sizes: "any" },
      { src: asset("/icon-192.png"), type: "image/png", sizes: "192x192" },
      { src: asset("/icon-512.png"), type: "image/png", sizes: "512x512", purpose: "any" },
    ],
  };
}
