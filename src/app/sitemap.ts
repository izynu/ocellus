import type { MetadataRoute } from "next";
import { SITE, ROUTES, LEGAL_ROUTES } from "@/lib/site";

/**
 * The sitemap is generated from the route table, so a new page cannot be
 * published without appearing here. Static export writes this to sitemap.xml.
 *
 * `SITE.url` already carries the base path, so the Pages build lists
 * /ocellus/... rather than the bare origin.
 */
export const dynamic = "force-static";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = SITE.url.replace(/\/$/, "");
  const now = new Date();
  const all = [...ROUTES, ...LEGAL_ROUTES];
  return all.map((route) => ({
    url: `${base}${route.href === "/" ? "" : route.href}/`,
    lastModified: now,
    changeFrequency: route.href === "/" ? "weekly" : "monthly",
    priority: route.href === "/" ? 1 : route.href === "/scan" ? 0.9 : 0.6,
  }));
}
