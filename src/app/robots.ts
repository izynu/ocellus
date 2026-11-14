import type { MetadataRoute } from "next";
import { SITE } from "@/lib/site";

/**
 * robots.txt. The sitemap line is the one that matters: it is also what the
 * SEO check looks for when this site is scanned by its own tool.
 *
 * `SITE.url` carries the base path, so the Pages build points at
 * /ocellus/sitemap.xml. The `host` directive names the origin only.
 */
export const dynamic = "force-static";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", allow: "/" }],
    sitemap: `${SITE.url}/sitemap.xml`,
    host: SITE.origin,
  };
}
