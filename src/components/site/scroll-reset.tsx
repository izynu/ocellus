"use client";

/**
 * Reset the scroll position when the route changes.
 *
 * Next's client-side navigation normally handles this, but a page with a sticky
 * header, a fixed background layer and a long footer can land scrolled to a
 * leftover offset, which reads as opening halfway down the page. This forces the
 * window to the top on every pathname change, except when the URL carries a hash
 * the reader explicitly asked for.
 *
 * It is client-only and renders nothing.
 */

import { usePathname } from "next/navigation";
import { useEffect } from "react";

export function ScrollReset() {
  const pathname = usePathname();

  useEffect(() => {
    if (typeof window === "undefined") return;
    // An explicit in-page anchor wins over the reset, so a table-of-contents
    // link still jumps where it says it will.
    if (window.location.hash) return;
    window.scrollTo({ top: 0, left: 0, behavior: "instant" as ScrollBehavior });
  }, [pathname]);

  return null;
}
