import { SiteShell } from "@/components/site/site-shell";
import { ScanWorkspace } from "@/components/scan/scan-workspace";
import { checks } from "@/lib/checks";
import { SITE, pageMeta } from "@/lib/site";

export const metadata = pageMeta({
  title: "Scan",
  // The count comes from the registry, not a literal. This was the one page
  // that hardcoded "Sixteen" and would have gone quietly stale on the next
  // check added.
  description: `Run ${SITE.name} against any public address. ${checks.length} checks across DNS, certificates, headers, email, privacy, accessibility and reputation, run in your browser with no upload and no account.`,
  path: "/scan",
});

export default function ScanPage() {
  return (
    <SiteShell>
      <ScanWorkspace />
    </SiteShell>
  );
}
