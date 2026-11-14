import { SiteShell } from "@/components/site/site-shell";
import { ScanWorkspace } from "@/components/scan/scan-workspace";
import { SITE, asset } from "@/lib/site";

export const metadata = {
  title: "Scan",
  description: `Run ${SITE.name} against any public address. Sixteen checks across DNS, certificates, headers, email, privacy, accessibility and reputation, run in your browser with no upload and no account.`,
  alternates: { canonical: asset("/scan") },
};

export default function ScanPage() {
  return (
    <SiteShell>
      <ScanWorkspace />
    </SiteShell>
  );
}
