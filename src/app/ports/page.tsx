import { SiteShell } from "@/components/site/site-shell";
import { NmapConsole } from "@/components/recon/nmap-console";
import { pageMeta } from "@/lib/site";

/**
 * The Nmap page.
 *
 * The browser reads what a public index observed and writes the nmap command
 * that answers the same question for real. It is the "nmapAutomator" surface the
 * project asked for, made honest: a scan runs on your machine, not in a tab.
 */

export const metadata = pageMeta({
  title: "Nmap and port scan",
  description:
    "Read the ports Shodan observed on an address, and generate the exact nmap and nmapAutomator commands to scan it yourself, from host discovery to a full TCP sweep and vulnerability scripts.",
  path: "/ports",
});

export default function PortsPage() {
  return (
    <SiteShell>
      <div className="container-page">
        <header className="rise pt-14 pb-2 md:pt-20">
          <p className="eyebrow">Ports and services</p>
          <h1 className="mt-4" style={{ maxWidth: "24ch" }}>
            Ports an index has seen, and the nmap command that finds the rest.
          </h1>
          <p className="mt-5" style={{ fontSize: "1.02em", maxWidth: "66ch", color: "var(--muted-foreground)" }}>
            A browser cannot send a SYN packet, so a live port scan has to run on your own machine. This
            page reads the ports Shodan already recorded for an address, then writes the command that
            scans it for real.
          </p>
        </header>

        <section className="section-tight">
          <NmapConsole />
        </section>
      </div>
    </SiteShell>
  );
}
