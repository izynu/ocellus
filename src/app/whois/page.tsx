import { SiteShell } from "@/components/site/site-shell";
import { HostLookup } from "@/components/recon/host-lookup";
import { pageMeta } from "@/lib/site";

/**
 * The host lookup page.
 *
 * The recon-first entry point: who owns the domain, when it was registered,
 * which nameservers answer, what the host resolves to, and which hostnames sit
 * under it. It runs a subset of the same registry checks the full scan runs.
 */

export const metadata = pageMeta({
  title: "Whois and host lookup",
  description:
    "Look up who owns a domain, when it was registered and expires, which nameservers and aliases it has, whether DNSSEC is in place, what the host resolves to, and which hostnames are recorded under it.",
  path: "/whois",
});

export default function WhoisPage() {
  return (
    <SiteShell>
      <div className="container-page">
        <header className="rise pt-12 pb-2 md:pt-16">
          <p className="eyebrow">Ownership and name</p>
          <h1 className="mt-3" style={{ maxWidth: "26ch" }}>
            Who is behind this host, and what does its name layer say?
          </h1>
          <p className="mt-5" style={{ fontSize: "1.02em", maxWidth: "66ch", color: "var(--muted-foreground)" }}>
            Ten lookups against the registration record and the name system: registrar and dates, the
            zone's records, aliases, nameservers, DNSSEC, the address, and the hostnames recorded
            underneath. Each one names the source that answered.
          </p>
        </header>

        <section className="section-tight">
          <HostLookup />
        </section>
      </div>
    </SiteShell>
  );
}
