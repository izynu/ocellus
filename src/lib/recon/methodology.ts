/**
 * The reconnaissance workflow, and which steps a browser can run.
 *
 * The shape of the workflow is the one the bug-bounty community has converged
 * on: learn the address space, then the hostnames, then fingerprint what
 * answers, then look at the content, the parameters and finally the software.
 * That sequence is a published methodology, not something invented here; the
 * `source` on each phase points at where it comes from.
 *
 * The column that matters is `inBrowser`. A static page can query public
 * indexes that send CORS headers, and nothing else. It cannot open a DNS
 * socket, send a SYN, or run a binary. So the recon page separates the phases a
 * scan can perform from the ones that need a terminal, and names the tool for
 * each terminal step rather than implying the tool does it. A page that listed
 * every step as if the product completed it would be describing software that
 * does not exist.
 *
 * What Ocellus does run itself lives in `src/lib/checks`, and each phase below
 * names the checks that carry it out, so the two views cannot drift apart in a
 * way a reader would notice.
 */

import type { ReconPhase } from "../types";

export const RECON_PHASES: ReconPhase[] = [
  {
    id: "asn",
    title: "Address space and networks",
    question: "Which networks belong to this organisation, and where does this host sit inside them?",
    inBrowser: true,
    checks: ["infrastructure", "nameservers", "cohosted"],
    tools: ["whois", "bgp.he.net", "RIPEstat"],
    body: "Start from the address behind the hostname, then climb to the autonomous system that announces it. An ASN turns one host into a range of addresses, and the range is where the forgotten hosts live. Ocellus reports the address, the ASN and its organisation, the nameserver networks and what else shares the address. It does not enumerate a whole ASN, which needs a scanner that sends packets.",
    source: "HowToHunt recon workflow: IP space discovery, ASN discovery",
    sourceUrl: "https://kathan19.gitbook.io/howtohunt/recon/workflow",
  },
  {
    id: "subdomains",
    title: "Subdomain enumeration",
    question: "Which hostnames under the domain exist, and how many of them are reachable?",
    inBrowser: true,
    checks: ["subdomains"],
    tools: ["crt.sh", "subfinder", "amass", "assetfinder", "dnsx"],
    body: "Passive first, from certificate transparency and the page's own links, because those records name hosts without touching the target. A browser can reach the CORS-open indexes and nothing else, so Ocellus reports what CT logs and the linked document name, and says that a certificate list is a lower bound. Active brute force, permutation and bulk resolution need a tool that can issue thousands of DNS queries, which a page cannot.",
    source: "HowToHunt subdomain enumeration: passive, active, permutation",
    sourceUrl: "https://kathan19.gitbook.io/howtohunt/recon/subdomain_enumeration",
  },
  {
    id: "fingerprint",
    title: "Fingerprinting",
    question: "What software answers, and which of it is worth reading a version for?",
    inBrowser: true,
    checks: ["tech-stack", "edge-protection", "security-headers", "vulnerability-exposure"],
    tools: ["httpx", "wappalyzer", "CISA KEV"],
    body: "A response names its server, its framework and often its version. Fingerprinting is the step that turns a hostname into a software inventory. Ocellus reads the headers, the markup and the response body for signatures, then joins the named product against the catalogue of vulnerabilities known to be exploited. The join is on product name, not version, so it narrows what to read rather than replacing a version audit.",
    source: "HowToHunt recon workflow: fingerprinting",
    sourceUrl: "https://kathan19.gitbook.io/howtohunt/recon/workflow",
  },
  {
    id: "dorking",
    title: "Search-engine discovery",
    question: "What has the search engine already indexed that the site did not mean to publish?",
    inBrowser: true,
    checks: [],
    tools: ["Google dorks", "Bing", "DuckDuckGo"],
    body: "A dork is a query built from operators, and it surfaces files, admin panels and debug output that are reachable and indexed. Ocellus does not run dorks itself, because search engines forbid automated querying without a key. Instead the dork page generates the query for the target and opens it in your browser, so the engine sees you, not this site. Nothing on that page is sent anywhere by Ocellus.",
    source: "pentest.bd dork list",
    sourceUrl: "https://pentest.bd/dorks/",
  },
  {
    id: "content",
    title: "Content and parameter discovery",
    question: "Which paths, files and parameters exist beyond the page that was linked?",
    inBrowser: false,
    checks: [],
    tools: ["ffuf", "feroxbuster", "gobuster", "dirsearch", "arjun"],
    body: "Content discovery fuzzes a wordlist against the host to find paths the site never linked. Parameter discovery does the same for query keys. Both send hundreds or thousands of requests to the target from one address, which is exactly the traffic a static page cannot generate and, on a third party, should not. This step is listed because the workflow is incomplete without it, and it is marked as terminal-only because that is what it is.",
    source: "HowToHunt recon workflow: content discovery, parameter discovery",
    sourceUrl: "https://kathan19.gitbook.io/howtohunt/recon/workflow",
  },
  {
    id: "ports",
    title: "Ports and services",
    question: "What is listening on the address, and does any of it belong on the internet?",
    inBrowser: false,
    checks: ["infrastructure"],
    tools: ["nmap", "naabu", "masscan", "Shodan InternetDB"],
    body: "Ocellus reads the ports Shodan's free index has observed, which is a record of an earlier crawl rather than a scan of the host now. A live port scan is listed here as a terminal step because a page cannot open a socket. The internetdb result is still worth reading: a database port that was open when Shodan last looked is a question to answer, not a proof it is open today.",
    source: "HowToHunt subdomain enumeration: port scanning phase",
    sourceUrl: "https://kathan19.gitbook.io/howtohunt/recon/subdomain_enumeration",
  },
  {
    id: "tls",
    title: "Certificates and transport",
    question: "Which certificates exist for these names, and is any revoked, shared or long-lived?",
    inBrowser: true,
    checks: ["ct-logs", "certificate-revocation", "redirects"],
    tools: ["crt.sh", "Cert Spotter", "SSL Labs", "testssl.sh"],
    body: "Certificate transparency is public, so every certificate ever issued for a name can be read without touching the target. Ocellus reads the issued set, the issuers, revocation and the validity windows. A full TLS handshake audit, which tests every cipher and protocol version, needs a host that can negotiate with the target, so that part is terminal-only.",
    source: "HowToHunt recon workflow, transport implied by fingerprinting",
    sourceUrl: "https://kathan19.gitbook.io/howtohunt/recon/workflow",
  },
  {
    id: "reputation",
    title: "Reputation and history",
    question: "Is this address currently listed, and how has the domain behaved over time?",
    inBrowser: true,
    checks: ["threat-intel", "malware-listings", "blocklist", "breach-history", "archive-history", "popularity"],
    tools: ["VirusTotal", "URLhaus", "OpenPhish", "Wayback Machine", "Have I Been Pwned"],
    body: "Before trusting a host, read what public feeds say about it and how long it has existed. Ocellus asks the keyless feeds, reports how many answered so a partial answer is never presented as a full one, and keeps a failed source separate from a clean result. VirusTotal's multi-engine verdict needs a key, so it is listed as a reference rather than run.",
    source: "Recon workflow, reputation read before content",
    sourceUrl: "https://kathan19.gitbook.io/howtohunt/recon/workflow",
  },
];

/** How many phases a browser can run, for the recon page's summary. */
export function browserPhaseCount(): number {
  return RECON_PHASES.filter((phase) => phase.inBrowser).length;
}
