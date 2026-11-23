/**
 * The wider scanner landscape, and where Ocellus sits in it.
 *
 * This is a reference page's data. A person who opens the scanner coverage page
 * wants two things: to know which well-known tools exist for a given question,
 * and to know which of them Ocellus can answer itself. Listing a tool without
 * saying whether Ocellus covers it would be a directory; the column that says
 * "in-browser" or "needs a terminal" is what makes the page honest.
 *
 * A tool is marked `native` when Ocellus runs the same kind of query from the
 * browser with no install. A tool is marked `reference` when it needs a binary,
 * an API key the visitor has to hold, or network access a page cannot make; the
 * page names those so the reader knows the gap is real and where to go for it.
 *
 * Nothing here is a claim that Ocellus replaces these tools. Several of them do
 * things a static page cannot, and the note on each row says so.
 */

import type { ToolCoverage } from "../types";

export type ToolEntry = {
  name: string;
  /** What the tool answers, in one line. */
  purpose: string;
  /** The home page, repository or documentation. */
  url: string;
  /** Free-text licence or cost note, kept short. */
  cost: string;
  /**
   * How Ocellus relates to it. `native` means the same question is answered in
   * the browser by a check in this product; `reference` means it is listed
   * because the question matters and Ocellus does not answer it.
   */
  coverage: ToolCoverage;
  /** The check that covers it, when coverage is `native`. */
  checkId?: string;
  /** What a static page cannot do that this tool can. */
  gap?: string;
};

export const TOOL_CATEGORIES = [
  {
    key: "address",
    label: "Who is this IP",
    note: "Address ownership, network and reverse name. The question every scan starts with.",
  },
  {
    key: "subdomains",
    label: "Subdomain enumeration",
    note: "Finding hostnames under a domain from public records before touching the target.",
  },
  {
    key: "ports",
    label: "Ports and services",
    note: "What is listening on an address, and whether it should be.",
  },
  {
    key: "url",
    label: "URL and malware scanning",
    note: "Whether a site or URL is currently listed as malicious, phishing or compromised.",
  },
  {
    key: "tls",
    label: "TLS and certificates",
    note: "Which certificates exist, whether they are valid, and what they name.",
  },
  {
    key: "headers",
    label: "Headers and configuration",
    note: "Whether the server sends the headers that protect a visitor, and how strong each is.",
  },
  {
    key: "dns",
    label: "DNS and mail",
    note: "The records a zone publishes, and whether mail from it can be forged.",
  },
  {
    key: "reputation",
    label: "Reputation and history",
    note: "How the domain has behaved over time and how widely it is seen.",
  },
] as const;

export type ToolCategoryKey = (typeof TOOL_CATEGORIES)[number]["key"];

/** Tools with the category they answer, in the order a scan would use them. */
export const TOOLS: Array<ToolEntry & { category: ToolCategoryKey }> = [
  // --- address ---
  {
    category: "address",
    name: "ipwho.is",
    purpose: "Geolocation and autonomous system for an address, as JSON.",
    url: "https://ipwho.is/",
    cost: "Free, keyless",
    coverage: "native",
    checkId: "infrastructure",
  },
  {
    category: "address",
    name: "RIPEstat",
    purpose: "Which network announces an address, from the RIR statistics.",
    url: "https://stat.ripe.net/",
    cost: "Free, keyless",
    coverage: "native",
    checkId: "nameservers",
  },
  {
    category: "address",
    name: "bgp.he.net",
    purpose: "Hurricane Electric's BGP and ASN browser.",
    url: "https://bgp.he.net/",
    cost: "Free, web",
    coverage: "native",
    checkId: "infrastructure",
    gap: "Ocellus reads the ASN from a geolocation API; Hurricane Electric also shows announced prefixes and peers.",
  },
  {
    category: "address",
    name: "HackerTarget geoIP",
    purpose: "Address to country, city and coordinates, as plain text.",
    url: "https://hackertarget.com/geoip-lookup/",
    cost: "Free, keyless, rate limited",
    coverage: "native",
    checkId: "infrastructure",
  },
  {
    category: "address",
    name: "whois",
    purpose: "The command-line registration client.",
    url: "https://www.rfc-editor.org/rfc/rfc3912.html",
    cost: "Built in to most systems",
    coverage: "reference",
    gap: "A page cannot open a WHOIS socket; Ocellus reads the same record over RDAP instead.",
  },

  // --- subdomains ---
  {
    category: "subdomains",
    name: "crt.sh",
    purpose: "Certificate Transparency search, including subdomain names.",
    url: "https://crt.sh/",
    cost: "Free, keyless",
    coverage: "native",
    checkId: "subdomains",
  },
  {
    category: "subdomains",
    name: "subfinder",
    purpose: "Passive subdomain enumeration from dozens of sources.",
    url: "https://github.com/projectdiscovery/subfinder",
    cost: "Free, open source",
    coverage: "reference",
    gap: "Needs a binary and API keys; Ocellus reads only the CORS-open indexes a page can reach.",
  },
  {
    category: "subdomains",
    name: "amass",
    purpose: "OWASP's deep OSINT and active enumeration engine.",
    url: "https://github.com/owasp-amass/amass",
    cost: "Free, open source",
    coverage: "reference",
    gap: "Runs active DNS and scraping that a browser page cannot perform.",
  },
  {
    category: "subdomains",
    name: "assetfinder",
    purpose: "Fast related-domain and subdomain lookups.",
    url: "https://github.com/tomnomnom/assetfinder",
    cost: "Free, open source",
    coverage: "reference",
    gap: "Aggregates sources that need direct API access.",
  },
  {
    category: "subdomains",
    name: "dnsx",
    purpose: "Bulk DNS resolution and probing of a hostname list.",
    url: "https://github.com/projectdiscovery/dnsx",
    cost: "Free, open source",
    coverage: "reference",
    gap: "Resolves thousands of names over raw DNS; a page is limited to DoH lookups.",
  },
  {
    category: "subdomains",
    name: "HackerTarget host search",
    purpose: "Hostnames seen for a domain, as CSV over HTTP.",
    url: "https://hackertarget.com/find-dns-host-records/",
    cost: "Free, keyless, rate limited",
    coverage: "native",
    checkId: "subdomains",
  },

  // --- ports ---
  {
    category: "ports",
    name: "Shodan InternetDB",
    purpose: "Open ports and known CVEs for an address, free and keyless.",
    url: "https://internetdb.shodan.io/",
    cost: "Free, keyless",
    coverage: "native",
    checkId: "infrastructure",
  },
  {
    category: "ports",
    name: "Shodan",
    purpose: "The full search engine for internet-connected devices.",
    url: "https://www.shodan.io/",
    cost: "Paid tiers, API key",
    coverage: "reference",
    gap: "InternetDB is the free index subset; full Shodan search needs a key.",
  },
  {
    category: "ports",
    name: "nmap",
    purpose: "Active port and service scan from your own host.",
    url: "https://nmap.org/",
    cost: "Free, open source",
    coverage: "reference",
    gap: "Sends packets from your machine; a page cannot open arbitrary sockets.",
  },
  {
    category: "ports",
    name: "naabu",
    purpose: "Fast port scanner built for recon pipelines.",
    url: "https://github.com/projectdiscovery/naabu",
    cost: "Free, open source",
    coverage: "reference",
    gap: "Same constraint: active scanning is not something a browser can do.",
  },
  {
    category: "ports",
    name: "masscan",
    purpose: "Internet-scale port scanning.",
    url: "https://github.com/robertdavidgraham/masscan",
    cost: "Free, open source",
    coverage: "reference",
    gap: "Designed for raw-socket scanning at scale.",
  },

  // --- url ---
  {
    category: "url",
    name: "Google Safe Browsing",
    purpose: "Google's malware and phishing verdict for a URL.",
    url: "https://transparencyreport.google.com/safe-browsing/search",
    cost: "Free, keyless via transparency report",
    coverage: "native",
    checkId: "malware-listings",
  },
  {
    category: "url",
    name: "VirusTotal",
    purpose: "A file or URL checked against dozens of engines at once.",
    url: "https://www.virustotal.com/",
    cost: "Free tier, API key",
    coverage: "reference",
    gap: "The API needs a key; Ocellus reads the keyless feeds instead.",
  },
  {
    category: "url",
    name: "URLhaus",
    purpose: "abuse.ch's database of malware distribution URLs.",
    url: "https://urlhaus.abuse.ch/",
    cost: "Free, keyless bulk download",
    coverage: "native",
    checkId: "malware-listings",
  },
  {
    category: "url",
    name: "OpenPhish",
    purpose: "A live feed of active phishing URLs.",
    url: "https://openphish.com/",
    cost: "Free, keyless",
    coverage: "native",
    checkId: "malware-listings",
  },
  {
    category: "url",
    name: "PhishTank",
    purpose: "Community-submitted phishing URLs with a verification state.",
    url: "https://phishtank.org/",
    cost: "Free, registration for API",
    coverage: "reference",
    gap: "The bulk API needs an account; the public feed is not CORS-open.",
  },
  {
    category: "url",
    name: "urlscan.io",
    purpose: "A rendered snapshot of a URL with the requests it made.",
    url: "https://urlscan.io/",
    cost: "Free public scans, API key for submission",
    coverage: "reference",
    gap: "Submitting a scan needs an API key; Ocellus reports what its own fetch saw.",
  },
  {
    category: "url",
    name: "NetAPI compromised feed",
    purpose: "Whether a domain appears in a compromised-site list.",
    url: "https://netapi.com/compromised-urls/",
    cost: "Free, keyless",
    coverage: "native",
    checkId: "malware-listings",
  },

  // --- tls ---
  {
    category: "tls",
    name: "Cert Spotter",
    purpose: "A certificate index with revocation status.",
    url: "https://sslmate.com/certspotter/",
    cost: "Free tier, keyless",
    coverage: "native",
    checkId: "certificate-revocation",
  },
  {
    category: "tls",
    name: "SSL Labs",
    purpose: "A deep TLS configuration grade and protocol audit.",
    url: "https://www.ssllabs.com/ssltest/",
    cost: "Free, rate limited",
    coverage: "reference",
    gap: "Needs a live handshake from a scanning host; a page cannot negotiate TLS to a third party.",
  },
  {
    category: "tls",
    name: "testssl.sh",
    purpose: "Command-line TLS testing with every cipher and vulnerability probe.",
    url: "https://testssl.sh/",
    cost: "Free, open source",
    coverage: "reference",
    gap: "Opens TLS connections directly, which a page is not permitted to do.",
  },

  // --- headers ---
  {
    category: "headers",
    name: "Security Headers",
    purpose: "A grade for the response headers a site sends.",
    url: "https://securityheaders.com/",
    cost: "Free",
    coverage: "native",
    checkId: "security-headers",
  },
  {
    category: "headers",
    name: "Mozilla Observatory",
    purpose: "A security grade covering headers, TLS, cookies and more.",
    url: "https://developer.mozilla.org/en-US/observatory",
    cost: "Free, API key for automation",
    coverage: "native",
    checkId: "security-headers",
    gap: "Observatory also scans TLS and cookies server-side; Ocellus grades headers and reads cookies statically.",
  },
  {
    category: "headers",
    name: "CSP Evaluator",
    purpose: "A line-by-line judgement of a Content-Security-Policy.",
    url: "https://csp-evaluator.withgoogle.com/",
    cost: "Free, web",
    coverage: "native",
    checkId: "security-headers",
  },

  // --- dns ---
  {
    category: "dns",
    name: "Google Public DNS",
    purpose: "DNS over HTTPS resolver.",
    url: "https://dns.google/",
    cost: "Free, keyless",
    coverage: "native",
    checkId: "dns-records",
  },
  {
    category: "dns",
    name: "MXToolbox",
    purpose: "Mail, DNS and blacklist diagnostics in one place.",
    url: "https://mxtoolbox.com/",
    cost: "Free, web",
    coverage: "native",
    checkId: "email-auth",
    gap: "Ocellus covers SPF, DKIM, DMARC and MTA-STS; MXToolbox also probes live SMTP.",
  },
  {
    category: "dns",
    name: "DNSViz",
    purpose: "A visual DNSSEC validation and chain-of-trust report.",
    url: "https://dnsviz.net/",
    cost: "Free, web",
    coverage: "native",
    checkId: "dnssec",
  },
  {
    category: "dns",
    name: "dnsdumpster",
    purpose: "DNS recon and hostname mapping for a domain.",
    url: "https://dnsdumpster.com/",
    cost: "Free, web",
    coverage: "native",
    checkId: "subdomains",
  },

  // --- reputation ---
  {
    category: "reputation",
    name: "AlienVault OTX",
    purpose: "Threat intelligence pulses and passive DNS for a domain or address.",
    url: "https://otx.alienvault.com/",
    cost: "Free, keyless",
    coverage: "native",
    checkId: "threat-intel",
  },
  {
    category: "reputation",
    name: "Have I Been Pwned",
    purpose: "Whether an operator or address appears in a disclosed breach.",
    url: "https://haveibeenpwned.com/",
    cost: "Free, keyless for breaches",
    coverage: "native",
    checkId: "breach-history",
  },
  {
    category: "reputation",
    name: "Wayback Machine",
    purpose: "The public archive of a site's past.",
    url: "https://web.archive.org/",
    cost: "Free, keyless",
    coverage: "native",
    checkId: "archive-history",
  },
  {
    category: "reputation",
    name: "Tranco",
    purpose: "A research ranking of the most-visited domains.",
    url: "https://tranco-list.eu/",
    cost: "Free, keyless",
    coverage: "native",
    checkId: "popularity",
  },
  {
    category: "reputation",
    name: "VirusTotal reputation",
    purpose: "Domain reputation and passive DNS across many engines.",
    url: "https://www.virustotal.com/gui/home/search",
    cost: "Free tier, API key",
    coverage: "reference",
    gap: "The reputation API needs a key; Ocellus reads keyless reputation sources.",
  },
];

/** How many tools Ocellus runs natively, per category. */
export function nativeCount(category: ToolCategoryKey): number {
  return TOOLS.filter((tool) => tool.category === category && tool.coverage === "native").length;
}
