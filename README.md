<div align="center">

<img src=".github/assets/hero.svg" alt="Ocellus: a browser-side audit of what a hostname exposes" width="100%">

**[izynu.github.io/ocellus](https://izynu.github.io/ocellus/)** &nbsp;·&nbsp; [Scan](https://izynu.github.io/ocellus/scan/) &nbsp;·&nbsp; [Checks](https://izynu.github.io/ocellus/checks/) &nbsp;·&nbsp; [Method](https://izynu.github.io/ocellus/method/)

<a href="https://github.com/izynu/ocellus/blob/main/LICENSE"><img src="https://img.shields.io/badge/licence-MIT-4fd1c5?style=flat-square" alt="Licence: MIT"></a>
<img src="https://img.shields.io/badge/checks-32-4fd1c5?style=flat-square" alt="32 checks">
<img src="https://img.shields.io/badge/groups-12-4fd1c5?style=flat-square" alt="12 groups">
<img src="https://img.shields.io/badge/sources-no%20API%20key-4fd1c5?style=flat-square" alt="No API key required">
<img src="https://img.shields.io/badge/runs-in%20your%20browser-4fd1c5?style=flat-square" alt="Runs in your browser">

</div>

Ocellus reads a website the way a careful visitor would. It asks the domain what it publishes, asks the certificate logs what was issued, asks the server what it admits in its response headers, and reads the page to see how it is built and what it loads. Then it shows the answer, the evidence behind the answer, and what it could not determine.

It runs entirely in your browser. There is no server, no account, no API key, and no database. Every value in a report came from a public source that your browser queried directly.

<img src=".github/assets/pipeline.svg" alt="Your browser queries public sources, the checks resolve one at a time, and the report shows what passed, what failed and what could not run" width="100%">

## Contents

- [What it checks](#what-it-checks)
- [How the score works](#how-the-score-works)
- [Where the data comes from](#where-the-data-comes-from)
- [Reconnaissance](#reconnaissance)
- [Using it](#using-it)
- [Run it locally](#run-it-locally)
- [Deploy](#deploy)
- [What it does not do](#what-it-does-not-do)
- [Keywords](#keywords)
- [Licence](#licence)

---

## What it checks

A scan runs **32 fixed checks across 12 groups**. Each check answers a single question about the target and reports what it measured, with the source that answered.

| Group | Checks | What the group determines |
| --- | :--: | --- |
| **Transport and certificates** | 3 | Which certificates have been issued for the domain, by which authorities, for which hostnames, how long each lasts, which of them were revoked, and every hop between the address you typed and the page that answered |
| **Name system** | 6 | Every address, mail, name-server and text record the zone publishes, when the registration began and expires, whether a wildcard answers for names nobody registered, whether DNSSEC is in place, which alias a host points at, and which network each nameserver sits on |
| **Response headers** | 3 | Whether the server sends the headers that tell a browser how to behave, how strong each one is, whether the site publishes a current security contact, and which CDN, proxy or web application firewall answered in front of the origin |
| **Email** | 1 | Whether SPF, DKIM and DMARC exist, whether they actually prevent forgery, and whether MTA-STS is announced |
| **Infrastructure** | 5 | Where the site is hosted, who announces the address, what Shodan has observed listening on it, which other hostnames share that address, and whether the software the response names appears in the catalogue of vulnerabilities known to be exploited |
| **Reconnaissance** | 2 | Which hostnames passive DNS has recorded under the domain, who the address belongs to, what else shares it, its reverse name, and what a public URL scanner has captured at this address |
| **Privacy** | 1 | Which cookies are set before consent, which trackers load, and what third parties the page contacts |
| **Content and accessibility** | 1 | Heading structure, alt text, form labels, duplicate ids, tab order, and the language declaration |
| **Performance** | 2 | Render-blocking resources, compression, caching, image dimensions, DOM size, and an estimate of the carbon cost of one page view |
| **Search and preview** | 1 | Crawl directives, canonical, sitemap, and whether a shared link renders as a card |
| **Reputation** | 6 | Whether the domain appears in threat intelligence, whether a malware or phishing feed currently lists it, whether a filtering resolver refuses to resolve it, how widely it is seen in traffic, how long it has existed in public, and whether the operator has appeared in a disclosed breach |
| **Interface friction** | 1 | Pre-checked consent boxes, confirmshaming copy, forced actions, and scarcity pressure |

A check that cannot run is reported as **unavailable** with the reason. It is removed from the score's denominator rather than counted as a pass. A site that blocks the scanner does not get a good grade for it.

---

## How the score works

Every check carries a weight of 1, 2 or 3 according to what it protects. Context checks carry the least, material checks more, and structural checks the most. Each status earns part of that weight:

| Status | Fraction of the weight | Meaning |
| --- | :--: | --- |
| `pass` | 1.00 | The source answered and the rule was met |
| `info` | 0.85 | An observation, not a judgement |
| `warn` | 0.55 | Worth fixing, not severe on its own |
| `fail` | 0.10 | The rule was broken |
| `unavailable` | removed | The source could not be reached, so no verdict is claimed |
| `skipped` | removed | The check does not apply to this target |

The score is the weighted mean over the checks that returned a verdict. Grades follow fixed bands: **A** at 90 or above, **B** at 78, **C** at 64, **D** at 50, **E** at 32, and **F** below 32. There are no curves, no per-site adjustments and no hidden bonuses. The [method page](https://izynu.github.io/ocellus/method/) reproduces the arithmetic in full.

---

## Where the data comes from

No source requires a key. Each is queried from the visitor's browser, and each request starts and ends there.

| Source | Used for |
| --- | --- |
| [Google Public DNS](https://dns.google) and [Cloudflare](https://cloudflare-dns.com) over DNS-over-HTTPS | Every DNS record, including DNSSEC |
| [Cloudflare security resolver](https://security.cloudflare-dns.com) | Whether a filtering resolver refuses to resolve the domain |
| [crt.sh](https://crt.sh) Certificate Transparency index | Issued certificates and the subdomain surface |
| [Cert Spotter](https://sslmate.com/certspotter/) | A second certificate index, and which certificates were revoked |
| [rdap.org](https://rdap.org) | Registration date, expiry, registrar and registry status |
| [Wayback Machine](https://web.archive.org) | How long the address has been captured in public |
| [Tranco](https://tranco-list.eu) | Where the domain sits in a public traffic ranking |
| [Shodan InternetDB](https://internetdb.shodan.io) | Open ports and known CVEs for the resolved address |
| [ipwho.is](https://ipwho.is) | Geolocation and autonomous system |
| [AlienVault OTX](https://otx.alienvault.com) | Threat intelligence pulses, and passive DNS for the resolved address |
| [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search), [NetAPI](https://netapi.com/compromised-urls/) and [OpenPhish](https://openphish.com/) | Whether a malware or phishing feed currently lists the site, and how many feeds actually answered |
| [Have I Been Pwned](https://haveibeenpwned.com) | Whether the operator has appeared in a disclosed breach |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/) | Whether the software the server names is known to be exploited, and how likely |
| [api.hackertarget.com](https://api.hackertarget.com) | Raw response headers, the redirect chain, reverse DNS, reverse IP and host search |
| [api.subdomain.center](https://api.subdomain.center) | Passive DNS hostnames under the domain |
| [urlscan.io](https://urlscan.io) | Prior public scans of the URL, with the title and server each one recorded |
| [r.jina.ai](https://r.jina.ai) | The document itself, because most sites send no CORS header. A site that does permit a cross-origin read is fetched directly instead, so its bytes and element tree are its own |
| [Website Carbon](https://www.websitecarbon.com) | An estimate of the carbon cost of one page view, as context rather than a verdict |
| [RIPEstat](https://stat.ripe.net) | Which network announces each nameserver's address, and whether DNS is hosted separately from the site |

Two upstreams are read through the reader service because they send no CORS header of their own: `api.subdomain.center` and `urlscan.io`. The report names the source next to every check, so a value can always be traced back to the service that supplied it.

---

## Reconnaissance

The reconnaissance group covers the passive half of a recon workflow: what can be learned about a host without touching it in a way it would notice.

- **Subdomain enumeration.** Hostnames under the domain from passive DNS, merged across two indexes, with any name that looks internal called out because a hostname that only appears in passive DNS is often one nobody wrote down.
- **URL and address lookups.** Reverse DNS for the host, the address it resolves to, the other hostnames recorded there, and prior public scans of the URL from urlscan.io.

Active steps, which send packets or thousands of requests from one address, are not part of the browser scan and are named as such in the report and on the method page. A static page cannot open a socket, and a tool that implied it had would be describing software that does not exist.

---

## Using it

Open [izynu.github.io/ocellus](https://izynu.github.io/ocellus/), type a domain or a full address, and start the scan. There is nothing to install and nothing to sign in to.

The checks resolve one at a time, so you watch each result arrive rather than waiting on a spinner. When the report appears, every check is listed in report order with its status, the value it measured, and the evidence behind it. Checks that could not run are kept in the list, marked unavailable, with the reason.

You can link straight to a scan with `?url=` in the address, print the report, or download it as JSON. Nothing is stored beyond your own browser tab.

---

## Run it locally

Requires Node.js 22, the version the deployment workflow uses.

```bash
git clone https://github.com/izynu/ocellus.git
cd ocellus
npm install
npm run dev
```

Open `http://localhost:3000`. No environment variables are needed for local development.

| Script | What it does |
| --- | --- |
| `npm run dev` | Start the development server |
| `npm run build` | Build a production export to `out/` |
| `npm run build:cpanel` | Build the document-root target into `dist/cpanel/` |
| `npm run build:pages` | Build the GitHub Pages target into `dist/pages/` |
| `npm run build:all` | Build both targets and write `dist/build.json` |
| `npm run start` | Serve an existing `out/` directory |
| `npm run lint` | Run ESLint over the tree |
| `npm run typecheck` | Run the TypeScript compiler with no emit |

---

## Deploy

Ocellus is a static export with no server component. There are two deployables, and they differ only in `basePath`, which Next.js has to bake in at build time:

- **cPanel or any document root.** `npm run build:cpanel`. Upload the contents of `dist/cpanel/` to `public_html`. The build writes an `.htaccess` with the security headers the scanner itself grades, so the site can be scanned by its own tool and come out clean. A runbook is in [`docs/cpanel-deploy.html`](docs/cpanel-deploy.html).
- **GitHub Pages project site.** `npm run build:pages`. Every asset is prefixed with the repository name, and a `.nojekyll` file is written so the `_next/` directory is served. The workflow in `.github/workflows/deploy.yml` runs this on every push to `main`.

Set `NEXT_PUBLIC_SITE_URL` to the canonical origin before either build if the deployment is not on the default domain.

---

## What it does not do

A clean report is not a security assessment, and the report says so. Specifically:

- **It does not render the page.** There is no layout engine and no script execution, so it cannot compute colour contrast ratios, measure Core Web Vitals timings, or observe what a page does after load.
- **It does not test for exploits.** A finding describes a configuration or a missing control, not a working attack.
- **It does not log in, submit a form, or crawl.** One document is fetched, not a site.
- **It does not run active scans.** No port scan, no fuzzing, no brute force. The port list comes from a third-party index that observed the address at some earlier time.
- **It does not decide whether a site is secure.** It reports what public sources say about one hostname at one moment, and the report shows where each value came from.

These limits are stated on the [method page](https://izynu.github.io/ocellus/method/) and inside the report itself, because a tool that hides them is worse than one that has them.

---

## Keywords

DNS records, DNSSEC, CAA, MX, SPF, DKIM, DMARC, MTA-STS, TLS reporting, certificate transparency, certificate revocation, security headers, Content-Security-Policy, HSTS, security.txt, passive DNS, subdomain enumeration, reverse DNS, reverse IP, URL scanning, threat intelligence, CISA KEV, EPSS, malware and phishing listings, domain reputation, breach history, privacy, cookies, trackers, accessibility, WCAG, dark patterns, interface friction, SEO, crawlability, page weight, carbon estimate.

---

## Licence

MIT. See [LICENSE](LICENSE).

<div align="center">
<sub>Built and maintained by <a href="https://zynu.me">Zynu</a>.</sub>
</div>
