/**
 * Dork templates, and the forms that are safe to generate.
 *
 * A dork is a search engine query built from operators rather than words. The
 * catalogue here is a reference: it lists the queries a person can run and lets
 * a visitor copy one and run it in their own browser, against the engine's own
 * index. Ocellus never runs a dork itself, because every engine's terms forbid
 * automated querying without an API key, and a report that claimed to have run
 * one would be describing a request nobody made.
 *
 * Each template is written with `{domain}`, `{host}` or `{origin}` where a
 * target value goes. Substitution is a plain string replace and nothing else:
 * no template interpolates a value into a regex, an HTML attribute, or a shell
 * string, so the worst a crafted hostname can do is produce a dork that finds
 * nothing.
 *
 * Six engines are represented. A template names only the engine whose
 * operators it uses: `site:`, `inurl:`, `intext:`, `intitle:` and `ext:` are
 * Google syntax, `cache:` and `filetype:` are Bing syntax, DuckDuckGo accepts
 * `site:` and `filetype:`, Shodan searches its own host index with
 * `hostname:`, `http.html:` and `http.title:`, GitHub code search uses
 * `path:`, `filename:` and a quoted phrase, and Censys searches certificates
 * with `parsed.names:`. A Google query is never relabelled as a Shodan one,
 * because the two index different things.
 *
 * Two rules constrain what is listed. A template must be a query an owner
 * running it against their own site would find useful, and it must be one whose
 * results are pages the site itself publishes. Nothing here is a login-bypass
 * payload, an injection string or anything that mutates a remote system. The
 * catalogue is the one a security team keeps for auditing its own surface.
 */

import type { DorkCategory } from "../types";

/** Values a template may interpolate. */
export type DorkVars = {
  domain: string;
  host: string;
  origin: string;
};

export type DorkEngine = "google" | "bing" | "duckduckgo" | "shodan" | "github" | "censys";

export type DorkTemplate = {
  /** Stable id, used as the React key and the copy target. */
  id: string;
  category: DorkCategory;
  /** One line, in the imperative: what querying this finds. */
  label: string;
  /** The query, with placeholders. */
  query: string;
  /** Where to run it. Only engines that support the operators in `query`. */
  engine: DorkEngine;
  /** Optional note shown under the query: what a hit means. */
  note?: string;
};

/**
 * Labels double as the display order. The order runs from what a hit proves
 * most directly to what it merely suggests, so the page opens on the categories
 * a reader should check first.
 */
export const DORK_CATEGORY_LABEL: Record<DorkCategory, string> = {
  exposure: "Exposed files and documents",
  leaks: "Secrets and pastes",
  cloud: "Object storage and cloud",
  api: "Interfaces and API surface",
  login: "Sign-in and admin surfaces",
  error: "Errors and debug output",
  code: "Code and repositories",
  docs: "Documents and published pages",
  content: "Indexable content",
  infra: "Infrastructure and third parties",
};

export const DORK_CATEGORY_NOTE: Record<DorkCategory, string> = {
  exposure:
    "Files a site did not mean to publish. A hit is a document that is reachable, indexable and readable without authentication.",
  leaks:
    "Code and credentials that have left the site: a paste, a committed config, a public bucket. A hit is the most serious kind of finding.",
  cloud:
    "Object storage, CDN origins and hosted data that name the domain. A hit is a bucket or dataset whose access rule should be confirmed.",
  api:
    "Specifications, consoles and endpoints the site publishes. A hit is an interface that documents more than its owner intends to expose.",
  login:
    "Entry points that are meant to be found by staff and are often indexed by accident. A hit is a surface to review, not a way in.",
  error:
    "Stack traces, debug panels and verbose errors that leak paths, versions or query shape.",
  code:
    "Repositories, configuration and pipeline files that mention the domain. A hit is source material that has left the site.",
  docs:
    "Documents and pages published outside the main site: PDFs, wikis, spreadsheets and runbooks. A hit is content that is reachable but may not be intended for the public.",
  content:
    "Pages a site is publishing that it may not intend to. Useful when auditing what a migration or a CMS left behind.",
  infra:
    "Third parties, subdomains and services a site links to or is described by, gathered from public indexes.",
};

/**
 * The catalogue.
 *
 * Ordered by how directly a hit matters within each category. Where two
 * queries would find the same thing, the more specific one is listed first so a
 * reader can run it before broadening.
 */
export const DORK_TEMPLATES: DorkTemplate[] = [
  // --- exposure ---
  {
    id: "env-file",
    category: "exposure",
    label: "Environment files",
    query: "site:{domain} (ext:env OR ext:env.bak OR ext:env.old)",
    engine: "google",
    note: "An .env file holds credentials and connection strings. A hit should be treated as leaked until verified otherwise.",
  },
  {
    id: "backup-archives",
    category: "exposure",
    label: "Database and site backups",
    query: "site:{domain} (ext:sql OR ext:sql.gz OR ext:bak OR ext:old)",
    engine: "google",
    note: "A downloadable backup is a full data breach in one URL.",
  },
  {
    id: "config-files",
    category: "exposure",
    label: "Configuration and key files",
    query: "site:{domain} (ext:yml OR ext:yaml OR ext:ini OR ext:pem OR ext:key)",
    engine: "google",
    note: "Deployment configs and private keys should never be served from a web root.",
  },
  {
    id: "vault-exports",
    category: "exposure",
    label: "VPN profiles and key stores",
    query: "site:{domain} (ext:ovpn OR ext:p12 OR ext:pfx OR ext:kdbx)",
    engine: "google",
    note: "A downloadable VPN profile or key store carries credentials that may still be valid.",
  },
  {
    id: "office-docs",
    category: "exposure",
    label: "Office documents",
    query: "site:{domain} (ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:ppt OR ext:pptx OR ext:pdf)",
    engine: "google",
    note: "Internal documents are often published by a CMS upload folder with no access rule.",
  },
  {
    id: "directory-index",
    category: "exposure",
    label: "Directory listings",
    query: 'site:{domain} intitle:"Index of"',
    engine: "google",
    note: "An autoindex page lists every file in a directory. One is a sign that listings are enabled.",
  },
  {
    id: "log-files",
    category: "exposure",
    label: "Log files",
    query: 'site:{domain} (ext:log OR intitle:"index of" ext:txt)',
    engine: "google",
    note: "Public logs leak paths, session tokens and internal addresses.",
  },
  {
    id: "vcs-metadata",
    category: "exposure",
    label: "Version control metadata",
    query: "site:{domain} (inurl:.git OR inurl:.svn OR inurl:.hg)",
    engine: "google",
    note: "A reachable .git directory lets a visitor reconstruct source that was never meant to be served.",
  },
  {
    id: "server-status",
    category: "exposure",
    label: "Status and diagnostic pages",
    query: 'site:{domain} (intitle:"phpinfo()" OR intitle:"Apache Status" OR intitle:"Server Status")',
    engine: "google",
    note: "phpinfo and status pages list environment variables, module versions and server paths.",
  },

  // --- leaks ---
  {
    id: "paste-sites",
    category: "leaks",
    label: "Paste sites",
    query: '"{domain}" (site:pastebin.com OR site:ghostbin.com OR site:paste.ee)',
    engine: "google",
    note: "A credential dump that names the domain is the highest-priority leak to triage.",
  },
  {
    id: "private-key-material",
    category: "leaks",
    label: "Private key markers",
    query:
      '"{domain}" (intext:"BEGIN RSA PRIVATE KEY" OR intext:"BEGIN OPENSSH PRIVATE KEY" OR intext:"BEGIN EC PRIVATE KEY")',
    engine: "google",
    note: "A pasted key that names the domain is a credential to revoke before anything else.",
  },
  {
    id: "leaked-secrets",
    category: "leaks",
    label: "Addresses and credentials in text",
    query: '"{domain}" (intext:"password" OR intext:"api_key" OR intext:"secret")',
    engine: "google",
    note: "A page pairing the domain with a secret is worth reading before it is removed.",
  },
  {
    id: "public-buckets",
    category: "leaks",
    label: "Cloud storage referencing the domain",
    query:
      '"{domain}" (site:s3.amazonaws.com OR site:storage.googleapis.com OR site:blob.core.windows.net)',
    engine: "google",
    note: "A bucket named for the domain that is listable is a direct data exposure.",
  },
  {
    id: "github-code",
    category: "leaks",
    label: "Code references on GitHub",
    query: '"@{domain}" site:github.com',
    engine: "google",
    note: "A repository that hard-codes the domain often also hard-codes a key for it.",
  },
  {
    id: "gists",
    category: "leaks",
    label: "Public gists",
    query: '"{domain}" site:gist.github.com',
    engine: "google",
    note: "A gist that names the domain often carries a sample config with working secrets.",
  },
  {
    id: "credential-pages",
    category: "leaks",
    label: "Pages titled with credentials",
    query: 'site:{domain} (intitle:credentials OR intitle:passwords OR intitle:"api keys")',
    engine: "google",
    note: "A page titled for credentials on the site's own domain is content that was published by mistake.",
  },
  {
    id: "alt-pastes",
    category: "leaks",
    label: "Smaller paste archives",
    query: '"{domain}" (site:rentry.co OR site:controlc.com OR site:privatebin.net)',
    engine: "google",
    note: "Smaller paste services hold the same dumps and are rarely covered by removal requests.",
  },

  // --- cloud ---
  {
    id: "cloud-s3",
    category: "cloud",
    label: "S3 buckets naming the domain",
    query: 'site:s3.amazonaws.com "{domain}"',
    engine: "google",
    note: "An S3 object that names the domain is a bucket whose contents the search engine has already crawled.",
  },
  {
    id: "cloud-gcs",
    category: "cloud",
    label: "Google Cloud Storage objects",
    query: 'site:storage.googleapis.com "{domain}"',
    engine: "google",
    note: "A Google Cloud Storage object naming the domain points at a bucket to check for public access.",
  },
  {
    id: "cloud-azure",
    category: "cloud",
    label: "Azure blob objects",
    query: 'site:blob.core.windows.net "{domain}"',
    engine: "google",
    note: "An Azure blob naming the domain points at a container whose access level should be confirmed.",
  },
  {
    id: "cloud-listings",
    category: "cloud",
    label: "Listing-enabled buckets",
    query:
      '"{domain}" (inurl:s3.amazonaws.com OR inurl:storage.googleapis.com) intext:"ListBucketResult"',
    engine: "google",
    note: "A ListBucketResult page is an XML index that lists every object in the bucket.",
  },
  {
    id: "cloud-backups",
    category: "cloud",
    label: "Backups in object storage",
    query: 'site:s3.amazonaws.com (ext:sql OR ext:bak OR ext:zip) "{domain}"',
    engine: "google",
    note: "A backup archive in a public bucket is a full copy of the data it was taken from.",
  },
  {
    id: "cloud-origin",
    category: "cloud",
    label: "Origins that mention the domain",
    query: 'http.html:"{domain}" -hostname:{domain}',
    engine: "shodan",
    note: "A host whose page mentions the domain but is served under another name is a candidate origin behind a CDN.",
  },
  {
    id: "cloud-spaces",
    category: "cloud",
    label: "Other object storage",
    query: '"{domain}" (site:digitaloceanspaces.com OR site:linodeobjects.com)',
    engine: "google",
    note: "Smaller object stores are often created ad hoc and left publicly readable.",
  },
  {
    id: "cloud-datasets",
    category: "cloud",
    label: "Hosted datasets",
    query: '"{domain}" (site:kaggle.com OR site:data.world OR site:figshare.com)',
    engine: "google",
    note: "A published dataset that names the domain may contain records the owner shared for one purpose.",
  },
  {
    id: "cloud-previews",
    category: "cloud",
    label: "Hosted clones and previews",
    query: '"{domain}" (site:cloudfront.net OR site:azurewebsites.net OR site:herokuapp.com)',
    engine: "google",
    note: "A preview host under a default provider name is a deployment that may not track the production access rules.",
  },

  // --- api ---
  {
    id: "api-swagger",
    category: "api",
    label: "OpenAPI and Swagger specifications",
    query: "site:{domain} (inurl:swagger.json OR inurl:openapi.json OR inurl:swagger.yaml)",
    engine: "google",
    note: "A specification file lists every endpoint, method and parameter the service accepts.",
  },
  {
    id: "api-graphql",
    category: "api",
    label: "GraphQL endpoints",
    query: "site:{domain} (inurl:graphql OR inurl:gql)",
    engine: "google",
    note: "A reachable GraphQL endpoint usually answers an introspection query that describes the whole schema.",
  },
  {
    id: "api-postman",
    category: "api",
    label: "Postman collections",
    query: '"{domain}" (site:postman.com OR site:documenter.getpostman.com)',
    engine: "google",
    note: "A shared collection names real hosts and paths, and sometimes carries an example token.",
  },
  {
    id: "api-keys",
    category: "api",
    label: "Keys in indexed pages",
    query:
      'site:{domain} (intext:"api_key" OR intext:"apikey" OR intext:"Authorization: Bearer")',
    engine: "google",
    note: "A page on the site that prints a key in its body is an interface exposing its own credentials.",
  },
  {
    id: "api-internal",
    category: "api",
    label: "Internal API paths",
    query: "site:{domain} (inurl:/api/v1 OR inurl:/api/v2 OR inurl:/api/internal)",
    engine: "google",
    note: "Internal API paths in the public index are endpoints the front end calls but nobody documented.",
  },
  {
    id: "api-reference",
    category: "api",
    label: "API reference pages",
    query: 'site:{domain} intitle:"API Reference"',
    engine: "google",
    note: "A reference page enumerates the surface a client can call without reading source.",
  },
  {
    id: "api-webhooks",
    category: "api",
    label: "Webhook and callback docs",
    query: 'site:{domain} (intext:"webhook" OR intext:"callback_url")',
    engine: "google",
    note: "Webhook documentation names the endpoints and payloads a third party will receive.",
  },
  {
    id: "api-health",
    category: "api",
    label: "Health and actuator endpoints",
    query: "site:{domain} (inurl:healthz OR inurl:actuator OR inurl:/health)",
    engine: "google",
    note: "A framework health or actuator endpoint reports build versions and internal component state.",
  },

  // --- login ---
  {
    id: "login-pages",
    category: "login",
    label: "Sign-in pages",
    query: "site:{domain} (inurl:login OR inurl:signin OR inurl:sign-in)",
    engine: "google",
    note: "Every distinct sign-in page is an authentication surface with its own lockout policy.",
  },
  {
    id: "admin-panels",
    category: "login",
    label: "Admin panels",
    query: "site:{domain} (inurl:admin OR inurl:administrator OR inurl:wp-admin)",
    engine: "google",
    note: "An internet-facing admin panel with a default path is a common target.",
  },
  {
    id: "phpmyadmin",
    category: "login",
    label: "phpMyAdmin and database tools",
    query: "site:{domain} (inurl:phpmyadmin OR inurl:adminer OR inurl:dbadmin)",
    engine: "google",
    note: "A database admin tool reachable from the internet is a critical exposure.",
  },
  {
    id: "api-docs",
    category: "login",
    label: "API documentation",
    query: "site:{domain} (inurl:swagger OR inurl:api-docs OR inurl:openapi)",
    engine: "google",
    note: "Published API docs enumerate every endpoint, including the ones meant for internal use.",
  },
  {
    id: "staging-hosts",
    category: "login",
    label: "Staging and dev hosts",
    query: "site:{domain} (inurl:staging OR inurl:dev OR inurl:test OR inurl:uat)",
    engine: "google",
    note: "Staging is where pre-release auth lives, often with sample data.",
  },
  {
    id: "password-reset",
    category: "login",
    label: "Password reset flows",
    query: "site:{domain} (inurl:reset OR inurl:forgot-password OR inurl:password)",
    engine: "google",
    note: "Each reset flow is an unauthenticated endpoint that sends mail and changes state.",
  },
  {
    id: "sso",
    category: "login",
    label: "Single sign-on endpoints",
    query: "site:{domain} (inurl:sso OR inurl:oauth OR inurl:saml)",
    engine: "google",
    note: "An SSO endpoint documents the identity provider and the trust it extends to the site.",
  },

  // --- error ---
  {
    id: "stack-traces",
    category: "error",
    label: "Stack traces and SQL errors",
    query: 'site:{domain} (intext:"Stack trace" OR intext:"SQL syntax" OR intext:"Warning: mysql")',
    engine: "google",
    note: "A public stack trace names libraries, versions and internal paths.",
  },
  {
    id: "debug-panels",
    category: "error",
    label: "Debug and framework panels",
    query: 'site:{domain} (intitle:"Debug" OR intitle:"Django" OR intitle:"Laravel")',
    engine: "google",
    note: "A framework debug page in production exposes environment variables and query history.",
  },
  {
    id: "error-pages",
    category: "error",
    label: "Verbose error pages",
    query: 'site:{domain} (intext:"Fatal error" OR intext:"Uncaught exception")',
    engine: "google",
    note: "Uncaught exceptions tell an attacker which software and version to target.",
  },
  {
    id: "traceback",
    category: "error",
    label: "Framework tracebacks",
    query: 'site:{domain} (intext:"Traceback (most recent call last)" OR intext:"Unhandled exception")',
    engine: "google",
    note: "A Python traceback prints file paths, library versions and the line that failed.",
  },
  {
    id: "error-logs",
    category: "error",
    label: "Error logs on the web root",
    query: "site:{domain} (inurl:error_log OR ext:err OR inurl:debug.log)",
    engine: "google",
    note: "An error log served from the web root records requests, paths and sometimes credentials.",
  },
  {
    id: "shodan-error-titles",
    category: "error",
    label: "Hosts answering with an error",
    query: 'http.title:"Error" hostname:{domain}',
    engine: "shodan",
    note: "A host whose indexed title is an error page is responding badly to a plain request.",
  },

  // --- code ---
  {
    id: "code-env",
    category: "code",
    label: "Committed environment files",
    query: '"{domain}" filename:.env',
    engine: "github",
    note: "An .env committed to a public repository carries the values it was written to hold.",
  },
  {
    id: "code-config",
    category: "code",
    label: "Committed configuration",
    query: '"{domain}" path:config',
    engine: "github",
    note: "A config file that names the domain also tends to name its mail host, database and keys.",
  },
  {
    id: "code-ci",
    category: "code",
    label: "Pipeline and workflow files",
    query: '"{domain}" path:.github/workflows',
    engine: "github",
    note: "A workflow file names the secrets a pipeline injects and the hosts it deploys to.",
  },
  {
    id: "code-iac",
    category: "code",
    label: "Infrastructure as code",
    query: '"{domain}" path:terraform',
    engine: "github",
    note: "A Terraform tree names the account, region and resource names behind the domain.",
  },
  {
    id: "code-docker",
    category: "code",
    label: "Container build files",
    query: '"{domain}" filename:Dockerfile',
    engine: "github",
    note: "A Dockerfile that hard-codes the domain shows the build context and base images in use.",
  },
  {
    id: "code-keys",
    category: "code",
    label: "Private keys in repositories",
    query: '"{domain}" filename:id_rsa',
    engine: "github",
    note: "A private key in a public repository should be treated as compromised even after it is removed.",
  },
  {
    id: "code-gitlab",
    category: "code",
    label: "Mirrors on other forges",
    query: '"{domain}" (site:gitlab.com OR site:bitbucket.org)',
    engine: "google",
    note: "A mirror on another forge outlives the repository it was copied from.",
  },
  {
    id: "code-well-known",
    category: "code",
    label: ".well-known and security.txt",
    query: "site:{domain} (inurl:.well-known OR inurl:security.txt)",
    engine: "google",
    note: "A .well-known file publishes contact and configuration data about the site on purpose.",
  },
  {
    id: "code-readme",
    category: "code",
    label: "Readme files naming the domain",
    query: '"{domain}" path:README.md',
    engine: "github",
    note: "A README that names the domain often documents internal hosts and setup steps.",
  },

  // --- docs ---
  {
    id: "docs-pdfs",
    category: "docs",
    label: "Published PDFs",
    query: "site:{domain} ext:pdf",
    engine: "google",
    note: "PDFs are indexable and often uploaded without the access rule applied to the page that links them.",
  },
  {
    id: "docs-spreadsheets",
    category: "docs",
    label: "Spreadsheet exports",
    query: "site:{domain} (ext:xlsx OR ext:xls OR ext:csv)",
    engine: "google",
    note: "A spreadsheet on the web root can hold customer lists or internal figures in full.",
  },
  {
    id: "docs-office",
    category: "docs",
    label: "Office documents",
    query: "site:{domain} (ext:docx OR ext:pptx OR ext:odt)",
    engine: "google",
    note: "Office files carry author names and revision history in their metadata.",
  },
  {
    id: "docs-runbooks",
    category: "docs",
    label: "Runbooks and playbooks",
    query: '"{domain}" (intitle:runbook OR intitle:"on-call" OR intitle:playbook)',
    engine: "google",
    note: "A runbook names the on-call rotation, the systems it touches and the steps to recover them.",
  },
  {
    id: "docs-wikis",
    category: "docs",
    label: "Hosted wikis",
    query: '"{domain}" site:atlassian.net',
    engine: "google",
    note: "A Confluence space that names the domain is an internal wiki the search engine has indexed.",
  },
  {
    id: "docs-notion",
    category: "docs",
    label: "Notion pages",
    query: '"{domain}" (site:notion.site OR site:notion.so)',
    engine: "google",
    note: "A Notion page shared by link is readable by anyone who finds the URL.",
  },
  {
    id: "docs-changelogs",
    category: "docs",
    label: "Changelogs and release notes",
    query: "site:{domain} (inurl:changelog OR inurl:release-notes OR inurl:CHANGES)",
    engine: "google",
    note: "A changelog reveals the versions in use and the fixes that have not shipped.",
  },
  {
    id: "docs-drive",
    category: "docs",
    label: "Shared documents in Drive",
    query: '"{domain}" (site:drive.google.com OR site:docs.google.com)',
    engine: "google",
    note: "A Drive document shared publicly is readable outside the organisation that owns it.",
  },
  {
    id: "docs-decks",
    category: "docs",
    label: "Published slide decks",
    query: '"{domain}" filetype:pptx',
    engine: "bing",
    note: "A deck that names the domain often contains strategy, pricing or architecture not meant for release.",
  },

  // --- content ---
  {
    id: "indexed-pages",
    category: "content",
    label: "Indexed pages",
    query: "site:{domain}",
    engine: "google",
    note: "The baseline: what the engine already knows about the site.",
  },
  {
    id: "intranet-words",
    category: "content",
    label: "Internal terminology",
    query: 'site:{domain} (intext:"internal use only" OR intext:"confidential" OR intext:"do not distribute")',
    engine: "google",
    note: "A page marked internal that is nonetheless indexed is a control that failed.",
  },
  {
    id: "forgotten-paths",
    category: "content",
    label: "Old and archived paths",
    query: "site:{domain} (inurl:old OR inurl:backup OR inurl:archive OR inurl:temp)",
    engine: "google",
    note: "Leftover paths are where an old, unpatched stack survives a migration.",
  },
  {
    id: "cached-copies",
    category: "content",
    label: "Cached copies",
    query: "site:{domain} cache:{origin}",
    engine: "bing",
    note: "A cached copy can preserve a page since removed, including one published by mistake.",
  },
  {
    id: "archived-copies",
    category: "content",
    label: "Archived copies",
    query: 'site:web.archive.org "{host}"',
    engine: "google",
    note: "An archived copy can preserve a page since removed, including one published by mistake.",
  },
  {
    id: "print-views",
    category: "content",
    label: "Print and preview views",
    query: "site:{domain} (inurl:print OR inurl:preview OR inurl:draft)",
    engine: "google",
    note: "A print or preview view often renders content the public page hides.",
  },
  {
    id: "search-results",
    category: "content",
    label: "Site search result pages",
    query: "site:{domain} (inurl:/search OR inurl:results)",
    engine: "google",
    note: "Indexed search pages cache queries and their results inside a public URL.",
  },
  {
    id: "media-dirs",
    category: "content",
    label: "Upload and media directories",
    query: "site:{domain} (inurl:uploads OR inurl:media OR inurl:files)",
    engine: "google",
    note: "Upload directories collect every file a CMS accepted, without the page-level rules.",
  },
  {
    id: "second-index",
    category: "content",
    label: "A second index baseline",
    query: "site:{domain}",
    engine: "duckduckgo",
    note: "A second index shows pages one engine dropped or never crawled.",
  },

  // --- infra ---
  {
    id: "subdomains-indexed",
    category: "infra",
    label: "Indexed hostnames",
    query: "site:*.{domain} -www",
    engine: "google",
    note: "Every host the engine has crawled under the domain, which is often wider than a certificate list.",
  },
  {
    id: "shodan-hosts",
    category: "infra",
    label: "Hosts identified by certificate",
    query: "hostname:{domain}",
    engine: "shodan",
    note: "Shodan lists hosts whose certificate or response names the domain, with the ports they answer on.",
  },
  {
    id: "censys-cert",
    category: "infra",
    label: "Certificates issued for the domain",
    query: "parsed.names:{domain}",
    engine: "censys",
    note: "Censys indexes certificate names, which includes hosts that never appeared in a DNS zone.",
  },
  {
    id: "ct-mentions",
    category: "infra",
    label: "Certificate transparency references",
    query: '"{domain}" site:crt.sh',
    engine: "google",
    note: "Certificate transparency logs every hostname a certificate was issued for.",
  },
  {
    id: "dns-archives",
    category: "infra",
    label: "Recorded DNS and TXT",
    query: '"{domain}" (site:securitytrails.com OR site:dnsdumpster.com)',
    engine: "google",
    note: "Third-party DNS archives preserve records the zone has since changed or removed.",
  },
  {
    id: "favicon-matches",
    category: "infra",
    label: "Hosts that share the name",
    query: '"{domain}" favicon',
    engine: "google",
    note: "A search on the brand plus favicon surfaces sibling hosts and clones worth reviewing.",
  },
  {
    id: "tech-profiles",
    category: "infra",
    label: "Technology profiles",
    query: '"{domain}" (site:builtwith.com OR site:wappalyzer.com)',
    engine: "google",
    note: "A public technology profile records the stack the domain serves and how it changed.",
  },
  {
    id: "copyright-mentions",
    category: "infra",
    label: "Brand mentions and acquisitions",
    query: 'intext:"copyright" intext:"{domain}"',
    engine: "google",
    note: "Pages that name the domain, including the acquirer or subsidiary that runs it.",
  },
];

/** The engine's search URL for one query, opened in the visitor's browser. */
export function dorkUrl(engine: DorkEngine, query: string): string {
  const q = encodeURIComponent(query);
  switch (engine) {
    case "bing":
      return `https://www.bing.com/search?q=${q}`;
    case "duckduckgo":
      return `https://duckduckgo.com/?q=${q}`;
    case "shodan":
      return `https://www.shodan.io/search?query=${q}`;
    case "github":
      return `https://github.com/search?q=${q}&type=code`;
    case "censys":
      return `https://search.censys.io/search?resource=hosts&q=${q}`;
    default:
      return `https://www.google.com/search?q=${q}`;
  }
}

/**
 * Fill a template for a target.
 *
 * A plain replace of three known tokens. Values are inserted verbatim, which
 * is safe here because the result is only ever shown as copyable text or handed
 * to `dorkUrl`, which percent-encodes the whole query. It is never placed in
 * markup as HTML and never sent anywhere by this site.
 */
export function renderDork(template: DorkTemplate, vars: DorkVars): string {
  return template.query
    .replaceAll("{domain}", vars.domain)
    .replaceAll("{host}", vars.host)
    .replaceAll("{origin}", vars.origin);
}
