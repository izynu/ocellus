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

export type DorkEngine = "google" | "bing" | "duckduckgo";

export type DorkTemplate = {
  /** Stable id, used as the React key and the copy target. */
  id: string;
  category: DorkCategory;
  /** One line, in the imperative: what querying this finds. */
  label: string;
  /** The query, with placeholders. */
  query: string;
  /** Where to run it. Every engine accepts `site:` and the quoted operators. */
  engine: DorkEngine;
  /** Optional note shown under the query: what a hit means. */
  note?: string;
};

export const DORK_CATEGORY_LABEL: Record<DorkCategory, string> = {
  exposure: "Exposed files and documents",
  login: "Sign-in and admin surfaces",
  error: "Errors and debug output",
  content: "Indexable content",
  infra: "Infrastructure and third parties",
  leaks: "Secrets and pastes",
};

export const DORK_CATEGORY_NOTE: Record<DorkCategory, string> = {
  exposure:
    "Files a site did not mean to publish. A hit is a document that is reachable, indexable and readable without authentication.",
  login:
    "Entry points that are meant to be found by staff and are often indexed by accident. A hit is a surface to review, not a way in.",
  error:
    "Stack traces, debug panels and verbose errors that leak paths, versions or query shape.",
  content:
    "Pages a site is publishing that it may not intend to. Useful when auditing what a migration or a CMS left behind.",
  infra:
    "Third parties, subdomains and services a site links to or is described by, gathered from public indexes.",
  leaks:
    "Code and credentials that have left the site: a paste, a committed config, a public bucket. A hit is the most serious kind of finding.",
};

/**
 * The catalogue.
 *
 * Ordered by how directly a hit matters: an exposed backup is more urgent than
 * a directory listing, which is more urgent than a mention.
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
    id: "staging-hosts",
    category: "login",
    label: "Staging and dev hosts",
    query: "site:{domain} (inurl:staging OR inurl:dev OR inurl:test OR inurl:uat)",
    engine: "google",
    note: "Staging is where pre-release auth lives, often with sample data.",
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
    id: "copyright-mentions",
    category: "infra",
    label: "Brand mentions and acquisitions",
    query: 'intext:"copyright" intext:"{domain}"',
    engine: "google",
    note: "Pages that name the domain, including the acquirer or subsidiary that runs it.",
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
    id: "dns-archives",
    category: "infra",
    label: "Recorded DNS and TXT",
    query: '"{domain}" (site:securitytrails.com OR site:dnsdumpster.com)',
    engine: "google",
    note: "Third-party DNS archives preserve records the zone has since changed or removed.",
  },

  // --- leaks ---
  {
    id: "github-code",
    category: "leaks",
    label: "Code references on GitHub",
    query: '"@{domain}" site:github.com',
    engine: "google",
    note: "A repository that hard-codes the domain often also hard-codes a key for it.",
  },
  {
    id: "paste-sites",
    category: "leaks",
    label: "Paste sites",
    query: '"{domain}" (site:pastebin.com OR site:ghostbin.com OR site:paste.ee)',
    engine: "google",
    note: "A credential dump that names the domain is the highest-priority leak to triage.",
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
    id: "leaked-secrets",
    category: "leaks",
    label: "Addresses and credentials in text",
    query: '"{domain}" (intext:"password" OR intext:"api_key" OR intext:"secret")',
    engine: "google",
    note: "A page pairing the domain with a secret is worth reading before it is removed.",
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
