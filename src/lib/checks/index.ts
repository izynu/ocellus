/**
 * The check registry.
 *
 * This list is the product surface: the scan page runs it, the /checks page
 * documents it, and the report orders itself by it. Adding a check means
 * adding one import and one entry here.
 */

import type { CheckDefinition, CheckGroup } from "../types";

import { dnsRecords } from "./dns-records";
import { dnssec } from "./dnssec";
import { securityHeaders } from "./security-headers";
import { ctLogs } from "./ct-logs";
import { redirects } from "./redirects";
import { emailAuth } from "./email-auth";
import { privacy } from "./privacy";
import { markup } from "./markup";
import { seo } from "./seo";
import { securityTxt } from "./security-txt";
import { infrastructure } from "./infrastructure";
import { subdomains } from "./subdomains";
import { techStack } from "./tech-stack";
import { threatIntel } from "./threat-intel";
import { malwareListings } from "./malware-listings";
import { performance } from "./performance";
import { carbon } from "./carbon";
import { darkPatterns } from "./dark-patterns";
import { whois } from "./whois";
import { dnsHygiene } from "./dns-hygiene";
import { dnsAliases } from "./dns-aliases";
import { nameservers } from "./nameservers";
import { archiveHistory } from "./archive-history";
import { popularity } from "./popularity";
import { vulnerabilityExposure } from "./vulnerability-exposure";
import { cohosted } from "./cohosted";
import { certificateRevocation } from "./certificate-revocation";
import { edgeProtection } from "./edge-protection";
import { blocklist } from "./blocklist";
import { breachHistory } from "./breach-history";

/**
 * Order is the report order: the transport and name layer first, then what the
 * server says about itself, then what the page asks of a visitor.
 */
export const checks: CheckDefinition[] = [
  dnsRecords,
  dnssec,
  whois,
  dnsHygiene,
  dnsAliases,
  nameservers,
  ctLogs,
  certificateRevocation,
  redirects,
  securityHeaders,
  edgeProtection,
  emailAuth,
  securityTxt,
  infrastructure,
  cohosted,
  vulnerabilityExposure,
  subdomains,
  techStack,
  threatIntel,
  malwareListings,
  blocklist,
  breachHistory,
  archiveHistory,
  popularity,
  privacy,
  markup,
  seo,
  performance,
  carbon,
  darkPatterns,
];

export const byId = new Map(checks.map((c) => [c.id, c]));

export const GROUP_LABEL: Record<CheckGroup, string> = {
  transport: "Transport and certificates",
  dns: "Name system",
  email: "Email",
  headers: "Response headers",
  privacy: "Privacy",
  content: "Content and accessibility",
  performance: "Performance",
  seo: "Search and preview",
  infrastructure: "Infrastructure",
  threat: "Reputation",
  ux: "Interface friction",
};

export const GROUP_ORDER: CheckGroup[] = [
  "transport",
  "dns",
  "headers",
  "email",
  "infrastructure",
  "privacy",
  "content",
  "performance",
  "seo",
  "threat",
  "ux",
];

/** The checks belonging to one group, in registry order. */
export function groupOf(group: CheckGroup): CheckDefinition[] {
  return checks.filter((c) => c.group === group);
}
