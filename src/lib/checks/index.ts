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
import { performance } from "./performance";
import { darkPatterns } from "./dark-patterns";

/**
 * Order is the report order: the transport and name layer first, then what the
 * server says about itself, then what the page asks of a visitor.
 */
export const checks: CheckDefinition[] = [
  dnsRecords,
  dnssec,
  ctLogs,
  redirects,
  securityHeaders,
  emailAuth,
  securityTxt,
  infrastructure,
  subdomains,
  techStack,
  threatIntel,
  privacy,
  markup,
  seo,
  performance,
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
