/**
 * security.txt, RFC 9116.
 *
 * The file is a machine-readable contact for someone who has found a
 * vulnerability. Its value is entirely in whether it is current: a file whose
 * Expires date has passed is defined by the RFC as invalid, so a stale file is
 * worse than none, because a researcher who trusts it reports into a mailbox
 * nobody reads.
 *
 * The file is fetched through the reader service because the target origin does
 * not send CORS headers. The reader returns the body as text when asked, and a
 * real file starts with Contact: lines. Anything else, including a rendered
 * error page, is treated as absent.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";

export type SecurityTxtData = {
  found: boolean;
  fields: Record<string, string[]>;
  expires: string | null;
  expired: boolean;
  canonical: string | null;
};

/** Field names defined by RFC 9116, plus the two in common use before it. */
const FIELDS = [
  "contact",
  "expires",
  "encryption",
  "acknowledgments",
  "preferred-languages",
  "canonical",
  "policy",
  "hiring",
  "csirt",
  "csaf",
];

const YEAR_MS = 365 * 24 * 60 * 60 * 1000;

function parseFields(body: string): Record<string, string[]> {
  const fields: Record<string, string[]> = {};
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    // Comments are lines beginning with #, and they carry no data.
    if (!line || line.startsWith("#")) continue;
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    if (!FIELDS.includes(name)) continue;
    const value = line.slice(colon + 1).trim();
    if (!value) continue;
    if (!fields[name]) fields[name] = [];
    fields[name].push(value);
  }
  return fields;
}

export const securityTxt: CheckDefinition = {
  id: "security-txt",
  title: "security.txt",
  question: "Does the site publish a current, valid security contact under RFC 9116?",
  group: "headers",
  weight: 1,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const origin = new URL(ctx.target.url).origin;

    const read = (path: string, key: string) =>
      ctx.net.text(`https://r.jina.ai/${origin}${path}`, {
        timeoutMs: 20_000,
        // A cached entry can predate the file or be a stale error body, and
        // "is there a security.txt" is a question about now. Bypass the cache.
        headers: { "x-respond-with": "text", "x-no-cache": "true" },
        cacheKey: key,
      });

    const wellKnown = await read("/.well-known/security.txt", `sectxt-wellknown:${origin}`);
    const root = await read("/security.txt", `sectxt-root:${origin}`);

    // A missing file and an unreachable reader look the same in the body, so
    // only claim "absent" when at least one request completed with a body.
    const anyResponse = wellKnown.ok || root.ok;

    if (!anyResponse) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "security.txt could not be fetched through the reader service.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: "r.jina.ai reader",
        note: "Both the well-known path and the root path failed to load. This says nothing about whether the file exists.",
      };
    }

    // RFC 9116 requires the file under /.well-known/; the root path is a
    // legacy location that is still honoured in practice.
    const wellKnownBody = wellKnown.ok ? wellKnown.text : "";
    const rootBody = root.ok ? root.text : "";
    const wellKnownFields = parseFields(wellKnownBody);
    const rootFields = parseFields(rootBody);

    // Presence is judged on any recognised RFC 9116 field, not on Contact
    // alone. A rendered error page carries no such fields, so it still reads as
    // absent, while a real file that forgot Contact stays visible as a file
    // with a defect rather than disappearing entirely.
    const fromWellKnown = Object.keys(wellKnownFields).length > 0;
    const fromRoot = Object.keys(rootFields).length > 0;
    const found = fromWellKnown || fromRoot;

    if (!found) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "warn",
        headline: `No security.txt was found at ${origin}/.well-known/security.txt or ${origin}/security.txt.`,
        findings: [
          {
            id: "security-txt-missing",
            title: "No security.txt",
            detail: `Neither the well-known path nor the root path returned a file with a Contact line. A researcher who finds a vulnerability has no published address to report it to.`,
            severity: "low",
            remediation: `Publish this file at ${origin}/.well-known/security.txt, with a future Expires date: Contact: mailto:security@${ctx.target.domain} and Expires: ${new Date(Date.now() + 300 * 24 * 60 * 60 * 1000).toISOString()}. RFC 9116 requires both fields.`,
            reference: {
              label: "RFC 9116",
              url: "https://www.rfc-editor.org/rfc/rfc9116.html",
            },
          },
        ],
        data: {
          found: false,
          fields: {},
          expires: null,
          expired: false,
          canonical: null,
        } satisfies SecurityTxtData,
        ms: Math.round(performance.now() - started),
        source: "r.jina.ai reader",
      };
    }

    const fields = fromWellKnown ? wellKnownFields : rootFields;
    const expires = fields.expires?.[0] ?? null;
    const canonical = fields.canonical?.[0] ?? null;
    const contacts = fields.contact ?? [];

    const expiresAt = expires ? Date.parse(expires) : Number.NaN;
    const expiresValid = !Number.isNaN(expiresAt);
    const expired = expiresValid && expiresAt < Date.now();
    const tooFarOut = expiresValid && expiresAt - Date.now() > YEAR_MS;

    const findings: Finding[] = [];

    if (expiresValid && expired) {
      findings.push({
        id: "security-txt-expired",
        title: "security.txt has expired",
        detail: `The Expires field is ${expires}, which is in the past. RFC 9116 says a file past its expiry should be considered invalid, so a researcher has no reason to trust the contact.`,
        severity: "medium",
        remediation: "Update the Expires date, and set a reminder to refresh it before it lapses.",
        reference: {
          label: "RFC 9116 §2.5.5",
          url: "https://www.rfc-editor.org/rfc/rfc9116.html#section-2.5.5",
        },
      });
    }

    if (!expires) {
      findings.push({
        id: "security-txt-no-expires",
        title: "security.txt has no Expires field",
        detail: "The file omits Expires, which RFC 9116 requires. Without it there is no way to tell a current contact from an abandoned one.",
        severity: "low",
        remediation: "Add an Expires field with an ISO 8601 timestamp less than a year in the future.",
        reference: {
          label: "RFC 9116 §2.5.5",
          url: "https://www.rfc-editor.org/rfc/rfc9116.html#section-2.5.5",
        },
      });
    } else if (tooFarOut) {
      findings.push({
        id: "security-txt-expires-far",
        title: "security.txt expires more than a year out",
        detail: `The Expires field is ${expires}, more than a year away. RFC 9116 recommends a shorter window so an abandoned contact is noticed rather than trusted indefinitely.`,
        severity: "low",
        remediation: "Shorten the Expires date to under twelve months and renew it as part of a routine check.",
        reference: {
          label: "RFC 9116 §2.5.5",
          url: "https://www.rfc-editor.org/rfc/rfc9116.html#section-2.5.5",
        },
      });
    }

    if (contacts.length === 0) {
      findings.push({
        id: "security-txt-no-contact",
        title: "security.txt has no Contact field",
        detail: "The file parsed but carries no Contact line, so it gives a researcher no address to use.",
        severity: "medium",
        remediation: "Add at least one Contact field, for example Contact: mailto:security@yourdomain, or a https:// URL to a reporting form.",
        reference: {
          label: "RFC 9116 §2.5.3",
          url: "https://www.rfc-editor.org/rfc/rfc9116.html#section-2.5.3",
        },
      });
    }

    if (canonical) {
      let canonicalHost = "";
      try {
        canonicalHost = new URL(canonical).hostname.toLowerCase();
      } catch {
        canonicalHost = "";
      }
      if (canonicalHost && canonicalHost !== ctx.target.host) {
        findings.push({
          id: "security-txt-canonical-mismatch",
          title: "security.txt points at a different host",
          detail: `The Canonical field is ${canonical}, which is not ${ctx.target.host}. Either the file was copied from another site, or it is served from a host it does not describe.`,
          severity: "low",
          remediation: `Set Canonical to the URL this file is actually served from, for example ${origin}/.well-known/security.txt.`,
          reference: {
            label: "RFC 9116 §2.5.2",
            url: "https://www.rfc-editor.org/rfc/rfc9116.html#section-2.5.2",
          },
        });
      }
    }

    // Every defect here is a hygiene problem rather than an exposure, so the
    // worst this check reports is a warning. The findings carry the severity.
    const status: CheckResult["status"] = findings.length > 0 ? "warn" : "pass";

    // `fields` is keyed by field name, so its size is the number of distinct
    // field types, not the number of lines. Saying "fields" for that count
    // overstated it on any file that repeats Contact.
    const fieldCount = Object.keys(fields).length;
    const headline = expired
      ? `security.txt is present but expired on ${expires}, so RFC 9116 treats it as invalid.`
      : `security.txt is present with ${fieldCount} field type${fieldCount === 1 ? "" : "s"}, ${contacts.length} contact${contacts.length === 1 ? "" : "s"}${expires ? `, valid until ${expires}` : " and no Expires date"}.`;

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        found: true,
        fields,
        expires,
        expired,
        canonical,
      } satisfies SecurityTxtData,
      ms: Math.round(performance.now() - started),
      source: `r.jina.ai reader, ${fromWellKnown ? "/.well-known/security.txt" : "/security.txt"}`,
    };
  },
};
