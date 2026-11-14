/**
 * Email authentication: can this domain's mail be trusted, and can anyone
 * forge it?
 *
 * Four records decide the answer:
 *  - SPF (TXT on the apex) names the hosts allowed to send as the domain.
 *  - DKIM (TXT on <selector>._domainkey) signs messages so tampering is visible.
 *  - DMARC (TXT on _dmarc) tells receivers what to do when SPF and DKIM both
 *    fail, and where to send reports.
 *  - MTA-STS and BIMI are the newer layers: transport security and brand marks.
 *
 * A domain with SPF but no DMARC has authentication and no policy, so a
 * receiver still has to guess. That gap is the most common real finding here.
 */

import type { CheckDefinition, CheckResult, Finding } from "../types";
import { unquoteTxt } from "../net/dns";

export type DmarcPolicy = {
  raw: string;
  p: string | null;
  sp: string | null;
  pct: number | null;
  rua: string[];
  ruf: string[];
  adkim: string | null;
  aspf: string | null;
  fo: string | null;
  tags: Record<string, string>;
};

export type SpfData = {
  raw: string;
  mechanisms: string[];
  all: string | null;
  /** Number of DNS-lookup mechanisms, against a hard limit of 10. */
  lookupCount: number;
  includes: string[];
};

export type EmailData = {
  spf: SpfData | null;
  dmarc: DmarcPolicy | null;
  dkim: Array<{ selector: string; present: boolean; keyType?: string; bits?: number }>;
  mx: Array<{ priority: number; host: string }>;
  mtaSts: { dns: boolean; policy: string | null } | null;
  bimi: string | null;
  /** True when the domain publishes a null MX (RFC 7505), i.e. sends no mail. */
  nullMx: boolean;
};

const DKIM_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "s1",
  "s2",
  "k1",
  "k2",
  "dkim",
  "mail",
  "smtp",
  "mandrill",
  "amazonses",
  "protonmail",
  "protonmail2",
  "protonmail3",
  "fm1",
  "fm2",
  "fm3",
  "brevo1",
  "brevo2",
  "sendgrid",
  "mailgun",
  "postmark",
  "cm",
  "hostingermail-a",
  "hostingermail-b",
  "hostingermail-c",
  "zoho",
  "zmail",
  "everlytics",
];

/** SPF mechanisms that cost a DNS lookup, which is capped at 10 by RFC 7208. */
const LOOKUP_MECHANISMS = ["include:", "a", "mx", "ptr", "exists:", "redirect="];

function parseSpf(raw: string): SpfData {
  const tokens = raw.split(/\s+/).slice(1); // drop "v=spf1"
  const mechanisms: string[] = [];
  const includes: string[] = [];
  let all: string | null = null;
  let lookupCount = 0;

  for (const t of tokens) {
    mechanisms.push(t);
    const lower = t.toLowerCase();
    if (lower === "all" || lower.startsWith("all")) all = t;
    else if (/^[+\-~?]?all$/.test(lower)) all = t;
    if (lower.startsWith("include:")) {
      includes.push(t.slice(8));
      lookupCount++;
    } else if (lower === "a" || lower.startsWith("a:") || lower.startsWith("a/")) {
      lookupCount++;
    } else if (lower === "mx" || lower.startsWith("mx:") || lower.startsWith("mx/")) {
      lookupCount++;
    } else if (lower === "ptr" || lower.startsWith("ptr:")) {
      lookupCount++;
    } else if (lower.startsWith("exists:")) {
      lookupCount++;
    } else if (lower.startsWith("redirect=")) {
      lookupCount++;
    }
  }
  return { raw, mechanisms, all, lookupCount, includes };
}

function parseDmarc(raw: string): DmarcPolicy {
  const tags: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim().toLowerCase();
    const v = part.slice(eq + 1).trim();
    if (k) tags[k] = v;
  }
  const list = (v?: string) =>
    (v ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  return {
    raw,
    p: tags.p ?? null,
    sp: tags.sp ?? null,
    pct: tags.pct ? Number(tags.pct) : null,
    rua: list(tags.rua),
    ruf: list(tags.ruf),
    adkim: tags.adkim ?? null,
    aspf: tags.aspf ?? null,
    fo: tags.fo ?? null,
    tags,
  };
}

function dkimKeyInfo(record: string): { keyType?: string; bits?: number } {
  const k = /k=([a-z]+)/i.exec(record)?.[1];
  const p = /p=([A-Za-z0-9+/=]+)/.exec(record)?.[1];
  if (!p) return { keyType: k };
  // Base64 length approximates key size: 2048-bit RSA is ~392 chars.
  const bits = p.length > 300 ? 2048 : p.length > 150 ? 1024 : undefined;
  return { keyType: k ?? "rsa", bits };
}

export const emailAuth: CheckDefinition = {
  id: "email-auth",
  title: "Email authentication",
  question: "Can this domain's mail be authenticated, and can anyone forge it?",
  group: "email",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const domain = ctx.target.domain;

    const [mxRes, txtRes, dmarcRes, mtaStsRes, bimiRes] = await Promise.all([
      ctx.dns.query(domain, "MX"),
      ctx.dns.query(domain, "TXT"),
      ctx.dns.query(`_dmarc.${domain}`, "TXT"),
      ctx.dns.query(`_mta-sts.${domain}`, "TXT"),
      ctx.dns.query(`default._bimi.${domain}`, "TXT"),
    ]);

    const txts = txtRes.answers.filter((r) => r.type === 16).map((r) => unquoteTxt(r.data));
    const spfRaw = txts.find((t) => /^v=spf1/i.test(t.trim()));
    const spf = spfRaw ? parseSpf(spfRaw.trim()) : null;

    const dmarcRaw = dmarcRes.answers
      .filter((r) => r.type === 16)
      .map((r) => unquoteTxt(r.data))
      .find((t) => /^v=DMARC1/i.test(t.trim()));
    const dmarc = dmarcRaw ? parseDmarc(dmarcRaw.trim()) : null;

    const mtaStsTxt = mtaStsRes.answers
      .filter((r) => r.type === 16)
      .map((r) => unquoteTxt(r.data))
      .find((t) => /^v=STSv1/i.test(t.trim()));

    const bimiRaw = bimiRes.answers
      .filter((r) => r.type === 16)
      .map((r) => unquoteTxt(r.data))
      .find((t) => /^v=BIMI1/i.test(t.trim()));

    const mxList = mxRes.answers
      .filter((r) => r.type === 15)
      .map((r) => {
        const [prio, host] = r.data.split(/\s+/);
        return { priority: Number(prio) || 0, host: (host ?? "").replace(/\.$/, "") };
      });
    const nullMx = mxList.length === 1 && (mxList[0].host === "" || mxList[0].host === ".");

    // DKIM: try the selectors that real mail providers use. A miss is not proof
    // that DKIM is absent, only that it is not on a well-known selector.
    const dkim = await Promise.all(
      DKIM_SELECTORS.slice(0, 12).map(async (selector) => {
        const res = await ctx.dns.query(`${selector}._domainkey.${domain}`, "TXT");
        const record = res.answers
          .filter((r) => r.type === 16)
          .map((r) => unquoteTxt(r.data))
          .find((t) => /v=DKIM1|k=|p=/i.test(t));
        return record
          ? { selector, present: true, ...dkimKeyInfo(record) }
          : { selector, present: false };
      })
    );
    const dkimFound = dkim.filter((d) => d.present);

    const findings: Finding[] = [];

    // --- SPF ---
    if (!spf) {
      findings.push({
        id: "email-no-spf",
        title: "No SPF record",
        detail: `${domain} publishes no v=spf1 TXT record. Receivers have no list of hosts authorised to send as this domain.`,
        severity: "high",
        remediation:
          "Publish an SPF record listing your sending hosts, ending in -all once you have verified the list is complete: v=spf1 include:... -all",
        reference: { label: "RFC 7208", url: "https://datatracker.ietf.org/doc/html/rfc7208" },
      });
    } else {
      if (spf.lookupCount > 10) {
        findings.push({
          id: "email-spf-lookups",
          title: "SPF exceeds the 10-lookup limit",
          detail: `The record needs ${spf.lookupCount} DNS lookups. RFC 7208 caps evaluation at 10, and receivers that hit the cap return permerror, which fails every message.`,
          severity: "high",
          remediation:
            "Flatten includes to literal IP ranges, or move rarely used senders to a subdomain with its own SPF record.",
          reference: { label: "RFC 7208 §4.6.4", url: "https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4" },
        });
      }
      if (!spf.all) {
        findings.push({
          id: "email-spf-no-all",
          title: "SPF has no all mechanism",
          detail: "The record does not end with an all mechanism, so unauthorised senders get a neutral result instead of a fail.",
          severity: "medium",
          remediation: "End the record with -all (hard fail) or ~all (soft fail) while you validate the sender list.",
        });
      } else if (spf.all.startsWith("?")) {
        findings.push({
          id: "email-spf-neutral",
          title: "SPF ends in ?all, which asserts nothing",
          detail: "A neutral result tells receivers to make up their own mind, which is the same as having no policy for unauthorised senders.",
          severity: "medium",
          remediation: "Change ?all to -all once you are confident every legitimate sender is listed.",
        });
      } else if (spf.all.startsWith("+")) {
        findings.push({
          id: "email-spf-pass-all",
          title: "SPF ends in +all, which authorises every host on the internet",
          detail: "+all passes any sender, so the record provides no protection and actively authorises forgery.",
          severity: "critical",
          remediation: "Change +all to -all immediately.",
        });
      }
    }

    // --- DMARC ---
    if (!dmarc) {
      findings.push({
        id: "email-no-dmarc",
        title: "No DMARC record",
        detail: `${domain} publishes no _dmarc TXT record. Receivers have no instruction for what to do when SPF and DKIM fail, and you receive no reports.`,
        severity: "high",
        remediation:
          "Start with v=DMARC1; p=none; rua=mailto:dmarc@yourdomain to collect reports, then move to p=quarantine and p=reject.",
        reference: { label: "RFC 7489", url: "https://datatracker.ietf.org/doc/html/rfc7489" },
      });
    } else {
      if (dmarc.p === "none") {
        findings.push({
          id: "email-dmarc-none",
          title: "DMARC policy is p=none",
          detail:
            "p=none asks receivers to report failures but take no action, so a forged message still reaches the inbox.",
          severity: "high",
          remediation:
            "Once reports show your legitimate senders passing, move to p=quarantine, then p=reject.",
          reference: { label: "RFC 7489 §6.3", url: "https://datatracker.ietf.org/doc/html/rfc7489#section-6.3" },
        });
      }
      if (dmarc.pct !== null && dmarc.pct < 100) {
        findings.push({
          id: "email-dmarc-pct",
          title: `DMARC only applies to ${dmarc.pct}% of mail`,
          detail: `pct=${dmarc.pct} leaves ${100 - dmarc.pct}% of failing messages unaffected by the policy.`,
          severity: "medium",
          remediation: "Raise pct to 100, or remove the tag, which defaults to 100.",
        });
      }
      if (dmarc.rua.length === 0) {
        findings.push({
          id: "email-dmarc-no-rua",
          title: "DMARC has no aggregate report address",
          detail: "Without rua, you never see which senders are failing, so you cannot safely tighten the policy.",
          severity: "low",
          remediation: "Add rua=mailto:dmarc-reports@yourdomain.",
        });
      }
      if (dmarc.sp && dmarc.sp === "none" && dmarc.p !== "none") {
        findings.push({
          id: "email-dmarc-sp-none",
          title: "Subdomains are exempt from the DMARC policy",
          detail: `p=${dmarc.p} protects the apex, but sp=none leaves every subdomain open to forgery.`,
          severity: "medium",
          remediation: "Remove sp=none, or set sp equal to p.",
        });
      }
    }

    // --- DKIM ---
    if (dkimFound.length === 0) {
      findings.push({
        id: "email-dkim-unknown",
        title: "No DKIM key found on a common selector",
        detail:
          "None of the 12 selectors checked returned a DKIM key. Either DKIM is not configured, or it uses a custom selector, which is legitimate but means this check cannot confirm it.",
        severity: "medium",
        remediation:
          "Confirm DKIM is enabled with your mail provider. If it is, publish the selector name in your DNS docs so it can be verified.",
        reference: { label: "RFC 6376", url: "https://datatracker.ietf.org/doc/html/rfc6376" },
      });
    } else {
      const weak = dkimFound.filter((d) => d.bits && d.bits < 1024);
      if (weak.length > 0) {
        findings.push({
          id: "email-dkim-weak",
          title: "DKIM key is shorter than 1024 bits",
          detail: `${weak.map((w) => w.selector).join(", ")} publish a key that is too short to resist a factoring attack.`,
          severity: "high",
          remediation: "Rotate to a 2048-bit RSA key, or an Ed25519 key where the provider supports it.",
        });
      }
    }

    // --- Transport and brand ---
    if (!mtaStsTxt && !nullMx) {
      findings.push({
        id: "email-no-mta-sts",
        title: "No MTA-STS policy",
        detail:
          "Without MTA-STS, a downgrade attack can force mail delivery over plaintext SMTP between servers.",
        severity: "low",
        remediation:
          "Publish a _mta-sts TXT record and host a policy file at https://mta-sts.yourdomain/.well-known/mta-sts.txt with mode: enforce.",
        reference: { label: "RFC 8461", url: "https://datatracker.ietf.org/doc/html/rfc8461" },
      });
    }

    const failing = findings.filter((f) => f.severity === "critical" || f.severity === "high");
    const status: CheckResult["status"] =
      failing.length >= 2 ? "fail" : failing.length === 1 || findings.length > 0 ? "warn" : "pass";

    const parts: string[] = [];
    parts.push(spf ? "SPF present" : "no SPF");
    parts.push(dmarc ? `DMARC p=${dmarc.p ?? "unset"}` : "no DMARC");
    parts.push(dkimFound.length ? `DKIM on ${dkimFound.map((d) => d.selector).join(", ")}` : "DKIM not confirmed");

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline: `${parts.join(", ")}.`,
      findings,
      data: {
        spf,
        dmarc,
        dkim,
        mx: mxList,
        mtaSts: mtaStsTxt ? { dns: true, policy: mtaStsTxt } : null,
        bimi: bimiRaw ?? null,
        nullMx,
      } satisfies EmailData,
      ms: Math.round(performance.now() - started),
      source: "DNS-over-HTTPS TXT and MX records",
    };
  },
};
