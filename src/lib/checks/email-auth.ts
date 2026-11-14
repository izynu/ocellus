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
  /**
   * Target of a `redirect=` modifier, or null. A record that redirects to
   * another domain is evaluated there, so it legitimately carries no all
   * mechanism of its own and must not be reported as though it lacked one.
   */
  redirect: string | null;
};

export type EmailData = {
  spf: SpfData | null;
  dmarc: DmarcPolicy | null;
  dkim: Array<{ selector: string; present: boolean; keyType?: string; bits?: number }>;
  mx: Array<{ priority: number; host: string }>;
  /**
   * MTA-STS is a two-part policy: a TXT record that announces it, and a policy
   * file served over HTTPS that carries the actual mode. Both are required by
   * RFC 8461 §3, so both are recorded. `policy` is the TXT value, `fileMode` the
   * mode parsed out of the policy file when it could be fetched.
   */
  mtaSts: { dns: boolean; policy: string | null; fileMode: string | null; fileOk: boolean } | null;
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

/**
 * SPF mechanisms that cost a DNS lookup, which RFC 7208 §4.6.4 caps at 10.
 *
 * Kept as documentation of what the counter in `parseSpf` covers, and used by
 * nothing at runtime: the parse branches match on the mechanism body directly
 * so the qualifier is already stripped by the time they run.
 */
export const LOOKUP_MECHANISMS = ["include:", "a", "mx", "ptr", "exists:", "redirect="] as const;

function parseSpf(raw: string): SpfData {
  const tokens = raw.split(/\s+/).slice(1); // drop "v=spf1"
  const mechanisms: string[] = [];
  const includes: string[] = [];
  let all: string | null = null;
  let redirect: string | null = null;
  let lookupCount = 0;

  for (const t of tokens) {
    mechanisms.push(t);
    // Strip the qualifier before matching. RFC 7208 lets every mechanism carry
    // one of + - ~ ?, and without this `-include:foo` matches no branch at all:
    // the include is not recorded, its lookup is not counted, and a record that
    // genuinely exceeds the 10-lookup cap reports zero.
    const lower = t.toLowerCase();
    const body = lower.replace(/^[+\-~?]/, "");
    // `all` is only the all mechanism. The old test also accepted any token
    // beginning with "all", so `allfoo` was read as a catch-all policy.
    if (body === "all") all = t;
    if (body.startsWith("include:")) {
      includes.push(t.slice(t.indexOf(":") + 1));
      lookupCount++;
    } else if (body === "a" || body.startsWith("a:") || body.startsWith("a/")) {
      lookupCount++;
    } else if (body === "mx" || body.startsWith("mx:") || body.startsWith("mx/")) {
      lookupCount++;
    } else if (body === "ptr" || body.startsWith("ptr:")) {
      lookupCount++;
    } else if (body.startsWith("exists:")) {
      lookupCount++;
    } else if (body.startsWith("redirect=")) {
      redirect = t.slice(t.indexOf("=") + 1);
      lookupCount++;
    }
  }
  return { raw, mechanisms, all, lookupCount, includes, redirect };
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

/**
 * What a `_domainkey` TXT record says about the key.
 *
 * RFC 6376 §3.6.1: an empty `p=` tag means the key was revoked. The old regex
 * required at least one character in the value, so `p=` matched nothing, the
 * record fell through as "present", and a revoked key was reported as a working
 * one. `p=([^;\s]*)` matches the empty value, which is then reported honestly.
 */
function dkimKeyInfo(record: string): { keyType?: string; bits?: number; revoked?: boolean } {
  const k = /(?:^|[;\s])k=([a-z]+)/i.exec(record)?.[1];
  // `p=` is base64 and may be folded across whitespace, so strip it before
  // measuring. Measuring the raw length undercounts a folded key and can
  // report a 2048-bit key as too short.
  const pMatch = /(?:^|[;\s])p=([^;]*)/i.exec(record);
  if (!pMatch) return { keyType: k };
  const p = pMatch[1].replace(/\s+/g, "");
  if (p.length === 0) return { keyType: k, revoked: true };
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

    // If the resolver never answered, an empty answer list means "unknown", not
    // "absent". Reporting "no SPF record" from a network failure is a fabricated
    // finding, and four of them used to fire at once here. Bail out with the
    // honest verdict instead.
    const resolverFailed = [mxRes, txtRes, dmarcRes, mtaStsRes, bimiRes].some((r) => r.failed);
    if (resolverFailed) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The DNS resolver did not answer, so the mail records could not be read.",
        findings: [],
        data: { spf: null, dmarc: null, dkim: [], mx: [], mtaSts: null, bimi: null, nullMx: false },
        source: "Google and Cloudflare DNS over HTTPS",
        ms: Math.round(performance.now() - started),
      };
    }

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

    // RFC 8461 §3 requires both halves: the TXT record announces the policy and
    // the HTTPS file states the mode. A TXT record alone protects nothing, so
    // the file is fetched and its mode read rather than inferring enforcement
    // from the record's presence.
    //
    // The fetch goes through the reader because the policy file is served from
    // mta-sts.<domain>, a different origin that sends no CORS header, so a
    // direct browser request would fail for every site and the check would
    // report "no policy file" universally.
    let mtaStsFileOk = false;
    let mtaStsMode: string | null = null;
    if (mtaStsTxt) {
      const policyRes = await ctx.net.text(
        `https://r.jina.ai/https://mta-sts.${domain}/.well-known/mta-sts.txt`,
        {
          timeoutMs: 20_000,
          cacheKey: `mtasts:${domain}`,
          headers: { "x-respond-with": "text", "x-no-cache": "true" },
        }
      );
      if (policyRes.ok) {
        const body = policyRes.text.toLowerCase();
        if (body.includes("version: stsv1")) {
          mtaStsFileOk = true;
          mtaStsMode = /mode\s*:\s*([a-z]+)/.exec(body)?.[1] ?? null;
        }
      }
    }

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
    //
    // Every selector is queried. The old code took the first 12, which silently
    // made the remaining provider selectors unreachable: a site signing as
    // `protonmail3` or `hostingermail-b` was reported as having no DKIM at all.
    // Each lookup is one DoH request and the resolver caches by name, so the
    // full list costs a second on a cold scan and nothing afterwards.
    const dkim = await Promise.all(
      DKIM_SELECTORS.map(async (selector) => {
        const res = await ctx.dns.query(`${selector}._domainkey.${domain}`, "TXT");
        const record = res.answers
          .filter((r) => r.type === 16)
          .map((r) => unquoteTxt(r.data))
          // Anchored on the version tag or a key tag at a tag boundary. The old
          // unanchored alternation accepted any TXT containing the text "p="
          // anywhere, which is not evidence of a DKIM key.
          .find((t) => /(?:^|;\s*)v=DKIM1\b/i.test(t) || /(?:^|;\s*)p=/i.test(t));
        return record
          ? { selector, present: true, ...dkimKeyInfo(record) }
          : { selector, present: false };
      })
    );
    const dkimFound = dkim.filter((d) => d.present && !d.revoked);

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
      // A redirect modifier hands evaluation to another domain, which is a
      // legitimate way to publish SPF for several domains from one record. The
      // all mechanism belongs to the record it redirects to, so its absence
      // here is not a defect and must not be reported as one.
      if (!spf.all && !spf.redirect) {
        findings.push({
          id: "email-spf-no-all",
          title: "SPF has no all mechanism",
          detail: "The record does not end with an all mechanism, so unauthorised senders get a neutral result instead of a fail.",
          severity: "medium",
          remediation: "End the record with -all (hard fail) or ~all (soft fail) while you validate the sender list.",
        });
      } else if (spf.all) {
        // A bare `all` carries an implicit `+` qualifier (RFC 7208 §4.6.2), so
        // the old test for a leading "+" missed the most dangerous record there
        // is: `v=spf1 all` authorises every host on the internet and produced no
        // finding at all. Normalise first, then branch on the qualifier alone.
        const allQualifier = /^[+\-~?]/.test(spf.all) ? spf.all[0] : "+";
        if (allQualifier === "?") {
          findings.push({
            id: "email-spf-neutral",
            title: "SPF ends in ?all, which asserts nothing",
            detail: "A neutral result tells receivers to make up their own mind, which is the same as having no policy for unauthorised senders.",
            severity: "medium",
            remediation: "Change ?all to -all once you are confident every legitimate sender is listed.",
          });
        } else if (allQualifier === "+") {
          const bare = spf.all === "all";
          findings.push({
            id: "email-spf-pass-all",
            title: bare
              ? "SPF ends in a bare all, which authorises every host"
              : "SPF ends in +all, which authorises every host on the internet",
            detail: bare
              ? "A bare all carries an implicit + qualifier, so it passes any sender. The record provides no protection and actively authorises forgery."
              : "+all passes any sender, so the record provides no protection and actively authorises forgery.",
            severity: "critical",
            remediation: "Change it to -all immediately.",
          });
        }
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
    // A revoked key (empty p=) is not a working key, so it is counted apart
    // from dkimFound. The old code counted it as found and said nothing.
    const dkimRevoked = dkim.filter((d) => d.present && d.revoked);
    if (dkimRevoked.length > 0) {
      findings.push({
        id: "email-dkim-revoked",
        title: "DKIM key has been revoked",
        detail: `${dkimRevoked.map((d) => d.selector).join(", ")} publish a _domainkey record with an empty p= tag. RFC 6376 defines that as a revoked key, so signatures made with it do not verify and mail sent under it fails DKIM.`,
        severity: "high",
        remediation:
          "If the key was retired deliberately, remove the record. If it was not, publish a fresh key at the selector your provider signs with.",
        reference: { label: "RFC 6376 §3.6.1", url: "https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.1" },
      });
    }
    if (dkimFound.length === 0) {
      findings.push({
        id: "email-dkim-unknown",
        title: "No DKIM key found on a common selector",
        detail: `None of the ${DKIM_SELECTORS.length} selectors checked returned a DKIM key. Either DKIM is not configured, or it uses a custom selector, which is legitimate but means this check cannot confirm it.`,
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
    } else if (mtaStsTxt && !mtaStsFileOk) {
      // The record exists but the policy file did not. RFC 8461 §3 makes both
      // mandatory, and senders that cannot fetch the file fall back to the
      // record's cached policy or to no policy at all, so this is not a
      // working deployment however the TXT record reads.
      findings.push({
        id: "email-mta-sts-no-file",
        title: "The MTA-STS TXT record is published but the policy file is not",
        detail: `_mta-sts.${domain} announces MTA-STS, but https://mta-sts.${domain}/.well-known/mta-sts.txt could not be read as an STS policy. Sending servers require both, so transport security is not in force.`,
        severity: "medium",
        remediation: `Serve a policy file at https://mta-sts.${domain}/.well-known/mta-sts.txt containing version: STSv1, mode: enforce, max_age: 604800 and an mx: line for each mail host.`,
        reference: { label: "RFC 8461 §3", url: "https://datatracker.ietf.org/doc/html/rfc8461#section-3" },
      });
    } else if (mtaStsTxt && mtaStsFileOk && mtaStsMode === "testing") {
      findings.push({
        id: "email-mta-sts-testing",
        title: "The MTA-STS policy is in testing mode",
        detail:
          "mode: testing reports TLS failures over SMTP but still delivers the mail. Nothing is protected until the mode is enforce.",
        severity: "low",
        remediation:
          "Read the TLS-RPT reports for a full week, then change mode: testing to mode: enforce.",
        reference: { label: "RFC 8461 §5", url: "https://datatracker.ietf.org/doc/html/rfc8461#section-5" },
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
        mtaSts: mtaStsTxt
          ? { dns: true, policy: mtaStsTxt, fileMode: mtaStsMode, fileOk: mtaStsFileOk }
          : null,
        bimi: bimiRaw ?? null,
        nullMx,
      } satisfies EmailData,
      ms: Math.round(performance.now() - started),
      source: "DNS-over-HTTPS TXT and MX records",
    };
  },
};
