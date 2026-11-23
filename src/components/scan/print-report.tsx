/**
 * The report as a document, for paper and PDF.
 *
 * The screen report is boxes, glass and disclosures. None of those survive a
 * printer well: a disclosure prints closed, a frosted panel prints grey, and an
 * animated ring prints as a still frame that may be captured mid-draw. So the
 * printed report is its own component, built for a sheet: a cover, a summary
 * table, findings grouped by severity, an appendix of every check, and a
 * provenance footer.
 *
 * It renders from the same `ScanReport` the screen report renders from, so the
 * two can never disagree about a value. It is mounted alongside the screen
 * report and hidden by `src/app/print.css` on screen, then shown and the screen
 * report hidden when printing. Nothing here is interactive: no buttons, no
 * disclosures, no state.
 */

import type { CheckGroup, CheckResult, ScanReport, Severity } from "@/lib/types";
import { rankFindings } from "@/lib/scan/score";
import { GROUP_LABEL, GROUP_ORDER, groupOf } from "@/lib/checks";
import { SEVERITY_META } from "./check-detail";

/** Plain-English reading of the score. Bands match the published cut-offs. */
function verdictFor(score: number): string {
  if (score >= 90) return "No significant problems found.";
  if (score >= 78) return "Mostly sound, with a few things to fix.";
  if (score >= 64) return "Several problems worth fixing.";
  if (score >= 50) return "Real problems that affect visitors or trust.";
  return "Serious problems in more than one area.";
}

function formatDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} seconds`;
}

/** Check id to group, built once from the registry. */
const GROUP_BY_ID = new Map<string, CheckGroup>();
for (const group of GROUP_ORDER) {
  for (const definition of groupOf(group)) GROUP_BY_ID.set(definition.id, group);
}

const SEVERITY_BANDS: Severity[] = ["critical", "high", "medium", "low", "info"];

/* --------------------------------------------------------------- facts ---- */

type FactRow = { label: string; value: string };

/**
 * The initialisms that appear as payload keys, mapped to their proper casing.
 * Without this, a key like `dnssecValidated` became "Dnssec Validated" and
 * `spf` became "Spf", which reads as a typo rather than as an abbreviation.
 */
const ACRONYMS: Record<string, string> = {
  dns: "DNS",
  dnssec: "DNSSEC",
  spf: "SPF",
  dkim: "DKIM",
  dmarc: "DMARC",
  tls: "TLS",
  ssl: "SSL",
  http: "HTTP",
  https: "HTTPS",
  ip: "IP",
  ipv4: "IPv4",
  ipv6: "IPv6",
  asn: "ASN",
  csp: "CSP",
  hsts: "HSTS",
  mta: "MTA",
  sts: "STS",
  caa: "CAA",
  ct: "CT",
  url: "URL",
  urls: "URLs",
  seo: "SEO",
  dom: "DOM",
  sri: "SRI",
  cdn: "CDN",
  cve: "CVE",
  cves: "CVEs",
  kev: "KEV",
  epss: "EPSS",
  otx: "OTX",
  mx: "MX",
  ptr: "PTR",
  srv: "SRV",
  txt: "TXT",
  ns: "NS",
  soa: "SOA",
  og: "OG",
};

/** camelCase or snake_case key to a readable label. */
function labelFor(key: string): string {
  return key
    .replace(/[_-]+/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(" ")
    .filter(Boolean)
    .map((word) => {
      const lower = word.toLowerCase();
      if (ACRONYMS[lower]) return ACRONYMS[lower];
      return word.replace(/^./, (char) => char.toUpperCase());
    })
    .join(" ");
}

function isPrimitive(value: unknown): boolean {
  return (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  );
}

function primitiveText(value: unknown): string {
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "number") return Number.isFinite(value) ? value.toLocaleString("en-US") : "not reported";
  const text = String(value).trim();
  return text.length > 160 ? `${text.slice(0, 157)}...` : text;
}

/**
 * A value from a check's payload as one line of text, or null when it would say
 * nothing useful. This is deliberately shallow: it reads primitives, a list of
 * primitives, and one level of an object whose fields are primitives. Anything
 * deeper is counted rather than expanded, because an appendix is not the place
 * for a nested tree.
 */
function describeValue(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (isPrimitive(value)) {
    const text = primitiveText(value);
    return text ? text : null;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return "none";
    if (value.every((item) => isPrimitive(item) || item === null)) {
      const items = value.filter((item) => item !== null).map(primitiveText);
      if (items.length === 0) return null;
      const shown = items.slice(0, 4);
      return items.length > shown.length
        ? `${shown.join(", ")} and ${items.length - shown.length} more`
        : shown.join(", ");
    }
    return `${value.length} item${value.length === 1 ? "" : "s"}`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    const primitives = entries.filter(([, item]) => isPrimitive(item));
    if (primitives.length === 0) return null;
    const shown = primitives
      .slice(0, 3)
      .map(([key, item]) => `${labelFor(key)}: ${primitiveText(item)}`);
    return primitives.length > shown.length
      ? `${shown.join(", ")}, and ${primitives.length - shown.length} more`
      : shown.join(", ");
  }
  return null;
}

/** The key values behind a check, capped so the appendix stays readable. */
function factsFor(data: unknown): FactRow[] {
  if (!data || typeof data !== "object" || Array.isArray(data)) return [];
  const rows: FactRow[] = [];
  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    if (rows.length >= 10) break;
    const described = describeValue(value);
    if (described) rows.push({ label: labelFor(key), value: described });
  }
  return rows;
}

/* ----------------------------------------------------------------- parts -- */

function Cover({ report }: { report: ScanReport }) {
  const total = report.checks.length;
  const excluded = report.counts.unavailable + report.counts.skipped;
  const scored = total - excluded;

  return (
    <header className="print-cover">
      <p className="muted" style={{ fontSize: "9pt", letterSpacing: "0.08em", textTransform: "uppercase" }}>
        Ocellus website audit
      </p>
      <hr className="print-cover__rule" />
      <h1>{report.target.host}</h1>
      <p className="muted" style={{ fontSize: "11pt" }}>
        A browser-side audit of one hostname, measured from public sources.
      </p>

      <dl className="print-cover__meta">
        <dt>Scanned address</dt>
        <dd className="mono">{report.target.url}</dd>
        <dt>Finished</dt>
        <dd>{formatDate(report.finishedAt)}</dd>
        <dt>Started</dt>
        <dd>{formatDate(report.startedAt)}</dd>
        <dt>Duration</dt>
        <dd>{formatDuration(report.durationMs)}</dd>
        <dt>Checks</dt>
        <dd>
          {scored} of {total} scored, {excluded} not scored
        </dd>
      </dl>

      <div className="print-score">
        <span className="print-score__number">{report.score}</span>
        <span className="print-score__grade">Grade {report.grade}</span>
      </div>
      <p className="print-verdict">{verdictFor(report.score)}</p>
    </header>
  );
}

function Summary({ report }: { report: ScanReport }) {
  const total = report.checks.length;
  const excluded = report.counts.unavailable + report.counts.skipped;
  const scored = total - excluded;

  const rows: Array<{ label: string; value: number }> = [
    { label: "Pass", value: report.counts.pass },
    { label: "Warn", value: report.counts.warn },
    { label: "Fail", value: report.counts.fail },
    { label: "Info", value: report.counts.info },
    { label: "Unavailable", value: report.counts.unavailable },
    { label: "Skipped", value: report.counts.skipped },
  ];

  return (
    <section className="print-section">
      <h2>Summary</h2>
      <table className="print-table">
        <tbody>
          {rows.map((row) => (
            <tr key={row.label}>
              <th scope="row">{row.label}</th>
              <td className="num">{row.value.toLocaleString("en-US")}</td>
            </tr>
          ))}
          <tr>
            <th scope="row">Scored in the grade</th>
            <td className="num">{scored.toLocaleString("en-US")}</td>
          </tr>
        </tbody>
      </table>
      <p>
        {scored} of {total} checks produced a verdict and form the grade. A check that could not
        run is not counted as a pass, so this report states how much of the picture it covers.
      </p>
    </section>
  );
}

function Findings({ report }: { report: ScanReport }) {
  const ranked = rankFindings(report.checks);

  if (ranked.length === 0) {
    return (
      <section className="print-section">
        <h2>Findings</h2>
        <p>No findings were reported. Every check that ran found nothing it considered worth noting.</p>
      </section>
    );
  }

  // Band, then group, then the finding. The order is what a reader acts on
  // first: the worst severity, then which part of the site it touches.
  const byBand = new Map<Severity, Map<string, typeof ranked>>();
  for (const entry of ranked) {
    const band = byBand.get(entry.finding.severity) ?? new Map<string, typeof ranked>();
    byBand.set(entry.finding.severity, band);
    const group = GROUP_BY_ID.get(entry.check.id);
    const label = group ? GROUP_LABEL[group] : "Other";
    const list = band.get(label) ?? [];
    list.push(entry);
    band.set(label, list);
  }

  return (
    <section>
      <h2>Findings</h2>
      <p className="muted">
        {ranked.length} finding{ranked.length === 1 ? "" : "s"}, most severe first, then by the
        part of the site each touches.
      </p>

      {SEVERITY_BANDS.map((band) => {
        const groups = byBand.get(band);
        if (!groups) return null;
        const count = [...groups.values()].reduce((sum, list) => sum + list.length, 0);
        return (
          <div key={band} className="print-section">
            <h3>
              {SEVERITY_META[band].label} ({count})
            </h3>
            {[...groups.entries()].map(([label, list]) => (
              <div key={label}>
                <h4>{label}</h4>
                {list.map(({ check, finding }) => (
                  <article key={`${check.id}-${finding.id}`} className="print-finding">
                    <p style={{ fontWeight: 600 }}>{finding.title}</p>
                    <p>{finding.detail}</p>
                    {finding.remediation && (
                      <p>
                        <span style={{ fontWeight: 600 }}>How to fix: </span>
                        {finding.remediation}
                      </p>
                    )}
                    {finding.reference && /^https?:\/\//i.test(finding.reference.url) && (
                      <p className="muted">
                        Reference:{" "}
                        <a href={finding.reference.url} rel="noopener noreferrer" target="_blank">
                          {finding.reference.label}
                        </a>
                      </p>
                    )}
                    {finding.evidence && finding.evidence.length > 0 && (
                      <table className="print-kv">
                        <tbody>
                          {finding.evidence.map((row, index) => (
                            <tr key={`${row.label}-${index}`}>
                              <th scope="row">{row.label}</th>
                              <td>
                                {row.value}
                                {row.detail ? ` ${row.detail}` : ""}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                    <p className="muted" style={{ fontSize: "8.5pt" }}>
                      Check: {check.title}
                    </p>
                  </article>
                ))}
              </div>
            ))}
          </div>
        );
      })}
    </section>
  );
}

function CheckBlock({ result }: { result: CheckResult }) {
  const facts = factsFor(result.data);
  const status = result.status;

  return (
    <article className={`print-check print-check--${status}`}>
      <div className="print-check__head">
        <span className="print-check__title">{result.title}</span>
        <span className="print-check__status">{status}</span>
      </div>
      <p style={{ marginTop: "2pt", fontSize: "9.5pt" }}>{result.headline}</p>
      {facts.length > 0 && (
        <table className="print-kv">
          <tbody>
            {facts.map((row, index) => (
              <tr key={`${row.label}-${index}`}>
                <th scope="row">{row.label}</th>
                <td>{row.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {result.note && <p className="print-note">Note: {result.note}</p>}
      <p className="print-check__source">
        Source: {result.source === "none" ? "not reported" : result.source}
      </p>
    </article>
  );
}

function Appendix({ report }: { report: ScanReport }) {
  const byGroup = new Map<CheckGroup, CheckResult[]>();
  for (const result of report.checks) {
    const group = GROUP_BY_ID.get(result.id);
    if (!group) continue;
    const list = byGroup.get(group) ?? [];
    list.push(result);
    byGroup.set(group, list);
  }

  const sections = GROUP_ORDER.map((group) => ({ group, results: byGroup.get(group) ?? [] })).filter(
    (section) => section.results.length > 0
  );

  return (
    <section>
      <h2>Check by check</h2>
      <p className="muted">
        Every check that ran, grouped by what it looks at. A check marked unavailable is kept, with
        the reason it could not complete.
      </p>
      {sections.map((section) => (
        <div key={section.group} className="print-section">
          <h3>{GROUP_LABEL[section.group]}</h3>
          {section.results.map((result) => (
            <CheckBlock key={result.id} result={result} />
          ))}
        </div>
      ))}
    </section>
  );
}

function Footer({ report }: { report: ScanReport }) {
  const sources = Array.from(
    new Set(
      report.checks.map((check) => check.source).filter((source) => source && source !== "none")
    )
  ).sort((a, b) => a.localeCompare(b));

  return (
    <footer className="print-footer print-section">
      <p style={{ fontWeight: 600 }}>Where this came from</p>
      <p>
        Every value in this report was read from a public source, queried directly from the
        browser that ran the scan. A check marked unavailable means the source could not be
        reached; it does not mean the check passed, and it is excluded from the grade rather than
        counted as one.
      </p>
      {sources.length > 0 && (
        <p>
          <span style={{ fontWeight: 600 }}>Sources: </span>
          {sources.join("; ")}
        </p>
      )}
      <p>
        This report is a set of automated observations of public data at one moment. It is not a
        security assessment, a penetration test, or professional advice. A clean result means the
        checks that ran found nothing they look for, not that the site is secure.
      </p>
    </footer>
  );
}

/* ----------------------------------------------------------------- entry -- */

/**
 * The full report as a printed document. Hidden on screen by `print.css` and
 * shown when printing; the screen report is hidden in the same media query.
 */
export function PrintReport({ report }: { report: ScanReport }) {
  return (
    <div className="print-doc" aria-hidden="true">
      <Cover report={report} />
      <Summary report={report} />
      <Findings report={report} />
      <Appendix report={report} />
      <Footer report={report} />
    </div>
  );
}
