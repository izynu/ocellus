/**
 * The report as a document, for paper and PDF.
 *
 * The screen report is boxes, glass and disclosures. None of those survive a
 * printer well: a disclosure prints closed, a frosted panel prints grey, and an
 * animated ring prints as a still frame that may be captured mid-draw. So the
 * printed report is its own component, built for a sheet. It is not a
 * re-skin of the screen view: it carries a cover, an executive summary, the
 * findings grouped by category, a full appendix of every check, and a
 * provenance block, because a printed report is read away from the screen
 * where it was produced.
 *
 * It renders from the same `ScanReport` the screen report renders from, so the
 * two can never disagree about a value. It is mounted alongside the screen
 * report and hidden by `src/app/print.css` on screen, then shown and the screen
 * report hidden when printing. Nothing here is interactive: no buttons, no
 * disclosures, no state.
 */

import type { CheckGroup, CheckResult, Finding, ScanReport, Severity } from "@/lib/types";
import { rankFindings } from "@/lib/scan/score";
import { GROUP_LABEL, GROUP_ORDER, groupOf } from "@/lib/checks";
import { SEVERITY_META, statusLabel } from "./check-detail";

/* ----------------------------------------------------------------- helpers -- */

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
  return date.toLocaleString("en-GB", {
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

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/* ------------------------------------------------------------------- facts -- */

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
  if (typeof value === "number") {
    return Number.isFinite(value) ? value.toLocaleString("en-US") : "not reported";
  }
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

/* ------------------------------------------------------------------ grouping -- */

type FindingEntry = { check: CheckResult; finding: Finding };
type FindingGroup = { group: CheckGroup | "other"; entries: FindingEntry[] };

function groupFindings(report: ScanReport): FindingGroup[] {
  const buckets = new Map<CheckGroup | "other", FindingEntry[]>();

  for (const entry of rankFindings(report.checks)) {
    const group = GROUP_BY_ID.get(entry.check.id) ?? "other";
    const list = buckets.get(group);
    if (list) list.push(entry);
    else buckets.set(group, [entry]);
  }

  for (const list of buckets.values()) {
    list.sort(
      (a, b) =>
        SEVERITY_ORDER[a.finding.severity] - SEVERITY_ORDER[b.finding.severity] ||
        a.finding.id.localeCompare(b.finding.id)
    );
  }

  const ordered: FindingGroup[] = [];
  for (const group of GROUP_ORDER) {
    const entries = buckets.get(group);
    if (entries) ordered.push({ group, entries });
  }
  const other = buckets.get("other");
  if (other) ordered.push({ group: "other", entries: other });
  return ordered;
}

/** "3 critical, 1 medium, 2 low", in severity order. */
function severitySummary(entries: FindingEntry[]): string {
  return SEVERITY_BANDS.flatMap((severity) => {
    const count = entries.filter((entry) => entry.finding.severity === severity).length;
    return count > 0 ? [`${count} ${severity}`] : [];
  }).join(", ");
}

function groupLabel(group: CheckGroup | "other"): string {
  return group === "other" ? "Other" : GROUP_LABEL[group];
}

/** Checks bucketed by category, in report order, with any unregistered result last. */
function checksByGroup(report: ScanReport): Array<{ group: CheckGroup | "other"; results: CheckResult[] }> {
  const byGroup = new Map<CheckGroup, CheckResult[]>();
  for (const result of report.checks) {
    const group = GROUP_BY_ID.get(result.id);
    if (!group) continue;
    const list = byGroup.get(group);
    if (list) list.push(result);
    else byGroup.set(group, [result]);
  }

  const ordered: Array<{ group: CheckGroup | "other"; results: CheckResult[] }> = [];
  for (const group of GROUP_ORDER) {
    const results = byGroup.get(group);
    if (results && results.length > 0) ordered.push({ group, results });
  }
  const other = report.checks.filter((result) => !GROUP_BY_ID.has(result.id));
  if (other.length > 0) ordered.push({ group: "other", results: other });
  return ordered;
}

/** Check ids that carry at least one finding, per category, for the summary table. */
function categoryStats(report: ScanReport) {
  const groups = checksByGroup(report);
  const findings = groupFindings(report);
  const findingCounts = new Map<string, number>();
  for (const section of findings) {
    findingCounts.set(section.group, section.entries.length);
  }

  return groups.map(({ group, results }) => {
    const counts = { pass: 0, warn: 0, fail: 0, other: 0 };
    for (const result of results) {
      if (result.status === "pass") counts.pass++;
      else if (result.status === "warn") counts.warn++;
      else if (result.status === "fail") counts.fail++;
      else counts.other++;
    }
    return {
      group,
      checks: results.length,
      findings: findingCounts.get(group) ?? 0,
      counts,
    };
  });
}

/* -------------------------------------------------------------------- parts -- */

function Cover({ report }: { report: ScanReport }) {
  const total = report.checks.length;
  const excluded = report.counts.unavailable + report.counts.skipped;
  const scored = Math.max(0, Math.min(total, total - excluded));
  const contents = [
    "Executive summary",
    "Findings by category",
    "Check by check",
    "Provenance",
  ];

  return (
    <header className="print-cover">
      <p className="print-cover__product">Ocellus</p>
      <p className="print-cover__kind">Website audit report</p>

      <h1 className="print-cover__host">{report.target.host}</h1>

      <div className="print-score">
        <span className="print-score__number">{report.score}</span>
        <span className="print-score__of">/100</span>
        <span className="print-score__grade">Grade {report.grade}</span>
      </div>

      <p className="print-verdict">{verdictFor(report.score)}</p>

      <dl className="print-cover__meta">
        <dt>Scanned address</dt>
        <dd className="mono">{report.target.url}</dd>
        <dt>Started</dt>
        <dd>{formatDate(report.startedAt)}</dd>
        <dt>Finished</dt>
        <dd>{formatDate(report.finishedAt)}</dd>
        <dt>Duration</dt>
        <dd>{formatDuration(report.durationMs)}</dd>
        <dt>Checks run</dt>
        <dd>{total}</dd>
        <dt>Checks scored</dt>
        <dd>
          {scored} of {total} ({excluded} not scored)
        </dd>
      </dl>

      <div className="print-contents">
        <p className="print-contents__title">Contents</p>
        <ol>
          {contents.map((entry) => (
            <li key={entry}>{entry}</li>
          ))}
        </ol>
      </div>
    </header>
  );
}

function ExecutiveSummary({ report }: { report: ScanReport }) {
  const total = report.checks.length;
  const excluded = report.counts.unavailable + report.counts.skipped;
  const scored = Math.max(0, Math.min(total, total - excluded));
  const findingsTotal = groupFindings(report).reduce(
    (sum, section) => sum + section.entries.length,
    0
  );

  const statusRows: Array<{ label: string; value: number; note: string }> = [
    { label: "Pass", value: report.counts.pass, note: "ran and met the rule" },
    { label: "Warn", value: report.counts.warn, note: "ran, something to fix" },
    { label: "Fail", value: report.counts.fail, note: "ran, serious problem" },
    { label: "Info", value: report.counts.info, note: "ran, neutral observation" },
    { label: "Unavailable", value: report.counts.unavailable, note: "source did not answer" },
    { label: "Skipped", value: report.counts.skipped, note: "does not apply here" },
  ];

  const stats = categoryStats(report);

  return (
    <section className="print-section">
      <h2>Executive summary</h2>

      <p className="print-lead">
        {report.target.host} scored {report.score} out of 100, grade {report.grade}.{" "}
        {verdictFor(report.score)}
      </p>

      <h3>Outcome by status</h3>
      <table className="print-table">
        <thead>
          <tr>
            <th scope="col">Status</th>
            <th scope="col" className="num">
              Checks
            </th>
            <th scope="col">What it means</th>
          </tr>
        </thead>
        <tbody>
          {statusRows.map((row) => (
            <tr key={row.label}>
              <th scope="row">{row.label}</th>
              <td className="num">{row.value.toLocaleString("en-US")}</td>
              <td className="muted">{row.note}</td>
            </tr>
          ))}
          <tr className="print-table__total">
            <th scope="row">Total checks</th>
            <td className="num">{total.toLocaleString("en-US")}</td>
            <td className="muted">
              {scored} scored, {excluded} excluded from the grade
            </td>
          </tr>
        </tbody>
      </table>

      <h3>Outcome by category</h3>
      <table className="print-table print-table--category">
        <thead>
          <tr>
            <th scope="col">Category</th>
            <th scope="col" className="num">
              Checks
            </th>
            <th scope="col" className="num">
              Findings
            </th>
            <th scope="col" className="num">
              Pass / Warn / Fail
            </th>
            <th scope="col" className="num">
              Other
            </th>
          </tr>
        </thead>
        <tbody>
          {stats.map((row) => (
            <tr key={row.group}>
              <th scope="row">{groupLabel(row.group)}</th>
              <td className="num">{row.checks}</td>
              <td className="num">{row.findings}</td>
              <td className="num">
                {row.counts.pass} / {row.counts.warn} / {row.counts.fail}
              </td>
              <td className="num">{row.counts.other}</td>
            </tr>
          ))}
          <tr className="print-table__total">
            <th scope="row">All categories</th>
            <td className="num">{total}</td>
            <td className="num">{findingsTotal}</td>
            <td className="num">
              {report.counts.pass} / {report.counts.warn} / {report.counts.fail}
            </td>
            <td className="num">
              {report.counts.info + report.counts.unavailable + report.counts.skipped}
            </td>
          </tr>
        </tbody>
      </table>

      <div className="print-callout">
        <p className="print-callout__title">Unavailable is not a pass</p>
        <p>
          The grade is computed over {scored} of {total} checks. A check whose source could not
          be reached or refused the request is removed from the denominator rather than counted
          as a pass, so the score describes what could be measured rather than what happened to
          answer. Re-running the scan may move the score in either direction.
        </p>
      </div>
    </section>
  );
}

function FindingArticle({ entry }: { entry: FindingEntry }) {
  const { check, finding } = entry;

  // The severity is stated once, in the band heading above this article, and
  // repeated only as the 3pt rail. Printing the word on every card as well
  // made a three-item band read as three separate pronouncements.
  return (
    <article className={`print-finding print-finding--${finding.severity}`}>
      <h4 className="print-finding__title">{finding.title}</h4>

      <p className="print-finding__detail">{finding.detail}</p>

      {finding.remediation && (
        <p className="print-finding__fix">
          <span className="print-finding__label">How to fix: </span>
          {finding.remediation}
        </p>
      )}

      {finding.reference && /^https?:\/\//i.test(finding.reference.url) && (
        <p className="print-finding__ref">
          <span className="print-finding__label">Reference: </span>
          {finding.reference.label}
          <br />
          <span className="mono">{finding.reference.url}</span>
        </p>
      )}

      {finding.evidence && finding.evidence.length > 0 && (
        <table className="print-kv">
          <caption className="print-kv__caption">Evidence</caption>
          <tbody>
            {finding.evidence.map((row, index) => (
              <tr key={`${row.label}-${index}`}>
                <th scope="row">{row.label}</th>
                <td>
                  {row.value}
                  {row.detail ? ` (${row.detail})` : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <p className="print-finding__check">Check: {check.title}</p>
    </article>
  );
}

function Findings({ report }: { report: ScanReport }) {
  const sections = groupFindings(report);
  const total = sections.reduce((sum, section) => sum + section.entries.length, 0);

  return (
    <section className="print-section">
      <h2>Findings by category</h2>

      {total === 0 ? (
        <p>
          No findings were reported. Every check that ran found nothing it considered worth
          noting.
        </p>
      ) : (
        <>
          <p className="print-lead">
            {total} finding{total === 1 ? "" : "s"}, grouped by the part of the site each one
            concerns. Within a category the list runs from the most severe down.
          </p>

          {sections.map((section) => {
            const bands = SEVERITY_BANDS.map((severity) => ({
              severity,
              entries: section.entries.filter((entry) => entry.finding.severity === severity),
            })).filter((band) => band.entries.length > 0);

            return (
              <div key={section.group} className="print-category">
                <h3 className="print-category__title">{groupLabel(section.group)}</h3>
                <p className="print-category__count">
                  {section.entries.length} finding{section.entries.length === 1 ? "" : "s"} (
                  {severitySummary(section.entries)})
                </p>
                {bands.map((band) => (
                  <div key={band.severity} className="print-band">
                    <h4 className="print-band__title">
                      {SEVERITY_META[band.severity].label}
                      <span className="print-band__count"> ({band.entries.length})</span>
                    </h4>
                    {band.entries.map((entry) => (
                      <FindingArticle
                        key={`${entry.check.id}-${entry.finding.id}`}
                        entry={entry}
                      />
                    ))}
                  </div>
                ))}
              </div>
            );
          })}
        </>
      )}
    </section>
  );
}

function CheckBlock({ result }: { result: CheckResult }) {
  const facts = factsFor(result.data).slice(0, 10);

  return (
    <article className={`print-check print-check--${result.status}`}>
      <div className="print-check__head">
        <span className="print-check__title">{result.title}</span>
        <span className="print-check__status">{statusLabel(result.status)}</span>
      </div>
      <p className="print-check__headline">{result.headline}</p>
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
  const sections = checksByGroup(report);

  return (
    <section className="print-section">
      <h2>Check by check</h2>
      <p className="print-lead">
        Every check that ran, grouped by what it looks at, with up to ten measured facts, any
        note, and the source each answer came from. A check marked Unavailable is kept, with the
        reason it could not complete.
      </p>

      {sections.map((section) => (
        <div key={section.group} className="print-appendix-group">
          <h3>{groupLabel(section.group)}</h3>
          {section.results.map((result) => (
            <CheckBlock key={result.id} result={result} />
          ))}
        </div>
      ))}
    </section>
  );
}

function Provenance({ report }: { report: ScanReport }) {
  const sources = Array.from(
    new Set(
      report.checks.map((check) => check.source).filter((source) => source && source !== "none")
    )
  ).sort((a, b) => a.localeCompare(b));

  return (
    <footer className="print-footer print-section">
      <h2>Provenance</h2>
      <p>
        Every value in this report was read from a public source, queried directly from the
        browser that ran the scan. Nothing was uploaded to a server owned by Ocellus. A check
        marked Unavailable means the source could not be reached or refused the request; it does
        not mean the check passed, and it is excluded from the grade rather than counted as one.
      </p>

      {sources.length > 0 ? (
        <>
          <h3>Sources consulted</h3>
          <ul className="print-sources">
            {sources.map((source) => (
              <li key={source} className="mono">
                {source}
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p>No public source was reachable during this scan.</p>
      )}

      <p>
        This report is a set of automated observations of public data at one moment. It is not a
        security assessment, a penetration test, or professional advice. A clean result means
        the checks that ran found nothing they look for, not that the site is secure.
      </p>

      <p className="print-footer__stamp">
        Report {report.id} · Generated {formatDate(report.finishedAt)} · Ocellus, browser-side
        website audit
      </p>
    </footer>
  );
}

/* -------------------------------------------------------------------- entry -- */

/**
 * The full report as a printed document. Hidden on screen by `print.css` and
 * shown when printing; the screen report is hidden in the same media query.
 */
export function PrintReport({ report }: { report: ScanReport }) {
  return (
    <div className="print-doc" aria-hidden="true">
      <Cover report={report} />
      <ExecutiveSummary report={report} />
      <Findings report={report} />
      <Appendix report={report} />
      <Provenance report={report} />
    </div>
  );
}
