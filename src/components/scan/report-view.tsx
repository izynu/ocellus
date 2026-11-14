"use client";

/**
 * The report.
 *
 * This is the surface a non-expert reads, so it is built in the order a person
 * asks questions: what was scanned, how did it do, what is wrong, what did each
 * check find, and where did the answers come from. Nothing here is decorative.
 *
 * The only interaction is disclosure: findings and per-check rows expand in
 * place. Every expander is a `<button>` with `aria-expanded` and `aria-controls`,
 * so the whole report is usable from the keyboard.
 */

import { Download, Printer } from "lucide-react";
import type { CheckGroup, CheckResult, ScanReport } from "@/lib/types";
import { rankFindings } from "@/lib/scan/score";
import { GROUP_LABEL, GROUP_ORDER, groupOf } from "@/lib/checks";
import { CheckDetail, FindingRow, statusLabel, statusTone } from "./check-detail";

/** Plain-English reading of the score. Bands match the published grade cut-offs. */
function verdictFor(score: number): string {
  if (score >= 90) return "No significant problems found.";
  if (score >= 78) return "Mostly sound, with a few things to fix.";
  if (score >= 64) return "Several problems worth fixing.";
  if (score >= 50) return "Real problems that affect visitors or trust.";
  return "Serious problems in more than one area.";
}

function verdictTone(score: number): string {
  if (score >= 78) return "tone-pass";
  if (score >= 50) return "tone-warn";
  return "tone-fail";
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function formatDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatMs(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms)} ms`;
}

/** Host to a safe filename fragment. */
function fileHost(host: string): string {
  return host.replace(/[^a-z0-9.-]+/gi, "-").replace(/^-+|-+$/g, "") || "site";
}

/** Check id to group, built once from the registry rather than per row. */
const GROUP_BY_ID = new Map<string, CheckGroup>();
for (const group of GROUP_ORDER) {
  for (const definition of groupOf(group)) GROUP_BY_ID.set(definition.id, group);
}

function groupFor(result: CheckResult): CheckGroup | null {
  return GROUP_BY_ID.get(result.id) ?? null;
}

function exportJson(report: ScanReport): void {
  const date = report.finishedAt.slice(0, 10);
  const name = `ocellus-${fileHost(report.target.host)}-${date}.json`;
  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  // Give the browser a tick to start the download before dropping the blob.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/* ------------------------------------------------------------------ parts -- */

function HeaderRow({ report }: { report: ScanReport }) {
  return (
    <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div style={{ minWidth: 0 }}>
        <p className="eyebrow">Scan report</p>
        <h2
          className="mono"
          style={{
            marginTop: 6,
            fontSize: 22,
            fontWeight: 600,
            letterSpacing: "-0.01em",
            overflowWrap: "anywhere",
          }}
        >
          {report.target.host}
        </h2>
        <dl
          style={{
            marginTop: 10,
            display: "grid",
            gridTemplateColumns: "auto minmax(0, 1fr)",
            gap: "3px 12px",
            fontSize: 13,
            color: "var(--muted-foreground)",
          }}
        >
          <dt>Final URL</dt>
          <dd className="mono" style={{ margin: 0, overflowWrap: "anywhere" }}>
            {report.target.url}
          </dd>
          <dt>Duration</dt>
          <dd className="tabular" style={{ margin: 0 }}>
            {formatDuration(report.durationMs)}
          </dd>
          <dt>Date</dt>
          <dd style={{ margin: 0 }}>{formatDate(report.finishedAt)}</dd>
        </dl>
      </div>

      <div className="flex flex-none flex-wrap gap-2">
        <button
          type="button"
          className="btn btn-quiet btn-sm"
          onClick={() => exportJson(report)}
        >
          <Download size={15} aria-hidden="true" />
          Export JSON
        </button>
        <button
          type="button"
          className="btn btn-quiet btn-sm"
          onClick={() => window.print()}
        >
          <Printer size={15} aria-hidden="true" />
          Print
        </button>
      </div>
    </header>
  );
}

function Verdict({ report }: { report: ScanReport }) {
  const tone = verdictTone(report.score);
  const total = report.checks.length;
  const unavailable = report.counts.unavailable + report.counts.skipped;
  const scored = total - unavailable;
  return (
    <section
      className="sheet sheet--raised"
      aria-labelledby="verdict-heading"
      style={{ padding: "20px 22px", marginTop: 18 }}
    >
      <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
        <div>
          <h3 id="verdict-heading" className="eyebrow">
            Score
          </h3>
          <div className="flex items-baseline gap-3" style={{ marginTop: 2 }}>
            <span
              className={`tabular ${tone}`}
              style={{ fontSize: 56, fontWeight: 600, lineHeight: 1 }}
            >
              {report.score}
            </span>
            <span
              style={{
                fontSize: 15,
                color: "var(--muted-foreground)",
                paddingBottom: 4,
              }}
            >
              out of 100
            </span>
            <span
              className="chip"
              style={{ marginBottom: 8, fontSize: 13, height: 28, paddingInline: 11 }}
            >
              Grade {report.grade}
            </span>
          </div>
        </div>
        <p style={{ flex: "1 1 260px", fontSize: 17, fontWeight: 520, minWidth: 0 }}>
          {verdictFor(report.score)}
          {unavailable > 0 ? ` ${unavailable === 1 ? "One check" : `${unavailable} checks`} did not run, so this is a partial picture.` : ""}
        </p>
      </div>
      <p style={{ marginTop: 12, fontSize: 13, color: "var(--muted-foreground)" }}>
        Weighted across the {scored} of {total} checks that ran. Checks that
        could not run are excluded, not counted as passes
        {unavailable > 0
          ? `, so this score rests on ${scored} of ${total} checks and a re-run may move it either way`
          : ""}
        .
      </p>
    </section>
  );
}

function CountTiles({ report }: { report: ScanReport }) {
  const tiles = [
    { key: "pass", tone: "tone-pass" },
    { key: "warn", tone: "tone-warn" },
    { key: "fail", tone: "tone-fail" },
    { key: "unavailable", tone: "tone-idle" },
  ] as const;
  const extra = report.counts.info + report.counts.skipped;
  const extraParts: string[] = [];
  if (report.counts.info > 0) {
    extraParts.push(`${report.counts.info} informational`);
  }
  if (report.counts.skipped > 0) {
    extraParts.push(`${report.counts.skipped} skipped`);
  }

  return (
    <section aria-label="Check status counts" style={{ marginTop: 14 }}>
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
        {tiles.map((tile) => (
          <div
            key={tile.key}
            className="sheet"
            style={{ padding: "12px 14px", minWidth: 0 }}
          >
            <div className="flex items-center gap-2" style={{ minWidth: 0 }}>
              <span className={`dot ${tile.tone}`} aria-hidden="true" />
              <span
                className="truncate-1"
                style={{ fontSize: 12, color: "var(--muted-foreground)" }}
              >
                {statusLabel(tile.key)}
              </span>
            </div>
            <div
              className="tabular"
              style={{ marginTop: 4, fontSize: 26, fontWeight: 600, lineHeight: 1.1 }}
            >
              {report.counts[tile.key]}
            </div>
          </div>
        ))}
      </div>
      {extra > 0 && (
        <p style={{ marginTop: 8, fontSize: 12.5, color: "var(--muted-foreground)" }}>
          {extraParts.join(" and ")} checks are not counted in the four tiles above.
        </p>
      )}
    </section>
  );
}

function FindingsSection({ report }: { report: ScanReport }) {
  const ranked = rankFindings(report.checks);
  const aboveInfo = ranked.filter((entry) => entry.finding.severity !== "info");

  return (
    <section aria-labelledby="findings-heading" style={{ marginTop: 34 }}>
      <div className="flex items-baseline justify-between gap-4">
        <h3 id="findings-heading" style={{ fontSize: 19 }}>
          Findings
        </h3>
        <span
          className="tabular"
          style={{ fontSize: 13, color: "var(--muted-foreground)" }}
        >
          {ranked.length} total
        </span>
      </div>

      {aboveInfo.length === 0 ? (
        <p
          style={{
            marginTop: 10,
            fontSize: 14,
            color: "var(--muted-foreground)",
          }}
        >
          No findings above informational severity. Everything the checks could
          measure is either clean or noted below.
        </p>
      ) : null}

      {ranked.length > 0 && (
        <ul
          className="divide-y divide-border"
          style={{ marginTop: 10, listStyle: "none", padding: 0 }}
        >
          {ranked.map(({ check, finding }) => (
            <FindingRow key={`${check.id}-${finding.id}`} finding={finding} />
          ))}
        </ul>
      )}
    </section>
  );
}

function CheckRow({ result }: { result: CheckResult }) {
  const expandable = result.findings.length > 0;
  const deEmphasised = result.status === "unavailable" || result.status === "skipped";
  const tone = statusTone(result.status);

  return (
    <>
      <tr
        style={{
          borderTop: "1px solid color-mix(in oklab, var(--border) 70%, transparent)",
          opacity: deEmphasised ? 0.78 : 1,
        }}
      >
        <td style={{ padding: "11px 8px 11px 0", verticalAlign: "top", width: 16 }}>
          <span
            className={`dot ${tone}`}
            role="img"
            aria-label={statusLabel(result.status)}
            style={{ marginTop: 7 }}
          />
        </td>
        <td style={{ padding: "11px 12px 11px 0", verticalAlign: "top", minWidth: 0 }}>
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span style={{ fontSize: 14.5, fontWeight: 560 }}>{result.title}</span>
            <span
              className={tone}
              style={{ fontSize: 11.5, fontWeight: 560, letterSpacing: "0.02em" }}
            >
              {statusLabel(result.status)}
            </span>
          </div>
          <p
            style={{
              marginTop: 3,
              fontSize: 13.5,
              color: "var(--muted-foreground)",
              overflowWrap: "anywhere",
            }}
          >
            {result.headline}
          </p>
          {result.note && (
            <p
              style={{
                marginTop: 4,
                fontSize: 12.5,
                color: "var(--muted-foreground)",
                overflowWrap: "anywhere",
              }}
            >
              <span className="mono">Note:</span> {result.note}
            </p>
          )}
          {/* The narrow layout has no source or time columns, so they repeat here. */}
          <div
            className="flex flex-wrap gap-x-3 gap-y-0.5 md:hidden"
            style={{ marginTop: 4, fontSize: 12, color: "var(--muted-foreground)" }}
          >
            <span className="mono" style={{ overflowWrap: "anywhere" }}>
              {result.source}
            </span>
            <span className="tabular">{formatMs(result.ms)}</span>
          </div>
        </td>
        <td
          className="mono hidden md:table-cell"
          style={{
            padding: "11px 12px 11px 0",
            verticalAlign: "top",
            fontSize: 12.5,
            color: "var(--muted-foreground)",
            overflowWrap: "anywhere",
          }}
        >
          {result.source}
        </td>
        <td
          className="tabular hidden md:table-cell"
          style={{
            padding: "11px 0",
            verticalAlign: "top",
            fontSize: 12.5,
            color: "var(--muted-foreground)",
            textAlign: "right",
            whiteSpace: "nowrap",
            width: 72,
          }}
        >
          {formatMs(result.ms)}
        </td>
      </tr>
      {expandable && (
        <tr>
          <td />
          <td colSpan={3} style={{ padding: "0 0 10px" }}>
            <CheckDetail result={result} />
          </td>
        </tr>
      )}
    </>
  );
}

function ChecksTable({ report }: { report: ScanReport }) {
  const byGroup = new Map<CheckGroup, CheckResult[]>();
  for (const result of report.checks) {
    const group = groupFor(result);
    if (!group) continue;
    const list = byGroup.get(group) ?? [];
    list.push(result);
    byGroup.set(group, list);
  }
  const ungrouped = report.checks.filter((result) => groupFor(result) === null);

  return (
    <section aria-labelledby="checks-heading" style={{ marginTop: 34 }}>
      <h3 id="checks-heading" style={{ fontSize: 19 }}>
        Check by check
      </h3>
      <p
        style={{
          marginTop: 6,
          fontSize: 13.5,
          color: "var(--muted-foreground)",
        }}
      >
        Every check that ran, grouped by what it looks at. A check marked
        unavailable is still listed with the reason it could not complete.
      </p>

      <div className="sheet" style={{ marginTop: 12, padding: "4px 16px 12px" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <caption className="sr-only">
            Each check, its status, headline, data source and run time.
          </caption>
          <thead>
            <tr>
              <th scope="col" className="sr-only">
                Status
              </th>
              <th
                scope="col"
                style={{
                  textAlign: "left",
                  padding: "12px 12px 8px 0",
                  fontSize: 11.5,
                  fontWeight: 600,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  color: "var(--muted-foreground)",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                Check
              </th>
              <th
                scope="col"
                className="hidden md:table-cell"
                style={{
                  textAlign: "left",
                  padding: "12px 12px 8px 0",
                  fontSize: 11.5,
                  fontWeight: 600,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  color: "var(--muted-foreground)",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                Source
              </th>
              <th
                scope="col"
                className="hidden md:table-cell"
                style={{
                  textAlign: "right",
                  padding: "12px 0 8px",
                  fontSize: 11.5,
                  fontWeight: 600,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  color: "var(--muted-foreground)",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                Time
              </th>
            </tr>
          </thead>

          {GROUP_ORDER.map((group) => {
            const results = byGroup.get(group);
            if (!results || results.length === 0) return null;
            return (
              <tbody key={group}>
                <tr>
                  <th
                    scope="colgroup"
                    colSpan={4}
                    style={{
                      textAlign: "left",
                      padding: "16px 0 4px",
                      fontSize: 12,
                      fontWeight: 600,
                      letterSpacing: "0.07em",
                      textTransform: "uppercase",
                      color: "var(--muted-foreground)",
                    }}
                  >
                    {GROUP_LABEL[group]}
                  </th>
                </tr>
                {results.map((result) => (
                  <CheckRow key={result.id} result={result} />
                ))}
              </tbody>
            );
          })}

          {ungrouped.length > 0 && (
            <tbody>
              <tr>
                <th
                  scope="colgroup"
                  colSpan={4}
                  style={{
                    textAlign: "left",
                    padding: "16px 0 4px",
                    fontSize: 12,
                    fontWeight: 600,
                    letterSpacing: "0.07em",
                    textTransform: "uppercase",
                    color: "var(--muted-foreground)",
                  }}
                >
                  Other
                </th>
              </tr>
              {ungrouped.map((result) => (
                <CheckRow key={result.id} result={result} />
              ))}
            </tbody>
          )}
        </table>
      </div>
    </section>
  );
}

function Provenance({ report }: { report: ScanReport }) {
  const sources = Array.from(
    new Set(
      report.checks
        .map((check) => check.source)
        .filter((source) => source && source !== "none")
    )
  ).sort((a, b) => a.localeCompare(b));

  return (
    <section aria-labelledby="provenance-heading" style={{ marginTop: 34 }}>
      <h3 id="provenance-heading" style={{ fontSize: 16 }}>
        Where this came from
      </h3>
      <p
        style={{
          marginTop: 8,
          fontSize: 13.5,
          color: "var(--muted-foreground)",
          maxWidth: "72ch",
        }}
      >
        Every value in this report was read from a public source, queried
        directly from your browser. Nothing was sent to a server owned by this
        site. A check marked <span className="tone-idle">unavailable</span> means
        the source could not be reached or refused the request. It does not mean
        the check passed.
      </p>
      {sources.length > 0 ? (
        <ul
          className="flex flex-wrap gap-2"
          style={{ marginTop: 12, listStyle: "none", padding: 0 }}
        >
          {sources.map((source) => (
            <li key={source}>
              <span className="chip chip--wrap mono">{source}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p style={{ marginTop: 12, fontSize: 13, color: "var(--muted-foreground)" }}>
          No public source was reachable during this scan.
        </p>
      )}
    </section>
  );
}

/* ------------------------------------------------------------------ entry -- */

export function ReportView({ report }: { report: ScanReport }) {
  return (
    <article className="rise" aria-label={`Report for ${report.target.host}`}>
      <div className="sheet" style={{ padding: "20px 22px" }}>
        <HeaderRow report={report} />
      </div>
      <Verdict report={report} />
      <CountTiles report={report} />
      <FindingsSection report={report} />
      <ChecksTable report={report} />
      <Provenance report={report} />
    </article>
  );
}
