"use client";

/**
 * The report, as boxes.
 *
 * The earlier version was a table with a column per fact, which forced a reader
 * to hold a header row in mind while scrolling and collapsed badly on a phone.
 * A box carries one check: its status rail, its title, one sentence, and the
 * findings behind a disclosure. Boxes reflow, so the same markup is a grid on a
 * desktop and a single column on a phone with no separate layout.
 *
 * The order is the order a person asks questions: what was scanned, how it did,
 * what is wrong, what each check found, where the answers came from.
 */

import { Download, Printer } from "lucide-react";
import type { CheckGroup, CheckResult, ScanReport } from "@/lib/types";
import { rankFindings } from "@/lib/scan/score";
import { GROUP_LABEL, GROUP_ORDER, groupOf } from "@/lib/checks";
import { CheckDetail, FindingRow, statusLabel, statusTone } from "./check-detail";
import { CheckFacts } from "./check-facts";
import { ScoreRing } from "./score-ring";

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

/**
 * A check's own elapsed time.
 *
 * Several checks read a document or header set that another check already
 * fetched, so they finish in under a millisecond and printed "0 ms", which
 * reads as a broken measurement rather than as the reuse it is. The time is
 * truthful; the label was not. Anything this fast did no waiting of its own,
 * so it says so.
 */
function formatMs(ms: number): string {
  if (ms < 2) return "reused a fetch";
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
            fontSize: 21,
            fontWeight: 600,
            letterSpacing: "-0.01em",
            overflowWrap: "anywhere",
          }}
        >
          {report.target.host}
        </h2>
        <div className="box__meta" style={{ marginTop: 10 }}>
          <span className="mono" style={{ overflowWrap: "anywhere" }}>
            {report.target.url}
          </span>
          <span className="tabular">{formatDuration(report.durationMs)}</span>
          <span>{formatDate(report.finishedAt)}</span>
        </div>
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
      className="box box--raised rise"
      aria-labelledby="verdict-heading"
      style={{ marginTop: 14, padding: "20px 22px" }}
    >
      <div className="flex flex-wrap items-center gap-x-7 gap-y-5">
        <ScoreRing score={report.score} grade={report.grade} tone={tone} />
        <div style={{ flex: "1 1 260px", minWidth: 0 }}>
          <h3 id="verdict-heading" className="eyebrow">
            Verdict
          </h3>
          <p style={{ marginTop: 6, fontSize: 18, fontWeight: 560, letterSpacing: "-0.01em" }}>
            {verdictFor(report.score)}
          </p>
          <p style={{ marginTop: 8, fontSize: 13.5, color: "var(--muted-foreground)" }}>
            Weighted across the {scored} of {total} checks that ran. A check that could not run
            is excluded rather than counted as a pass
            {unavailable > 0
              ? `, so this score rests on ${scored} checks and a re-run may move it either way`
              : ""}
            .
          </p>
        </div>
      </div>
    </section>
  );
}

const COUNT_TILES = [
  { key: "pass", tone: "tone-pass" },
  { key: "warn", tone: "tone-warn" },
  { key: "fail", tone: "tone-fail" },
  { key: "unavailable", tone: "tone-idle" },
] as const;

function CountTiles({ report }: { report: ScanReport }) {
  const total = Math.max(1, report.checks.length);
  const extra = report.counts.info + report.counts.skipped;

  return (
    <section aria-label="Check status counts" style={{ marginTop: 12 }}>
      <ul className="box-grid">
        {COUNT_TILES.map((tile, index) => {
          const value = report.counts[tile.key];
          return (
            <li
              key={tile.key}
              className={`box rise ${tile.tone}`}
              style={{ ["--i" as string]: index, padding: "13px 15px" }}
            >
              <div className="box__head">
                <span className="dot" aria-hidden="true" />
                <span
                  className="box__title"
                  style={{ fontSize: 12.5, fontWeight: 560, letterSpacing: "0.02em" }}
                >
                  {statusLabel(tile.key)}
                </span>
              </div>
              <div className="stat" style={{ marginTop: 8 }}>
                {value}
              </div>
              <div className="meter" style={{ marginTop: 10 }}>
                <div
                  className="meter__fill"
                  style={{ width: `${Math.round((value / total) * 100)}%` }}
                />
              </div>
            </li>
          );
        })}
      </ul>
      {extra > 0 && (
        <p style={{ marginTop: 8, fontSize: 12.5, color: "var(--muted-foreground)" }}>
          {report.counts.info > 0
            ? `${report.counts.info} informational`
            : ""}
          {report.counts.info > 0 && report.counts.skipped > 0 ? " and " : ""}
          {report.counts.skipped > 0 ? `${report.counts.skipped} skipped` : ""}{" "}
          {extra === 1 ? "check is" : "checks are"} not counted in the four boxes above.
        </p>
      )}
    </section>
  );
}

function FindingsSection({ report }: { report: ScanReport }) {
  const ranked = rankFindings(report.checks);
  const aboveInfo = ranked.filter((entry) => entry.finding.severity !== "info");

  return (
    <section aria-labelledby="findings-heading" style={{ marginTop: 30 }}>
      <div className="flex items-baseline justify-between gap-4">
        <h3 id="findings-heading" style={{ fontSize: 18 }}>
          Findings
        </h3>
        <span className="tabular" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
          {ranked.length} total
        </span>
      </div>

      {aboveInfo.length === 0 ? (
        <p style={{ marginTop: 8, fontSize: 14, color: "var(--muted-foreground)" }}>
          No findings above informational severity. Everything the checks could measure is either
          clean or noted below.
        </p>
      ) : null}

      {ranked.length > 0 && (
        <ul
          className="divide-y divide-border"
          style={{ marginTop: 8, listStyle: "none", padding: 0 }}
        >
          {ranked.map(({ check, finding }) => (
            <FindingRow key={`${check.id}-${finding.id}`} finding={finding} />
          ))}
        </ul>
      )}
    </section>
  );
}

function CheckBox({ result, index }: { result: CheckResult; index: number }) {
  const expandable = result.findings.length > 0;
  const tone = statusTone(result.status);

  return (
    <li
      className={`box box--railed rise ${tone}`}
      style={{ ["--i" as string]: Math.min(index, 12) }}
    >
      <div className="box__head">
        <span className="dot" aria-hidden="true" />
        <span className="box__title">{result.title}</span>
      </div>
      <p className="box__body">{result.headline}</p>

      <CheckFacts result={result} />

      {result.note && (
        <p className="box__body" style={{ fontSize: 12.5, marginTop: 6 }}>
          <span className="mono">Note:</span> {result.note}
        </p>
      )}

      {expandable && <CheckDetail result={result} />}

      <div className="box__meta">
        <span className="mono" style={{ overflowWrap: "anywhere" }}>
          {result.source}
        </span>
        <span className="tabular">{formatMs(result.ms)}</span>
      </div>
    </li>
  );
}

function ChecksByGroup({ report }: { report: ScanReport }) {
  const byGroup = new Map<CheckGroup, CheckResult[]>();
  for (const result of report.checks) {
    const group = groupFor(result);
    if (!group) continue;
    const list = byGroup.get(group) ?? [];
    list.push(result);
    byGroup.set(group, list);
  }
  const ungrouped = report.checks.filter((result) => groupFor(result) === null);

  const sections: Array<{ key: string; label: string; results: CheckResult[] }> = [];
  for (const group of GROUP_ORDER) {
    const results = byGroup.get(group);
    if (results && results.length > 0) {
      sections.push({ key: group, label: GROUP_LABEL[group], results });
    }
  }
  if (ungrouped.length > 0) {
    sections.push({ key: "other", label: "Other", results: ungrouped });
  }

  return (
    <section aria-labelledby="checks-heading" style={{ marginTop: 30 }}>
      <h3 id="checks-heading" style={{ fontSize: 18 }}>
        Check by check
      </h3>
      <p style={{ marginTop: 6, fontSize: 13.5, color: "var(--muted-foreground)" }}>
        Every check that ran, grouped by what it looks at. A check marked unavailable is still
        listed, with the reason it could not complete.
      </p>

      {sections.map((section) => (
        <section key={section.key} style={{ marginTop: 20 }} aria-label={section.label}>
          <div className="flex flex-wrap items-baseline justify-between gap-3">
            <h4 style={{ fontSize: 13.5, fontWeight: 600, letterSpacing: "-0.005em" }}>
              {section.label}
            </h4>
            <span className="tabular" style={{ fontSize: 12, color: "var(--muted-foreground)" }}>
              {section.results.length}
            </span>
          </div>
          <ul className="box-grid" style={{ marginTop: 10 }}>
            {section.results.map((result, index) => (
              <CheckBox key={result.id} result={result} index={index} />
            ))}
          </ul>
        </section>
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
    <section aria-labelledby="provenance-heading" style={{ marginTop: 30 }}>
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
        Every value in this report was read from a public source, queried directly from your
        browser. Nothing was sent to a server owned by this site. A check marked{" "}
        <span className="tone-idle">unavailable</span> means the source could not be reached or
        refused the request. It does not mean the check passed.
      </p>
      {sources.length > 0 ? (
        <ul className="flex flex-wrap gap-2" style={{ marginTop: 12, listStyle: "none", padding: 0 }}>
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
      <div className="box" style={{ padding: "18px 20px" }}>
        <HeaderRow report={report} />
      </div>
      <Verdict report={report} />
      <CountTiles report={report} />
      <FindingsSection report={report} />
      <ChecksByGroup report={report} />
      <Provenance report={report} />
    </article>
  );
}
