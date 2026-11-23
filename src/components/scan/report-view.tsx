"use client";

/**
 * The report, as boxes.
 *
 * The screen report answers five questions in the order a person asks them:
 * what was scanned, how it did, how much of it could be measured, what is
 * wrong, and what each individual check found. The sixth block states where
 * every value came from.
 *
 * Findings are never pooled into one ranked list. A mixed list puts a
 * certificate note beside a cookie note and asks a reader to hold both in mind
 * at once. Here every finding lives under the category it came from, inside a
 * collapsible section, with a severity count for that category and a filter
 * above the list. A reader can answer "is anything wrong with the email
 * setup?" without reading everything else on the page.
 */

import { useEffect, useId, useState } from "react";
import { Check, ChevronDown, Copy, Download, Printer } from "lucide-react";
import type { CheckGroup, CheckResult, Finding, ScanReport, Severity } from "@/lib/types";
import { rankFindings } from "@/lib/scan/score";
import { GROUP_LABEL, GROUP_ORDER, groupOf } from "@/lib/checks";
import {
  CheckDetail,
  FindingRow,
  SEVERITY_META,
  statusLabel,
  statusTone,
} from "./check-detail";
import { CheckFacts } from "./check-facts";
import { ScoreRing } from "./score-ring";
import { PrintReport } from "./print-report";

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

/* --------------------------------------------------------------- findings -- */

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_BANDS: Severity[] = ["critical", "high", "medium", "low", "info"];

type FindingEntry = { check: CheckResult; finding: Finding };

type GroupedFindings = { group: CheckGroup; entries: FindingEntry[] };

/**
 * Every finding, bucketed by category.
 *
 * `rankFindings` supplies the report-wide ranking; inside a category the list
 * is sorted by severity and then by finding id, so the same report always
 * prints in the same order and two runs can be compared line by line.
 */
function groupFindings(report: ScanReport): GroupedFindings[] {
  const buckets = new Map<CheckGroup, FindingEntry[]>();

  for (const entry of rankFindings(report.checks)) {
    const group = GROUP_BY_ID.get(entry.check.id);
    if (!group) continue;
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

  return GROUP_ORDER.filter((group) => buckets.has(group)).map((group) => ({
    group,
    entries: buckets.get(group)!,
  }));
}

/** "3 critical, 1 medium, 2 low", in severity order. */
function severitySummary(entries: FindingEntry[]): string {
  return SEVERITY_BANDS.flatMap((severity) => {
    const count = entries.filter((entry) => entry.finding.severity === severity).length;
    return count > 0 ? [`${count} ${severity}`] : [];
  }).join(", ");
}

/* ----------------------------------------------------------------- export -- */

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

/**
 * The summary a person pastes into a ticket or a chat.
 *
 * Plain text, no markdown, because the destination is unknown. It carries the
 * score, the grade, the counts and the five worst findings, and it says how
 * many checks produced the score, so the number is never quoted without the
 * caveat that belongs to it.
 */
function summaryText(report: ScanReport): string {
  const ranked = rankFindings(report.checks).slice(0, 5);
  const excluded = report.counts.unavailable + report.counts.skipped;
  const scored = report.checks.length - excluded;

  const lines = [
    `Ocellus report for ${report.target.host}`,
    `Scanned ${report.target.url}`,
    `Finished ${formatDate(report.finishedAt)} in ${formatDuration(report.durationMs)}`,
    `Score ${report.score} of 100, grade ${report.grade} (${scored} of ${report.checks.length} checks scored)`,
    `Pass ${report.counts.pass}, warn ${report.counts.warn}, fail ${report.counts.fail}, unavailable ${report.counts.unavailable}, info ${report.counts.info}, skipped ${report.counts.skipped}`,
  ];

  if (ranked.length === 0) {
    lines.push("No findings were reported.");
  } else {
    lines.push("Top findings:");
    ranked.forEach((entry, index) => {
      lines.push(
        `${index + 1}. [${SEVERITY_META[entry.finding.severity].label}] ${entry.finding.title} (${entry.check.title})`
      );
    });
  }

  return lines.join("\n");
}

/**
 * Clipboard write with a fallback.
 *
 * `navigator.clipboard` needs a secure context and a transient user gesture.
 * A static export can be opened from `file://`, where it does not exist at
 * all, so the old selection copy is the fallback rather than an error message
 * about the browser.
 */
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall through to the selection-based path.
  }

  try {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.top = "-1000px";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(area);
    return copied;
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ parts -- */

function HeaderRow({ report }: { report: ScanReport }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  // The label returns to its resting state on its own, so the control never
  // claims something that stopped being true two minutes ago.
  useEffect(() => {
    if (copyState === "idle") return;
    const timer = setTimeout(() => setCopyState("idle"), 2400);
    return () => clearTimeout(timer);
  }, [copyState]);

  const onCopy = async () => {
    const ok = await copyText(summaryText(report));
    setCopyState(ok ? "copied" : "failed");
  };

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
          title="Opens the print dialog. Choose Save as PDF there to keep a copy, or print to paper."
        >
          <Printer size={15} aria-hidden="true" />
          Export PDF
        </button>
        <button
          type="button"
          className="btn btn-quiet btn-sm"
          onClick={onCopy}
          title="Copies the score, the counts and the five worst findings as plain text."
        >
          {copyState === "copied" ? (
            <Check size={15} aria-hidden="true" />
          ) : (
            <Copy size={15} aria-hidden="true" />
          )}
          {copyState === "copied" ? "Copied" : copyState === "failed" ? "Copy failed" : "Copy summary"}
        </button>
        <span className="sr-only" role="status" aria-live="polite">
          {copyState === "copied"
            ? "Summary copied to the clipboard."
            : copyState === "failed"
              ? "The clipboard was not available. Select the report text instead."
              : ""}
        </span>
      </div>
    </header>
  );
}

function Verdict({ report }: { report: ScanReport }) {
  const tone = verdictTone(report.score);
  const total = report.checks.length;
  const excluded = report.counts.unavailable + report.counts.skipped;
  const scored = Math.max(0, Math.min(total, total - excluded));

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
            Scored over {scored} of {total} checks. A check that could not run is excluded rather
            than counted as a pass.
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
          {report.counts.info > 0 ? `${report.counts.info} informational` : ""}
          {report.counts.info > 0 && report.counts.skipped > 0 ? " and " : ""}
          {report.counts.skipped > 0 ? `${report.counts.skipped} skipped` : ""}{" "}
          {extra === 1 ? "check is" : "checks are"} not counted in the four boxes above.
        </p>
      )}
    </section>
  );
}

function FindingsGroupSection({
  group,
  entries,
}: {
  group: CheckGroup;
  entries: FindingEntry[];
}) {
  const [open, setOpen] = useState(true);
  const panelId = useId();

  return (
    <section className={`area-${group}`} style={{ marginTop: 20 }} aria-label={GROUP_LABEL[group]}>
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h4 className="area-head" style={{ margin: 0, fontSize: 14.5 }}>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            aria-expanded={open}
            aria-controls={panelId}
            onClick={() => setOpen((value) => !value)}
            style={{
              paddingInline: 0,
              height: 30,
              gap: 9,
              fontSize: 14.5,
              fontWeight: 600,
              color: "var(--foreground)",
            }}
          >
            <span className="dot" aria-hidden="true" />
            {GROUP_LABEL[group]}
            <ChevronDown
              size={15}
              aria-hidden="true"
              style={{
                color: "var(--muted-foreground)",
                transform: open ? "rotate(180deg)" : "none",
                transition: "transform 160ms ease",
              }}
            />
          </button>
        </h4>
        <span className="tabular" style={{ fontSize: 12, color: "var(--muted-foreground)" }}>
          {entries.length} finding{entries.length === 1 ? "" : "s"}
        </span>
      </div>

      <p style={{ marginTop: 2, fontSize: 12.5, color: "var(--muted-foreground)" }}>
        {severitySummary(entries)}
      </p>

      <div id={panelId} hidden={!open}>
        <ul className="divide-y divide-border" style={{ marginTop: 4, listStyle: "none", padding: 0 }}>
          {entries.map(({ check, finding }) => (
            <FindingRow key={`${check.id}-${finding.id}`} finding={finding} />
          ))}
        </ul>
      </div>
    </section>
  );
}

function FindingsSection({ report }: { report: ScanReport }) {
  const sections = groupFindings(report);
  const [filter, setFilter] = useState<CheckGroup | "all">("all");
  const total = sections.reduce((sum, section) => sum + section.entries.length, 0);
  const visible = filter === "all" ? sections : sections.filter((section) => section.group === filter);

  return (
    <section aria-labelledby="findings-heading" style={{ marginTop: 30 }}>
      <div className="flex items-baseline justify-between gap-4">
        <h3 id="findings-heading" style={{ fontSize: 18 }}>
          Findings
        </h3>
        <span className="tabular" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
          {total} total
        </span>
      </div>

      {total === 0 ? (
        <p style={{ marginTop: 8, fontSize: 14, color: "var(--muted-foreground)" }}>
          No findings were reported. Every check that ran found nothing it considered worth
          noting.
        </p>
      ) : (
        <>
          <p style={{ marginTop: 6, fontSize: 13.5, color: "var(--muted-foreground)" }}>
            Grouped by the part of the site they concern, never into one mixed list. Use the
            filter to read a single category.
          </p>

          <div
            className="flex flex-wrap gap-2"
            role="group"
            aria-label="Filter findings by category"
            style={{ marginTop: 12 }}
          >
            <button
              type="button"
              className={`btn btn-sm ${filter === "all" ? "btn-quiet" : "btn-ghost"}`}
              aria-pressed={filter === "all"}
              onClick={() => setFilter("all")}
              style={filter === "all" ? { fontWeight: 600 } : undefined}
            >
              All <span className="tabular">{total}</span>
            </button>
            {sections.map((section) => {
              const active = filter === section.group;
              return (
                <button
                  key={section.group}
                  type="button"
                  className={`btn btn-sm ${active ? "btn-quiet" : "btn-ghost"}`}
                  aria-pressed={active}
                  onClick={() => setFilter(section.group)}
                  style={active ? { fontWeight: 600 } : undefined}
                >
                  {GROUP_LABEL[section.group]} <span className="tabular">{section.entries.length}</span>
                </button>
              );
            })}
          </div>

          {visible.map((section) => (
            <FindingsGroupSection
              key={section.group}
              group={section.group}
              entries={section.entries}
            />
          ))}
        </>
      )}
    </section>
  );
}

function CheckBox({ result, index }: { result: CheckResult; index: number }) {
  const expandable = result.findings.length > 0;
  const tone = statusTone(result.status);

  return (
    <li
      className={`box box--area rise ${tone}`}
      style={{ ["--i" as string]: Math.min(index, 12) }}
    >
      <div className="box__head">
        <span className="dot" aria-hidden="true" />
        <span className="box__title">{result.title}</span>
        {/* The status was carried by the rail colour alone, which a reader
            with colour blindness or a greyscale print cannot recover. The word
            states it, and the colour only reinforces it. */}
        <span className={`chip ${tone}`} style={{ marginLeft: "auto", flex: "none" }}>
          {statusLabel(result.status)}
        </span>
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
        <section
          key={section.key}
          className={section.key === "other" ? undefined : `area-${section.key}`}
          style={{ marginTop: 20 }}
          aria-label={section.label}
        >
          <div className="flex flex-wrap items-baseline justify-between gap-3">
            <div className="area-head">
              <span className="dot" aria-hidden="true" />
              <h4 style={{ fontSize: 13.5, fontWeight: 600, letterSpacing: "-0.005em" }}>
                {section.label}
              </h4>
            </div>
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
    <>
      <article className="screen-doc rise" aria-label={`Report for ${report.target.host}`}>
        <div className="box" style={{ padding: "18px 20px" }}>
          <HeaderRow report={report} />
        </div>
        <Verdict report={report} />
        <CountTiles report={report} />
        <FindingsSection report={report} />
        <ChecksByGroup report={report} />
        <Provenance report={report} />
      </article>
      {/*
       * The paper version of the same report. It is in the DOM so the browser
       * has it when the print dialog opens; `print.css` hides one and shows the
       * other by media, so the screen tree above is untouched on a display.
       */}
      <PrintReport report={report} />
    </>
  );
}
