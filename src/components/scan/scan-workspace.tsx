"use client";

/**
 * The whole scan flow on one page.
 *
 * Three states: idle, running, done. The running state is the product: results
 * land one at a time so the user watches real checks resolve rather than a
 * spinner. The done state hands off to `ReportView`.
 *
 * Status language is taught where it is first met. Before a scan the legend
 * spells out what each of the six statuses means and which two leave the score
 * denominator. While a scan runs the arriving cards are grouped by status, so a
 * failure is never buried under a run of passes. After a scan the same six
 * statuses become a summary strip and a filter over the check list, with every
 * count computed from the results that actually came back.
 *
 * Deep linking: `?url=` is read from `window.location.search` in an effect
 * rather than `useSearchParams`, because static export would otherwise require
 * a Suspense boundary around the whole page for no benefit.
 */

import { useCallback, useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import { InvalidTarget } from "@/lib/target";
import {
  loadReport,
  runScan,
  saveReport,
  type ProgressEvent,
} from "@/lib/scan/runner";
import type { CheckResult, CheckStatus, ScanReport } from "@/lib/types";
import { GROUP_LABEL, GROUP_ORDER, checks } from "@/lib/checks";
import { statusLabel, statusTone } from "./check-detail";
import { ReportView } from "./report-view";
import { KeyPanel } from "./key-panel";

type Phase = "idle" | "running" | "done";

type StatusFilterValue = CheckStatus | "all";

/**
 * The one place the status wording lives.
 *
 * The meanings are the product's definition of the status language, not helper
 * text for this page alone, so every view that teaches or filters by status
 * reads them from here. Order is the order a reader meets them: the three
 * verdicts, the observation, then the two that do not score.
 */
const STATUS_LEGEND: ReadonlyArray<{ status: CheckStatus; meaning: string }> = [
  { status: "pass", meaning: "The source answered and the rule was met." },
  { status: "warn", meaning: "Something worth fixing, not severe on its own." },
  { status: "fail", meaning: "The rule was broken." },
  { status: "info", meaning: "An observation, not a judgement." },
  {
    status: "unavailable",
    meaning: "The source could not be reached. Excluded from the score, never a pass.",
  },
  { status: "skipped", meaning: "Does not apply here. Also excluded from the score." },
];

/** The four statuses that carry a verdict. Info and skipped do not score. */
const VERDICT_STATUSES: ReadonlyArray<CheckStatus> = [
  "pass",
  "warn",
  "fail",
  "unavailable",
];

/** Failures first while a scan streams, so the worst news is never below the fold. */
const RUN_ORDER: ReadonlyArray<CheckStatus> = [
  "fail",
  "warn",
  "pass",
  "info",
  "unavailable",
  "skipped",
];

function countByStatus(results: readonly CheckResult[]): Record<CheckStatus, number> {
  const counts: Record<CheckStatus, number> = {
    pass: 0,
    warn: 0,
    fail: 0,
    info: 0,
    unavailable: 0,
    skipped: 0,
  };
  for (const result of results) counts[result.status] += 1;
  return counts;
}

function formatSeconds(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} seconds`;
}

/* ----------------------------------------------------------------- legend -- */

/**
 * What the six statuses mean.
 *
 * Expanded before a scan, when a reader has no results to attach the words to
 * yet. After a scan it mounts collapsed and can be reopened, because by then
 * the results themselves are the thing to read.
 */
function StatusLegend({
  collapsible = false,
  defaultOpen = true,
}: {
  collapsible?: boolean;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();

  return (
    <section
      className="box box--raised"
      aria-labelledby="status-legend-heading"
      style={{ marginTop: 16 }}
    >
      <div className="box--row">
        <div className="box__main">
          <h2 id="status-legend-heading" className="box__title" style={{ fontSize: 15 }}>
            What the statuses mean
          </h2>
          <p className="box__body" style={{ maxWidth: "68ch" }}>
            Every check ends in one of six states. Four of them score. Two record what could not be
            measured, and never stand in for a pass.
          </p>
        </div>
        {collapsible && (
          <div className="box__aside">
            <button
              type="button"
              className="btn btn-quiet btn-sm"
              aria-expanded={open}
              aria-controls={panelId}
              onClick={() => setOpen((value) => !value)}
            >
              {open ? "Hide" : "Show"}
            </button>
          </div>
        )}
      </div>

      <div id={panelId} hidden={collapsible && !open} style={{ marginTop: 12 }}>
        <ul className="box-grid box-grid--dense" style={{ listStyle: "none", padding: 0 }}>
          {STATUS_LEGEND.map((entry) => {
            const tone = statusTone(entry.status);
            return (
              <li key={entry.status}>
                <div className="box__head">
                  <span className={`dot ${tone}`} aria-hidden="true" />
                  <span className="box__title" style={{ fontSize: 13 }}>
                    {statusLabel(entry.status)}
                  </span>
                </div>
                <p className="box__body" style={{ marginTop: 4, fontSize: 12.5 }}>
                  {entry.meaning}
                </p>
              </li>
            );
          })}
        </ul>

        <p className="box__meta" style={{ marginTop: 12 }}>
          Unavailable and skipped leave the score denominator. A check nobody could answer never
          counts as a pass.
        </p>
      </div>
    </section>
  );
}

/* ---------------------------------------------------------------- results -- */

/**
 * One check, as it appears while streaming and after the scan.
 *
 * The status is stated in words as well as carried by the rail and the dot, so
 * a reader who cannot separate the hues still gets the verdict.
 */
function ResultCard({ result }: { result: CheckResult }) {
  const tone = statusTone(result.status);
  return (
    <li className={`box box--railed land ${tone}`}>
      <div className="box__head">
        <span className="dot" role="img" aria-label={statusLabel(result.status)} />
        <span className="box__title">{result.title}</span>
        <span className={`chip ${tone}`} style={{ marginLeft: "auto", flex: "none" }}>
          {statusLabel(result.status)}
        </span>
      </div>
      <p className="box__body truncate-2">{result.headline}</p>
    </li>
  );
}

/** Six compact tiles, with the four scoring statuses stronger than the two that do not score. */
function StatusSummary({ counts }: { counts: Record<CheckStatus, number> }) {
  return (
    <section aria-label="Status counts for this scan" style={{ marginTop: 16 }}>
      <ul className="box-grid box-grid--dense" style={{ listStyle: "none", padding: 0 }}>
        {STATUS_LEGEND.map((entry, index) => {
          const tone = statusTone(entry.status);
          const strong = VERDICT_STATUSES.includes(entry.status);
          return (
            <li
              key={entry.status}
              className={`box rise ${strong ? `box--railed ${tone}` : "tone-idle"}`}
              title={entry.meaning}
              style={{ ["--i" as string]: index, padding: "12px 14px" }}
            >
              <div className="box__head">
                <span className={`dot ${tone}`} aria-hidden="true" />
                <span
                  className="box__title"
                  style={{ fontSize: 12.5, fontWeight: 560, letterSpacing: "0.02em" }}
                >
                  {statusLabel(entry.status)}
                </span>
                <span
                  className="stat tabular"
                  style={{
                    marginLeft: "auto",
                    fontSize: strong ? 26 : 21,
                    color: strong ? undefined : "var(--muted-foreground)",
                  }}
                >
                  {counts[entry.status]}
                </span>
              </div>
              <p className="box__body" style={{ marginTop: 4, fontSize: 11.5 }}>
                {entry.meaning}
              </p>
            </li>
          );
        })}
      </ul>
      <p className="box__meta" style={{ marginTop: 8 }}>
        Unavailable and skipped are excluded from the denominator, not counted as passes.
      </p>
    </section>
  );
}

/** The status filter. Counts come from the results that ran. */
function StatusFilter({
  counts,
  value,
  onChange,
}: {
  counts: Record<CheckStatus, number>;
  value: StatusFilterValue;
  onChange: (next: StatusFilterValue) => void;
}) {
  const total = STATUS_LEGEND.reduce((sum, entry) => sum + counts[entry.status], 0);

  return (
    <div
      className="scroller"
      role="group"
      aria-label="Filter checks by status"
      style={{ marginTop: 12 }}
    >
      <button
        type="button"
        className={`btn btn-sm ${value === "all" ? "btn-quiet" : "btn-ghost"}`}
        aria-pressed={value === "all"}
        onClick={() => onChange("all")}
        style={value === "all" ? { fontWeight: 600 } : undefined}
      >
        All <span className="tabular">{total}</span>
      </button>

      {STATUS_LEGEND.map((entry) => {
        const active = value === entry.status;
        return (
          <button
            key={entry.status}
            type="button"
            className={`btn btn-sm ${active ? "btn-quiet" : "btn-ghost"}`}
            aria-pressed={active}
            onClick={() => onChange(entry.status)}
            style={active ? { fontWeight: 600 } : undefined}
          >
            <span className={`dot ${statusTone(entry.status)}`} aria-hidden="true" />
            {statusLabel(entry.status)} <span className="tabular">{counts[entry.status]}</span>
          </button>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------ page -- */

export function ScanWorkspace() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<CheckResult[]>([]);
  const [progress, setProgress] = useState({ done: 0, total: checks.length });
  const [report, setReport] = useState<ScanReport | null>(null);
  const [previous, setPrevious] = useState<ScanReport | null>(null);
  const [filter, setFilter] = useState<StatusFilterValue>("all");

  /** Invalidates callbacks from an aborted or superseded run. */
  const runToken = useRef(0);
  const controllerRef = useRef<AbortController | null>(null);
  const booted = useRef(false);
  const resultsRef = useRef<HTMLElement | null>(null);

  const start = useCallback(async (raw: string) => {
    const value = raw.trim();
    if (!value) {
      setError("Enter a web address to scan.");
      return;
    }

    const token = ++runToken.current;
    const controller = new AbortController();
    controllerRef.current = controller;

    setError(null);
    setReport(null);
    setResults([]);
    setProgress({ done: 0, total: checks.length });
    setPrevious(null);
    setFilter("all");
    setPhase("running");

    let settled = false;
    try {
      const finished = await runScan(value, {
        signal: controller.signal,
        onProgress: (event: ProgressEvent) => {
          if (token !== runToken.current) return;
          if (event.kind === "start") {
            setProgress({ done: 0, total: event.total });
          } else if (event.kind === "check") {
            setProgress({ done: event.done, total: event.total });
            setResults((current) => [...current, event.result]);
          }
        },
      });

      if (token !== runToken.current) return;
      saveReport(finished);
      setReport(finished);
      setPhase("done");
      settled = true;
    } catch (err) {
      if (token !== runToken.current) return;
      if (err instanceof InvalidTarget) {
        setError(err.message);
      } else {
        setError(
          err instanceof Error && err.message
            ? err.message
            : "The scan could not run. Check the address and try again."
        );
      }
      setPhase("idle");
      settled = true;
    } finally {
      // The UI must never stay in the running state, whatever happened.
      if (!settled && token === runToken.current) {
        setPhase("idle");
        setError("The scan stopped before it finished.");
      }
      if (token === runToken.current) controllerRef.current = null;
    }
  }, []);

  const cancel = useCallback(() => {
    // Bump the token first so no in-flight callback can touch state afterwards.
    runToken.current += 1;
    controllerRef.current?.abort();
    controllerRef.current = null;
    setPhase("idle");
    setResults([]);
    setError(null);
    setFilter("all");
    setProgress({ done: 0, total: checks.length });
  }, []);

  const reset = useCallback(() => {
    runToken.current += 1;
    controllerRef.current?.abort();
    controllerRef.current = null;
    setPhase("idle");
    setReport(null);
    setResults([]);
    setError(null);
    setFilter("all");
  }, []);

  /**
   * Change the status filter without yanking a reader who is already looking
   * at the list. When the list top has scrolled out of view, bring it back into
   * view once; otherwise leave the scroll offset alone.
   */
  const changeFilter = useCallback((next: StatusFilterValue) => {
    setFilter(next);
    const node = resultsRef.current;
    if (node && node.getBoundingClientRect().top < 0) {
      node.scrollIntoView({ block: "start" });
    }
  }, []);

  // Boot: offer the stored report, and honour ?url=. Runs once per mount; the
  // ref guard keeps StrictMode's double effect from starting two scans. The
  // reads happen after paint so the server-rendered markup and the first client
  // render agree, which is why this is deferred rather than an initial state.
  useEffect(() => {
    if (booted.current) return;

    const task = window.setTimeout(() => {
      booted.current = true;
      const stored = loadReport();
      if (stored) setPrevious(stored);

      const preset = new URLSearchParams(window.location.search).get("url");
      if (preset) {
        setInput(preset);
        void start(preset);
      }
    }, 0);

    return () => window.clearTimeout(task);
  }, [start]);

  // Cancel an in-flight scan when the page is left.
  useEffect(() => {
    return () => {
      runToken.current += 1;
      controllerRef.current?.abort();
    };
  }, []);

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void start(input);
  }

  const running = phase === "running";
  const percent =
    progress.total > 0
      ? Math.min(100, Math.round((progress.done / progress.total) * 100))
      : 0;

  const summary = report
    ? `${report.target.host} scored ${report.score} out of 100 in ${formatSeconds(
        report.durationMs
      )}.`
    : "";

  const doneChecks = report ? report.checks : [];
  const counts = countByStatus(doneChecks);
  const visibleChecks =
    filter === "all" ? doneChecks : doneChecks.filter((result) => result.status === filter);
  const runningCounts = countByStatus(results);

  return (
    <div className="container-page" style={{ paddingTop: 40, paddingBottom: 24 }}>
      <h1 style={{ fontSize: 26 }}>Scan a site</h1>

      {previous && phase !== "running" && !report && (
        <div
          className="box rise"
          style={{
            marginTop: 16,
            padding: "12px 15px",
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 10,
          }}
        >
          <p style={{ fontSize: 13.5, color: "var(--muted-foreground)", minWidth: 0 }}>
            A previous scan of <span className="mono">{previous.target.host}</span> is
            available
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              className="btn btn-quiet btn-sm"
              onClick={() => {
                setReport(previous);
                setPrevious(null);
                setFilter("all");
                setPhase("done");
              }}
            >
              View
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => setPrevious(null)}
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      <form onSubmit={onSubmit} style={{ marginTop: 20 }} noValidate>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            gap: 10,
          }}
        >
          <div style={{ flex: "1 1 240px", minWidth: 0 }}>
            <label htmlFor="scan-url" className="sr-only">
              Web address to scan
            </label>
            <input
              id="scan-url"
              className="field"
              type="text"
              name="url"
              inputMode="url"
              autoComplete="url"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              placeholder="example.com"
              value={input}
              disabled={running}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? "scan-url-error" : undefined}
              onChange={(event) => {
                setInput(event.target.value);
                if (error) setError(null);
              }}
            />
          </div>

          {running ? (
            <button type="button" className="btn btn-quiet" onClick={cancel}>
              Cancel
            </button>
          ) : (
            <button type="submit" className="btn btn-primary">
              Run scan
            </button>
          )}
        </div>

        {error && (
          <p
            id="scan-url-error"
            role="alert"
            className="tone-fail"
            style={{ marginTop: 8, fontSize: 13.5 }}
          >
            {error}
          </p>
        )}
      </form>

      {phase === "idle" && (
        <div className="rise" style={{ marginTop: 22 }}>
          <div style={{ marginBottom: 20 }}>
            <KeyPanel />
          </div>

          <StatusLegend />

          <p
            style={{
              marginTop: 20,
              fontSize: 14,
              color: "var(--muted-foreground)",
              maxWidth: "66ch",
            }}
          >
            {checks.length} checks run in your browser against public sources.
            Nothing is uploaded to this site. Each check appears as its source answers, so the
            first results are visible before the slowest one finishes.
          </p>

          <h2 className="eyebrow" style={{ marginTop: 24 }}>
            What it looks at
          </h2>
          <ul className="box-grid" style={{ marginTop: 12 }}>
            {GROUP_ORDER.map((group, index) => {
              const members = checks.filter((c) => c.group === group);
              return (
                <li
                  key={group}
                  className="box rise"
                  style={{ ["--i" as string]: index, padding: "12px 14px" }}
                >
                  <div className="box__head">
                    <span className="box__title" style={{ fontSize: 13.5 }}>
                      {GROUP_LABEL[group]}
                    </span>
                  </div>
                  <div className="box__meta">
                    <span className="tabular">
                      {members.length} {members.length === 1 ? "check" : "checks"}
                    </span>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {running && (
        <div style={{ marginTop: 22 }}>
          <div
            role="progressbar"
            aria-label="Scan progress"
            aria-valuemin={0}
            aria-valuemax={progress.total}
            aria-valuenow={progress.done}
            className="meter"
            style={{ height: 6 }}
          >
            <div
              className="meter__fill"
              style={{
                width: `${percent}%`,
                background: "var(--primary)",
                transition: "width 220ms ease",
              }}
            />
          </div>
          <p
            className="tabular"
            aria-live="polite"
            style={{ marginTop: 8, fontSize: 13, color: "var(--muted-foreground)" }}
          >
            {progress.done} of {progress.total} checks complete
          </p>

          {results.length > 0 && (
            <div style={{ marginTop: 16 }}>
              {/* The same six words as the legend, each with a running count. */}
              <p
                className="tabular"
                aria-live="polite"
                style={{ fontSize: 12.5, color: "var(--muted-foreground)", marginBottom: 6 }}
              >
                {STATUS_LEGEND.map((entry) => `${statusLabel(entry.status)} ${runningCounts[entry.status]}`).join(
                  "  /  "
                )}
              </p>

              {RUN_ORDER.map((status) => {
                const group = results.filter((result) => result.status === status);
                if (group.length === 0) return null;
                return (
                  <section
                    key={status}
                    aria-label={`${statusLabel(status)} results`}
                    style={{ marginTop: 16 }}
                  >
                    <div className="flex items-baseline justify-between gap-3">
                      <div className="box__head">
                        <span className={`dot ${statusTone(status)}`} aria-hidden="true" />
                        <span style={{ fontSize: 13, fontWeight: 600 }}>
                          {statusLabel(status)}
                        </span>
                      </div>
                      <span
                        className="tabular"
                        style={{ fontSize: 12, color: "var(--muted-foreground)" }}
                      >
                        {group.length}
                      </span>
                    </div>
                    <ul className="box-grid" style={{ marginTop: 8 }}>
                      {group.map((result) => (
                        <ResultCard key={result.id} result={result} />
                      ))}
                    </ul>
                  </section>
                );
              })}

              {progress.done < progress.total && (
                <ul className="box-grid" style={{ marginTop: 16 }}>
                  <li className="box awaiting" aria-hidden="true">
                    <div className="box__head">
                      <span className="dot tone-idle" />
                      <span
                        className="box__title"
                        style={{ color: "var(--muted-foreground)" }}
                      >
                        Waiting on the next source
                      </span>
                    </div>
                    <p className="box__body">
                      The slowest checks are the certificate index and the document reader.
                    </p>
                  </li>
                </ul>
              )}
            </div>
          )}
        </div>
      )}

      {phase === "done" && report && (
        <div style={{ marginTop: 24 }}>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 10,
            }}
          >
            <p className="tabular scan-summary" style={{ fontSize: 14, minWidth: 0 }}>
              {summary}
            </p>
            <button type="button" className="btn btn-quiet btn-sm" onClick={reset}>
              Scan another
            </button>
          </div>

          <StatusLegend collapsible defaultOpen={false} />
          <StatusSummary counts={counts} />

          <section
            ref={resultsRef}
            aria-labelledby="scan-checks-heading"
            style={{ marginTop: 24, scrollMarginTop: 88 }}
          >
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <h2 id="scan-checks-heading" style={{ fontSize: 18 }}>
                Checks by status
              </h2>
              <span
                className="tabular"
                style={{ fontSize: 13, color: "var(--muted-foreground)" }}
              >
                {visibleChecks.length} of {doneChecks.length} shown
              </span>
            </div>
            <p style={{ marginTop: 6, fontSize: 13.5, color: "var(--muted-foreground)" }}>
              Every check that ran, filtered by the status you choose. The full report follows
              below.
            </p>

            <StatusFilter counts={counts} value={filter} onChange={changeFilter} />

            {visibleChecks.length === 0 ? (
              <p
                style={{
                  marginTop: 14,
                  padding: "14px 16px",
                  fontSize: 13.5,
                  color: "var(--muted-foreground)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius)",
                  minHeight: 64,
                }}
              >
                No check finished with this status.
              </p>
            ) : (
              <ul
                className="box-grid box-grid--wide"
                style={{ marginTop: 12, minHeight: 160 }}
              >
                {visibleChecks.map((result) => (
                  <ResultCard key={result.id} result={result} />
                ))}
              </ul>
            )}
          </section>

          <div style={{ marginTop: 14 }}>
            <ReportView report={report} />
          </div>
        </div>
      )}
    </div>
  );
}
