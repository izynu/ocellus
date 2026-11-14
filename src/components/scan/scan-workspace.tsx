"use client";

/**
 * The whole scan flow on one page.
 *
 * Three states: idle, running, done. The running state is the product: results
 * land one at a time so the user watches real checks resolve rather than a
 * spinner. The done state hands off to `ReportView`.
 *
 * Deep linking: `?url=` is read from `window.location.search` in an effect
 * rather than `useSearchParams`, because static export would otherwise require
 * a Suspense boundary around the whole page for no benefit.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { InvalidTarget } from "@/lib/target";
import {
  loadReport,
  runScan,
  saveReport,
  type ProgressEvent,
} from "@/lib/scan/runner";
import type { CheckResult, ScanReport } from "@/lib/types";
import { GROUP_LABEL, GROUP_ORDER, checks } from "@/lib/checks";
import { statusLabel, statusTone } from "./check-detail";
import { ReportView } from "./report-view";

type Phase = "idle" | "running" | "done";

function formatSeconds(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} seconds`;
}

export function ScanWorkspace() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<CheckResult[]>([]);
  const [progress, setProgress] = useState({ done: 0, total: checks.length });
  const [report, setReport] = useState<ScanReport | null>(null);
  const [previous, setPrevious] = useState<ScanReport | null>(null);

  /** Invalidates callbacks from an aborted or superseded run. */
  const runToken = useRef(0);
  const controllerRef = useRef<AbortController | null>(null);
  const booted = useRef(false);

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
          <p
            style={{
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
            <ul className="box-grid" style={{ marginTop: 14 }}>
              {results.map((result) => (
                <li
                  key={result.id}
                  className={`box box--railed land ${statusTone(result.status)}`}
                >
                  <div className="box__head">
                    <span
                      className="dot"
                      role="img"
                      aria-label={statusLabel(result.status)}
                    />
                    <span className="box__title">{result.title}</span>
                  </div>
                  <p className="box__body truncate-2">{result.headline}</p>
                </li>
              ))}
              {progress.done < progress.total && (
                <li className="box awaiting" aria-hidden="true">
                  <div className="box__head">
                    <span className="dot tone-idle" />
                    <span className="box__title" style={{ color: "var(--muted-foreground)" }}>
                      Waiting on the next source
                    </span>
                  </div>
                  <p className="box__body">
                    The slowest checks are the certificate index and the document reader.
                  </p>
                </li>
              )}
            </ul>
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
            <p className="tabular" style={{ fontSize: 14, minWidth: 0 }}>
              {summary}
            </p>
            <button type="button" className="btn btn-quiet btn-sm" onClick={reset}>
              Scan another
            </button>
          </div>
          <div style={{ marginTop: 14 }}>
            <ReportView report={report} />
          </div>
        </div>
      )}
    </div>
  );
}
