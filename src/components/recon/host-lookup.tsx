"use client";

/**
 * A focused host lookup.
 *
 * The full scan runs every check. This runs only the checks that answer "who is
 * this, and what does the name layer say about it": registration, the zone, the
 * alias, the nameservers, DNSSEC, the host's address and the hostnames beneath
 * it. It is the recon-first entry point, so a reader who wants ownership does not
 * have to scroll past header and accessibility results to find it.
 *
 * It runs the same registry checks through the same runner, so a number here
 * cannot disagree with the same check in a full report.
 */

import { useCallback, useRef, useState } from "react";
import { InvalidTarget } from "@/lib/target";
import { runScan } from "@/lib/scan/runner";
import type { CheckResult, ScanReport } from "@/lib/types";
import { CheckFacts } from "./../scan/check-facts";
import { statusLabel, statusTone } from "./../scan/check-detail";

/** The checks that answer the ownership and name question. */
const LOOKUP_CHECKS = [
  "whois",
  "dns-records",
  "dnssec",
  "dns-hygiene",
  "dns-aliases",
  "nameservers",
  "ct-logs",
  "subdomains",
  "infrastructure",
  "cohosted",
] as const;

export function HostLookup() {
  const [input, setInput] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<CheckResult[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const token = useRef(0);

  const run = useCallback(async () => {
    const value = input.trim();
    if (!value) {
      setError("Enter a domain to look up.");
      return;
    }
    const mine = ++token.current;
    setError(null);
    setResults([]);
    setReport(null);
    setRunning(true);
    try {
      const finished = await runScan(value, {
        only: [...LOOKUP_CHECKS],
        onProgress: (event) => {
          if (mine !== token.current) return;
          if (event.kind === "check") setResults((prev) => [...prev, event.result]);
        },
      });
      if (mine === token.current) setReport(finished);
    } catch (err) {
      if (mine !== token.current) return;
      setError(
        err instanceof InvalidTarget
          ? err.message
          : err instanceof Error
            ? err.message
            : "The lookup could not run."
      );
    } finally {
      if (mine === token.current) setRunning(false);
    }
  }, [input]);

  const answered = results.filter((r) => r.status !== "unavailable" && r.status !== "skipped").length;

  return (
    <div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run();
        }}
        noValidate
        style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center" }}
      >
        <div style={{ flex: "1 1 280px", minWidth: 0 }}>
          <label htmlFor="whois-input" className="sr-only">
            Domain to look up
          </label>
          <input
            id="whois-input"
            className="field"
            type="text"
            inputMode="url"
            autoComplete="url"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="example.com"
            value={input}
            disabled={running}
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? "whois-error" : undefined}
            onChange={(e) => {
              setInput(e.target.value);
              if (error) setError(null);
            }}
          />
        </div>
        <button type="submit" className="btn btn-primary" disabled={running}>
          {running ? "Looking up…" : "Who is this?"}
        </button>
      </form>

      {error && (
        <p id="whois-error" role="alert" className="tone-fail" style={{ marginTop: 8, fontSize: 13.5 }}>
          {error}
        </p>
      )}

      {running && (
        <p className="tabular" style={{ marginTop: 10, fontSize: 13, color: "var(--muted-foreground)" }}>
          {results.length} of {LOOKUP_CHECKS.length} lookups answered…
        </p>
      )}

      {results.length > 0 && (
        <ul className="box-grid box-grid--wide" style={{ marginTop: 16, listStyle: "none", padding: 0 }}>
          {results.map((result, index) => (
            <li
              key={result.id}
              className={`box box--railed land ${statusTone(result.status)}`}
              style={{ ["--i" as string]: Math.min(index, 10) }}
            >
              <div className="box__head">
                <span className="dot" aria-hidden="true" />
                <span className="box__title">{result.title}</span>
                <span className={`chip ${statusTone(result.status)}`} style={{ marginLeft: "auto" }}>
                  {statusLabel(result.status)}
                </span>
              </div>
              <p className="box__body">{result.headline}</p>
              <CheckFacts result={result} />
              {result.note && (
                <p className="box__meta" style={{ display: "block", marginTop: 6 }}>
                  {result.note}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}

      {report && (
        <p style={{ marginTop: 14, fontSize: 13.5, color: "var(--muted-foreground)" }}>
          {answered} of {LOOKUP_CHECKS.length} lookups produced a verdict. For the full picture,
          including headers, email and reputation,{" "}
          <a
            href={`/scan/?url=${encodeURIComponent(report.target.host)}`}
            style={{ color: "var(--primary)" }}
          >
            run the full scan
          </a>
          .
        </p>
      )}
    </div>
  );
}
