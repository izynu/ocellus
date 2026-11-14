/**
 * The scan runner.
 *
 * Owns the lifecycle of one scan: build the context, run the checks with a
 * bounded concurrency and a hard per-check timeout, stream progress, and
 * assemble the report. Nothing here knows what a check does; it only knows the
 * shape of one.
 *
 * Two behaviours worth stating because they are deliberate:
 *
 *  - A check that throws becomes an `unavailable` result carrying the error,
 *    not a failed scan. One broken upstream should not erase fifteen good
 *    results.
 *  - Checks run in two waves. Cheap, independent checks (DNS, headers, CT)
 *    start first so the page has something to show while the document is still
 *    being fetched. The second wave is whatever is left.
 */

import type {
  CheckDefinition,
  CheckResult,
  HeaderSnapshot,
  HtmlDocument,
  ScanContext,
  ScanReport,
  Target,
} from "../types";
import { NetClient } from "../net/client";
import { DnsResolver } from "../net/dns";
import { fetchHeaders, fetchHtml } from "../net/document";
import { parseTarget } from "../target";
import { checks as ALL_CHECKS } from "../checks";
import { countStatuses, scoreChecks } from "./score";

export type ProgressEvent =
  | { kind: "start"; target: Target; total: number }
  | { kind: "check"; result: CheckResult; done: number; total: number }
  | { kind: "done"; report: ScanReport };

export type RunOptions = {
  onProgress?: (event: ProgressEvent) => void;
  signal?: AbortSignal;
  /** Restrict the run to a subset of check ids. Used by the group pages. */
  only?: string[];
  /** Hard ceiling for a single check. */
  checkTimeoutMs?: number;
};

// The slowest upstream is crt.sh, which allows 45s and one retry. The per-check
// ceiling has to sit above that, or the retry can never complete and the
// generous timeout on the fetch buys nothing.
const DEFAULT_CHECK_TIMEOUT = 100_000;

export async function runScan(
  input: string,
  options: RunOptions = {}
): Promise<ScanReport> {
  const target = parseTarget(input);
  const startedAt = new Date();
  const started = performance.now();

  const net = new NetClient(6);
  const dns = new DnsResolver(net);
  const controller = new AbortController();
  const signal = options.signal
    ? AbortSignal.any([options.signal, controller.signal])
    : controller.signal;

  // The document and the header snapshot are fetched at most once each and
  // shared by every check. Both are memoised on first request, so a check that
  // never needs the HTML never triggers the fetch.
  let htmlPromise: Promise<HtmlDocument> | null = null;
  let headerPromise: Promise<HeaderSnapshot> | null = null;

  const ctx: ScanContext = {
    target,
    net,
    dns,
    signal,
    html: () => {
      if (!htmlPromise) htmlPromise = fetchHtml(net, target);
      return htmlPromise;
    },
    headers: () => {
      if (!headerPromise) headerPromise = fetchHeaders(net, target);
      return headerPromise;
    },
  };

  const selected = options.only
    ? ALL_CHECKS.filter((c) => options.only!.includes(c.id))
    : ALL_CHECKS;

  // Wave one: the checks that do not need the shared document, ordered so the
  // cheapest land first.
  const waveOne = selected
    .filter((c) => c.group === "dns" || c.group === "headers" || c.group === "transport")
    .sort((a, b) => a.weight - b.weight);
  const waveTwo = selected
    .filter((c) => !waveOne.includes(c))
    .sort((a, b) => a.weight - b.weight);

  const results: CheckResult[] = [];
  options.onProgress?.({ kind: "start", target, total: selected.length });

  const runOne = async (def: CheckDefinition): Promise<CheckResult> => {
    const timeoutMs = options.checkTimeoutMs ?? DEFAULT_CHECK_TIMEOUT;
    try {
      const result = await withTimeout(def.run(ctx), timeoutMs, def);
      results.push(result);
      options.onProgress?.({
        kind: "check",
        result,
        done: results.length,
        total: selected.length,
      });
      return result;
    } catch (err) {
      const failed = failureResult(def, err);
      results.push(failed);
      options.onProgress?.({
        kind: "check",
        result: failed,
        done: results.length,
        total: selected.length,
      });
      return failed;
    }
  };

  // Two concurrent checks per wave keeps upstreams calm while still finishing a
  // sixteen-check scan in a reasonable time. The NetClient gate is the real
  // limiter; this just prevents every check from starting at once.
  await runPool(waveOne, 3, runOne);
  await runPool(waveTwo, 3, runOne);

  const finishedAt = new Date();
  const weights: Record<string, number> = {};
  for (const def of ALL_CHECKS) weights[def.id] = def.weight;

  // Report order follows the registry, not completion order, so the page does
  // not reshuffle between runs.
  const ordered = ALL_CHECKS.filter((def) => results.some((r) => r.id === def.id)).map(
    (def) => results.find((r) => r.id === def.id)!
  );

  const { score, grade } = scoreChecks(ordered, weights);

  const report: ScanReport = {
    id: randomId(),
    target,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: Math.round(performance.now() - started),
    checks: ordered,
    score,
    grade,
    counts: countStatuses(ordered),
  };

  options.onProgress?.({ kind: "done", report });
  return report;
}

function randomId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return Math.random().toString(36).slice(2) + Date.now().toString(36);
  }
}

async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  def: CheckDefinition
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${def.title} did not finish within ${ms / 1000}s.`)),
          ms
        );
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function failureResult(def: CheckDefinition, err: unknown): CheckResult {
  const message = err instanceof Error ? err.message : "The check failed without a message.";
  return {
    id: def.id,
    title: def.title,
    question: def.question,
    status: "unavailable",
    headline: `${def.title} could not complete.`,
    findings: [],
    ms: 0,
    source: "none",
    note: message,
  };
}

/** Run tasks with a fixed number in flight, preserving nothing about order. */
async function runPool<T>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<unknown>
): Promise<void> {
  let index = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) {
      const item = items[index++];
      await worker(item);
    }
  });
  await Promise.all(runners);
}

/** Persist the last report so a reload on the results page still shows it. */
const STORAGE_KEY = "ocellus.report.v1";

export function saveReport(report: ScanReport): void {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(report));
  } catch {
    // A private window with storage disabled still scans; it just cannot reload.
  }
}

export function loadReport(): ScanReport | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as ScanReport;
  } catch {
    return null;
  }
}

export function clearReport(): void {
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing to do.
  }
}
