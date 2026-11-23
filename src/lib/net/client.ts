/**
 * Fetch layer shared by every check.
 *
 * Three jobs:
 *  1. A single place where timeouts, retries and a concurrency cap live, so a
 *     scan of 40 checks does not open 40 sockets at once.
 *  2. A cache keyed by URL, so two checks that need the same document fetch it
 *     once.
 *  3. Uniform failure. Every call returns a discriminated result instead of
 *     throwing, so a check can report "unavailable" without a try/catch.
 */

export type FetchOk<T = unknown> = {
  ok: true;
  status: number;
  headers: Headers;
  text: string;
  /** Parsed body when the call was made with `json: true`, otherwise undefined. */
  json: T;
  url: string;
  ms: number;
};

export type FetchFail = {
  ok: false;
  reason:
    | "timeout"
    | "network"
    | "http"
    | "parse"
    | "blocked"
    | "ratelimited"
    | "invalid";
  status?: number;
  message: string;
  ms: number;
};

export type FetchResult<T = unknown> = FetchOk<T> | FetchFail;

export type NetOptions = {
  timeoutMs?: number;
  /** Retry once on network/timeout failures. Off by default: a scan is impatient. */
  retry?: boolean;
  /** Send `Accept: application/json` and parse the body. */
  json?: boolean;
  headers?: Record<string, string>;
  /** Cache key when the request URL alone is not unique. */
  cacheKey?: string;
};

const DEFAULT_TIMEOUT = 12_000;

/** Simple counting semaphore so a scan never floods an upstream with requests. */
class Gate {
  private active = 0;
  private queue: Array<() => void> = [];
  constructor(private readonly limit: number) {}

  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= this.limit) {
      await new Promise<void>((resolve) => this.queue.push(resolve));
    }
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      const next = this.queue.shift();
      if (next) next();
    }
  }
}

function classify(status: number): FetchFail["reason"] | null {
  if (status === 429) return "ratelimited";
  if (status === 401 || status === 403 || status === 451) return "blocked";
  if (status >= 500) return "http";
  return null;
}

export class NetClient {
  private cache = new Map<string, Promise<FetchResult>>();
  private gate: Gate;

  constructor(concurrency = 6) {
    this.gate = new Gate(concurrency);
  }

  /** Fetch and return the body as text. Cached by URL + accept header. */
  text(url: string, opts: NetOptions = {}): Promise<FetchResult> {
    const key = opts.cacheKey ?? `text:${url}:${opts.headers?.Accept ?? ""}`;
    const hit = this.cache.get(key);
    if (hit) return hit;
    const promise = this.execute(url, opts);
    this.cache.set(key, promise);
    return promise;
  }

  /**
   * Fetch and parse JSON. Parse failures come back as `reason: "parse"`.
   *
   * The generic is a promise the caller makes about the upstream's shape, not
   * something that can be checked at runtime, so every consumer still has to
   * treat fields as possibly absent.
   */
  json<T = unknown>(url: string, opts: NetOptions = {}): Promise<FetchResult<T>> {
    return this.text(url, {
      ...opts,
      json: true,
      headers: { Accept: "application/json", ...opts.headers },
    }) as Promise<FetchResult<T>>;
  }

  /** Drop a cache entry, e.g. after a rate-limited response should be retried. */
  forget(url: string): void {
    for (const key of [...this.cache.keys()]) {
      if (key.includes(url)) this.cache.delete(key);
    }
  }

  private async execute(url: string, opts: NetOptions): Promise<FetchResult> {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT;
    const attempt = async (): Promise<FetchResult> => {
      const started = performance.now();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(url, {
          signal: controller.signal,
          mode: "cors",
          credentials: "omit",
          redirect: "follow",
          headers: {
            Accept: opts.json ? "application/json" : "*/*",
            ...opts.headers,
          },
        });
        const text = await res.text();
        const ms = Math.round(performance.now() - started);

        if (!res.ok) {
          const reason = classify(res.status) ?? "http";
          return {
            ok: false,
            reason,
            status: res.status,
            message: `${res.status} ${res.statusText || "request rejected"}`,
            ms,
          };
        }

        let parsed: unknown;
        if (opts.json) {
          try {
            parsed = JSON.parse(text);
          } catch {
            return {
              ok: false,
              reason: "parse",
              status: res.status,
              message: "Response was not valid JSON.",
              ms,
            };
          }
        }

        return {
          ok: true,
          status: res.status,
          headers: res.headers,
          text,
          json: parsed,
          url: res.url || url,
          ms,
        };
      } catch (err) {
        const ms = Math.round(performance.now() - started);
        const aborted =
          err instanceof DOMException && err.name === "AbortError";
        return {
          ok: false,
          reason: aborted ? "timeout" : "network",
          message: aborted
            ? `No response within ${timeoutMs} ms.`
            : err instanceof Error
              ? err.message
              : "Network request failed.",
          ms,
        };
      } finally {
        clearTimeout(timer);
      }
    };

    return this.gate.run(async () => {
      const first = await attempt();
      if (
        !first.ok &&
        opts.retry &&
        (first.reason === "timeout" || first.reason === "network")
      ) {
        return attempt();
      }
      return first;
    });
  }
}

/**
 * Turn a failed fetch into a sentence a reader understands. CORS is the most
 * common failure on a static site and is worth naming explicitly, because
 * "Failed to fetch" tells the user nothing.
 */
export function describeFailure(fail: FetchFail, what: string): string {
  switch (fail.reason) {
    case "timeout":
      return `${what} did not respond in time.`;
    case "blocked":
      return `${what} refused the request (${fail.status ?? "no status"}).`;
    case "ratelimited":
      return `${what} is rate limiting requests from this address. Wait before running the scan again.`;
    case "parse":
      return `${what} returned a response that could not be read.`;
    case "network":
      return `${what} could not be reached from the browser. This is usually a missing CORS header on the source.`;
    default:
      return `${what} returned ${fail.status ?? "an error"}.`;
  }
}
