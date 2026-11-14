/**
 * Shared types for every check Ocellus runs.
 *
 * A scan is a list of `CheckResult`s. Each check owns one question about a
 * target and answers it with a status, a headline, and whatever structured
 * evidence it managed to collect. The report layer never reaches back into a
 * check's internals: it reads `findings` and `data` only.
 */

export type Target = {
  /** What the user typed, trimmed. */
  input: string;
  /** Absolute URL with scheme and host, no trailing slash on the path root. */
  url: string;
  /**
   * The exact hostname from the URL, lowercased, with any trailing dot removed.
   * `www.` is kept: a scan of www.example.com must request headers and DNS for
   * www.example.com, because a host can serve a different response than its
   * apex. Comparisons that mean "same site" use `domain`, not this.
   */
  host: string;
  /** Registrable domain, best-effort (eTLD+1). Used for DNS and WHOIS checks. */
  domain: string;
  /** Subdomain prefix between host and domain, or "" when host === domain. */
  subdomain: string;
  scheme: "http" | "https";
};

export type CheckStatus =
  /** The check ran and produced a clean verdict. */
  | "pass"
  /** The check ran and found something worth fixing. */
  | "warn"
  /** The check ran and found something serious. */
  | "fail"
  /** The check ran; the result is neutral information, not a verdict. */
  | "info"
  /** The upstream source could not be reached or refused the request. */
  | "unavailable"
  /** The check does not apply to this target. */
  | "skipped";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type EvidenceRow = {
  label: string;
  value: string;
  /** Optional qualifier rendered as a small tag: "missing", "weak", "ok". */
  tone?: "good" | "bad" | "neutral";
  /** Longer explanation shown when the row is expanded. */
  detail?: string;
};

export type Finding = {
  id: string;
  title: string;
  /** What is wrong, in one sentence, with the measured value inline. */
  detail: string;
  severity: Severity;
  /** What to do about it. Omitted when the finding is informational. */
  remediation?: string;
  /** Standard or specification the finding is judged against. */
  reference?: { label: string; url: string };
  evidence?: EvidenceRow[];
};

export type CheckResult<T = unknown> = {
  id: string;
  /** Human title, e.g. "HTTP security headers". */
  title: string;
  /** One line describing what the check asked. */
  question: string;
  status: CheckStatus;
  /** A single sentence a reader can act on. */
  headline: string;
  /** Structured payload, check-specific. Rendered by that check's own view. */
  data?: T;
  findings: Finding[];
  /** Wall-clock milliseconds the check took. */
  ms: number;
  /** Where the data came from, shown in the report so provenance is visible. */
  source: string;
  /** Set when status is "unavailable" or "skipped". */
  note?: string;
};

export type CheckGroup =
  | "transport"
  | "dns"
  | "email"
  | "headers"
  | "privacy"
  | "content"
  | "performance"
  | "seo"
  | "infrastructure"
  | "threat"
  | "ux";

export type CheckDefinition = {
  id: string;
  title: string;
  question: string;
  group: CheckGroup;
  /** Rough cost, used to order the queue: cheap checks report first. */
  weight: 1 | 2 | 3;
  run: (ctx: ScanContext) => Promise<CheckResult>;
};

export type ScanContext = {
  target: Target;
  /** Shared fetch layer with timeouts, caching, and a concurrency gate. */
  net: import("./net/client").NetClient;
  /** The target's HTML, fetched once and reused by every content check. */
  html: () => Promise<HtmlDocument>;
  /** Raw HTTP response headers for the target. */
  headers: () => Promise<HeaderSnapshot>;
  /** DNS answers, cached per (name, type). */
  dns: import("./net/dns").DnsResolver;
  /** Set when an earlier stage failed hard enough to make later checks moot. */
  signal: AbortSignal;
};

export type HtmlDocument = {
  /** Final URL after redirects, when the source reports it. */
  finalUrl: string;
  /** The HTML source as text. */
  source: string;
  /** Parsed document, or null when parsing was impossible. */
  doc: Document | null;
  /** True when the body looks like a bot-check or consent wall, not the page. */
  suspectInterstitial: boolean;
  /** Which route produced it, for the provenance line. */
  via: string;
};

export type HeaderSnapshot = {
  /** Status code of the final response. */
  status: number;
  /** Lowercased header name to raw value. Repeated headers keep every value. */
  headers: Record<string, string[]>;
  /** Every hop, in order, when the source exposes redirects. */
  chain: Array<{ status: number; location?: string }>;
  /** Final URL after redirects. */
  finalUrl: string;
  via: string;
};

export type ScanReport = {
  id: string;
  target: Target;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  checks: CheckResult[];
  /** 0-100, higher is better. Weighted across the groups that ran. */
  score: number;
  grade: "A" | "B" | "C" | "D" | "E" | "F";
  counts: Record<CheckStatus, number>;
};
