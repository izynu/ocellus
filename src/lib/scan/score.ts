/**
 * Scoring.
 *
 * A single number for a whole report is a blunt instrument, so the rules are
 * fixed and published: every check carries a weight, every status maps to a
 * fixed fraction, and a check that could not run is removed from the
 * denominator rather than scored as a pass. A site with twelve unavailable
 * checks and four passes does not get an A, it gets an A on four checks and
 * the report says so.
 */

import type { CheckResult, CheckStatus, ScanReport, Severity } from "../types";

/** Fraction of a check's weight earned by each status. */
const STATUS_VALUE: Record<CheckStatus, number | null> = {
  pass: 1,
  info: 0.85,
  warn: 0.55,
  fail: 0.1,
  // Not the site's fault and not evidence of health: drop from the denominator.
  unavailable: null,
  skipped: null,
};

export function scoreChecks(
  checks: CheckResult[],
  weights: Record<string, number>
): { score: number; grade: ScanReport["grade"] } {
  let earned = 0;
  let possible = 0;

  for (const check of checks) {
    const value = STATUS_VALUE[check.status];
    if (value === null) continue;
    const weight = weights[check.id] ?? 1;
    earned += weight * value;
    possible += weight;
  }

  if (possible === 0) return { score: 0, grade: "F" };

  const score = Math.round((earned / possible) * 100);
  return { score, grade: gradeFor(score) };
}

function gradeFor(score: number): ScanReport["grade"] {
  if (score >= 90) return "A";
  if (score >= 78) return "B";
  if (score >= 64) return "C";
  if (score >= 50) return "D";
  if (score >= 32) return "E";
  return "F";
}

export function countStatuses(checks: CheckResult[]): Record<CheckStatus, number> {
  const counts: Record<CheckStatus, number> = {
    pass: 0,
    warn: 0,
    fail: 0,
    info: 0,
    unavailable: 0,
    skipped: 0,
  };
  for (const c of checks) counts[c.status]++;
  return counts;
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Findings across the whole report, worst first. */
export function rankFindings(checks: CheckResult[]) {
  return checks
    .flatMap((check) => check.findings.map((finding) => ({ check, finding })))
    .sort((a, b) => SEVERITY_RANK[a.finding.severity] - SEVERITY_RANK[b.finding.severity]);
}

/** The fraction a single check earns on its own, for the report's per-row bar. */
export function checkFraction(status: CheckStatus): number | null {
  return STATUS_VALUE[status];
}
