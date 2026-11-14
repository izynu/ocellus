"use client";

/**
 * The smallest unit of the report: one finding, and one check's findings.
 *
 * Both the top-level findings list and the per-check table use `FindingRow`, so
 * a finding looks and behaves the same wherever it appears. The only state in
 * this file is whether a disclosure is open, which is why it lives in the client
 * graph.
 */

import { useId, useState } from "react";
import { ChevronDown } from "lucide-react";
import type {
  CheckResult,
  CheckStatus,
  EvidenceRow,
  Finding,
  Severity,
} from "@/lib/types";

type SeverityMeta = { label: string; tone: string; color: string };

/**
 * `.chip` sets its own muted colour after the tone classes in globals.css, so
 * the tone class alone would be overridden. The inline colour is the tone
 * variable, which is the same value the class carries.
 */
export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  critical: { label: "Critical", tone: "tone-fail", color: "var(--signal-fail)" },
  high: { label: "High", tone: "tone-fail", color: "var(--signal-fail)" },
  medium: { label: "Medium", tone: "tone-warn", color: "var(--signal-warn)" },
  low: { label: "Low", tone: "tone-info", color: "var(--signal-info)" },
  info: { label: "Info", tone: "tone-idle", color: "var(--signal-idle)" },
};

export function severityChipStyle(severity: Severity) {
  const color = SEVERITY_META[severity].color;
  return {
    color,
    borderColor: `color-mix(in oklab, ${color} 45%, var(--border))`,
  };
}

const STATUS_TONE: Record<CheckStatus, string> = {
  pass: "tone-pass",
  warn: "tone-warn",
  fail: "tone-fail",
  info: "tone-info",
  unavailable: "tone-idle",
  skipped: "tone-idle",
};

const STATUS_LABEL: Record<CheckStatus, string> = {
  pass: "Pass",
  warn: "Warn",
  fail: "Fail",
  info: "Info",
  unavailable: "Unavailable",
  skipped: "Skipped",
};

export function statusTone(status: CheckStatus): string {
  return STATUS_TONE[status] ?? "tone-idle";
}

export function statusLabel(status: CheckStatus): string {
  return STATUS_LABEL[status] ?? status;
}

const EVIDENCE_TONE: Record<NonNullable<EvidenceRow["tone"]>, string | undefined> = {
  good: "tone-pass",
  bad: "tone-fail",
  neutral: undefined,
};

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

/**
 * One finding. Rendered as a list item, so it must sit inside a list.
 * The disclosure is a real button with `aria-expanded` and `aria-controls`,
 * and the panel is always in the DOM so the control always resolves.
 */
export function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const meta = SEVERITY_META[finding.severity] ?? SEVERITY_META.info;
  const hasDetail = Boolean(
    finding.remediation ||
      (finding.reference && isHttpUrl(finding.reference.url)) ||
      (finding.evidence && finding.evidence.length > 0)
  );

  return (
    <li style={{ paddingBlock: 14 }}>
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
        <span className={`chip ${meta.tone}`} style={severityChipStyle(finding.severity)}>
          {meta.label}
        </span>
        <span style={{ fontSize: 15, fontWeight: 580, letterSpacing: "-0.005em" }}>
          {finding.title}
        </span>
      </div>

      <p style={{ marginTop: 6, fontSize: 14, color: "var(--muted-foreground)" }}>
        {finding.detail}
      </p>

      {hasDetail && (
        <>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            aria-expanded={open}
            aria-controls={panelId}
            onClick={() => setOpen((value) => !value)}
            style={{ paddingInline: 0, marginTop: 6 }}
          >
            <ChevronDown
              size={15}
              aria-hidden="true"
              style={{
                transform: open ? "rotate(180deg)" : "none",
                transition: "transform 160ms ease",
              }}
            />
            How to fix
          </button>

          <div id={panelId} hidden={!open} style={{ marginTop: 4 }}>
            {finding.evidence && finding.evidence.length > 0 && (
              <dl
                style={{
                  display: "grid",
                  gridTemplateColumns: "auto minmax(0, 1fr)",
                  gap: "4px 14px",
                  fontSize: 13,
                  marginBottom: 10,
                }}
              >
                {finding.evidence.map((row, index) => (
                  <div key={`${row.label}-${index}`} style={{ display: "contents" }}>
                    <dt style={{ color: "var(--muted-foreground)" }}>{row.label}</dt>
                    <dd
                      className={EVIDENCE_TONE[row.tone ?? "neutral"]}
                      style={{ margin: 0, overflowWrap: "anywhere" }}
                    >
                      {row.value}
                      {row.detail && (
                        <span
                          style={{
                            display: "block",
                            marginTop: 2,
                            fontSize: 12,
                            color: "var(--muted-foreground)",
                          }}
                        >
                          {row.detail}
                        </span>
                      )}
                    </dd>
                  </div>
                ))}
              </dl>
            )}

            {finding.remediation && (
              <p style={{ fontSize: 14, maxWidth: "68ch" }}>{finding.remediation}</p>
            )}

            {finding.reference && isHttpUrl(finding.reference.url) && (
              <p style={{ marginTop: 8, fontSize: 13 }}>
                <span style={{ color: "var(--muted-foreground)" }}>Reference: </span>
                <a
                  href={finding.reference.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{
                    color: "var(--primary)",
                    textDecoration: "underline",
                    textUnderlineOffset: 3,
                  }}
                >
                  {finding.reference.label}
                </a>
              </p>
            )}
          </div>
        </>
      )}
    </li>
  );
}

/**
 * One check's findings behind a disclosure. `defaultOpen` starts it expanded,
 * which the table does not use, but a future focused view can.
 */
export function CheckDetail({
  result,
  defaultOpen = false,
}: {
  result: CheckResult;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();
  const count = result.findings.length;

  if (count === 0) return null;

  return (
    <div style={{ marginTop: 6 }}>
      <button
        type="button"
        className="btn btn-ghost btn-sm"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((value) => !value)}
        style={{ paddingInline: 0 }}
      >
        <ChevronDown
          size={15}
          aria-hidden="true"
          style={{
            transform: open ? "rotate(180deg)" : "none",
            transition: "transform 160ms ease",
          }}
        />
        {open ? "Hide findings" : `Show ${count} finding${count === 1 ? "" : "s"}`}
      </button>

      <div id={panelId} hidden={!open}>
        <ul className="divide-y divide-border" style={{ marginTop: 2 }}>
          {result.findings.map((finding) => (
            <FindingRow key={finding.id} finding={finding} />
          ))}
        </ul>
      </div>
    </div>
  );
}
