"use client";

/**
 * The source catalogue, filterable.
 *
 * Every row answers one question: is this answered by a check that runs in the
 * browser, and if not, what exactly stops it. The filters exist so a reader who
 * arrived asking about one tool, or about one barrier, can narrow 120 rows to
 * the handful that matter without reading the rest.
 *
 * The component is a client component because the filters are local state. It
 * reads the catalogue and the category tables directly from the data module, so
 * the rows on screen cannot drift from the rows the build validated.
 *
 * The registry check ids arrive as a prop rather than being imported here. The
 * registry holds every check's `run` function, and a catalogue has no use for
 * it; the server page resolves the ids and passes the known set down. A native
 * row whose id is not in that set renders as `unverified` and gets no link.
 */

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  ACCESS_BARRIER_LABEL,
  SOURCE_CATEGORY_LABEL,
  SOURCE_CATEGORY_NOTE,
  SOURCES,
  nativeCount,
  sourcesIn,
  type AccessBarrier,
  type SourceCategory,
  type SourceEntry,
} from "@/lib/recon/sources";

/** Barrier order follows the record's key order, which is a fixed order. */
const BARRIERS = Object.keys(ACCESS_BARRIER_LABEL) as AccessBarrier[];

/** Category order follows the label record, so sections never reshuffle. */
const CATEGORIES = Object.keys(SOURCE_CATEGORY_LABEL) as SourceCategory[];

/** Totals for the filter row, computed once at module load from the catalogue. */
const BARRIER_TOTAL: Record<AccessBarrier, number> = BARRIERS.reduce(
  (totals, barrier) => {
    totals[barrier] = SOURCES.filter((entry) => entry.barrier === barrier).length;
    return totals;
  },
  {} as Record<AccessBarrier, number>
);

function ToggleChip({
  label,
  pressed,
  count,
  onClick,
}: {
  label: string;
  pressed: boolean;
  count?: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className="chip"
      aria-pressed={pressed}
      onClick={onClick}
      style={{
        cursor: "pointer",
        background: pressed
          ? "color-mix(in oklab, var(--primary) 16%, var(--muted))"
          : "var(--muted)",
        borderColor: pressed
          ? "color-mix(in oklab, var(--primary) 55%, var(--border))"
          : "var(--border)",
        color: pressed ? "var(--foreground)" : "var(--muted-foreground)",
      }}
    >
      <span>{label}</span>
      {count !== undefined && (
        <span className="tabular" style={{ opacity: 0.7 }}>
          {count}
        </span>
      )}
    </button>
  );
}

function SourceCard({
  entry,
  knownChecks,
  index,
}: {
  entry: SourceEntry;
  knownChecks: Set<string>;
  index: number;
}) {
  const native = entry.coverage === "native";
  const checkKnown = native && entry.checkId !== undefined && knownChecks.has(entry.checkId);

  return (
    <li
      className={`box box--railed rise ${native ? "tone-pass" : "tone-idle"}`}
      style={{ ["--i" as string]: Math.min(index, 8) }}
    >
      <div className="box__head">
        <h3 className="box__title">
          <a
            href={entry.url}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "var(--foreground)", textDecoration: "none" }}
          >
            {entry.name}
          </a>
        </h3>
      </div>

      <div className="box__meta" style={{ marginTop: 6 }}>
        <span
          className="badge"
          style={{
            color: native ? "var(--signal-pass)" : "var(--signal-idle)",
            borderColor: native
              ? "color-mix(in oklab, var(--signal-pass) 45%, var(--border))"
              : "var(--border)",
          }}
          title={native ? "A check queries this from your browser" : "Listed for reference"}
        >
          <span className="dot" aria-hidden="true" />
          {native ? "Native" : "Reference"}
        </span>
        <span className="badge" title={ACCESS_BARRIER_LABEL[entry.barrier]}>
          {ACCESS_BARRIER_LABEL[entry.barrier]}
        </span>
      </div>

      <p className="box__body">{entry.answers}</p>

      <div className="box__meta">
        <span className="chip chip--wrap">{entry.cost}</span>
      </div>

      {native && entry.how && (
        <p
          className="box__body"
          style={{ marginTop: 10, paddingTop: 9, borderTop: "1px solid var(--border)" }}
        >
          {entry.how}
        </p>
      )}

      {!native && entry.gap && (
        <p
          className="box__body"
          style={{ marginTop: 10, paddingTop: 9, borderTop: "1px solid var(--border)" }}
        >
          {entry.gap}
        </p>
      )}

      {native && (
        <p className="mono" style={{ marginTop: 10, fontSize: 12, color: "var(--muted-foreground)" }}>
          {checkKnown ? (
            <>
              check{" "}
              <Link href="/checks" style={{ color: "var(--primary)" }}>
                {entry.checkId}
              </Link>
            </>
          ) : (
            <>
              <span
                className="badge"
                style={{
                  height: "auto",
                  minHeight: 20,
                  color: "var(--signal-warn)",
                  borderColor: "color-mix(in oklab, var(--signal-warn) 45%, var(--border))",
                }}
                title="This row names a check id the live registry does not contain"
              >
                unverified
              </span>{" "}
              {entry.checkId ?? "no check id"}
            </>
          )}
        </p>
      )}
    </li>
  );
}

export function SourceCatalogue({ knownCheckIds }: { knownCheckIds: string[] }) {
  const [query, setQuery] = useState("");
  const [nativeOnly, setNativeOnly] = useState(false);
  const [barriers, setBarriers] = useState<AccessBarrier[]>([]);
  const [category, setCategory] = useState<SourceCategory | "all">("all");

  const knownChecks = useMemo(() => new Set(knownCheckIds), [knownCheckIds]);
  const needle = query.trim().toLowerCase();

  const filtered = useMemo(() => {
    return SOURCES.filter((entry) => {
      if (nativeOnly && entry.coverage !== "native") return false;
      if (barriers.length > 0 && !barriers.includes(entry.barrier)) return false;
      if (category !== "all" && entry.category !== category) return false;
      if (needle) {
        const haystack = [
          entry.name,
          entry.answers,
          entry.cost,
          SOURCE_CATEGORY_LABEL[entry.category],
        ]
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  }, [nativeOnly, barriers, category, needle]);

  const sections = useMemo(
    () => CATEGORIES.filter((key) => filtered.some((entry) => entry.category === key)),
    [filtered]
  );

  const allClear = !nativeOnly && barriers.length === 0 && category === "all" && needle === "";

  function toggleBarrier(barrier: AccessBarrier) {
    setBarriers((current) =>
      current.includes(barrier)
        ? current.filter((item) => item !== barrier)
        : [...current, barrier]
    );
  }

  function clearAll() {
    setNativeOnly(false);
    setBarriers([]);
    setCategory("all");
    setQuery("");
  }

  return (
    <div>
      <div className="box rise" style={{ marginTop: 24, padding: "16px 18px" }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 14, alignItems: "flex-end" }}>
          <div style={{ flex: "1 1 280px", minWidth: 0, maxWidth: 460 }}>
            <label
              htmlFor="source-filter"
              style={{ display: "block", fontSize: 13, fontWeight: 560, marginBottom: 7 }}
            >
              Filter sources
            </label>
            <input
              id="source-filter"
              className="field"
              type="search"
              autoComplete="off"
              spellCheck={false}
              value={query}
              placeholder="Name, question, cost or category"
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>

          <div style={{ flex: "1 1 200px", minWidth: 0, maxWidth: 280 }}>
            <label
              htmlFor="source-category"
              style={{ display: "block", fontSize: 13, fontWeight: 560, marginBottom: 7 }}
            >
              Category
            </label>
            <select
              id="source-category"
              className="field"
              value={category}
              onChange={(event) => setCategory(event.target.value as SourceCategory | "all")}
            >
              <option value="all">All categories</option>
              {CATEGORIES.map((key) => (
                <option key={key} value={key}>
                  {SOURCE_CATEGORY_LABEL[key]}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ marginTop: 16 }}>
          <p className="eyebrow" style={{ marginBottom: 8 }}>
            Coverage and access
          </p>
          <div
            role="group"
            aria-label="Coverage and access filters"
            style={{ display: "flex", flexWrap: "wrap", gap: 7 }}
          >
            <ToggleChip label="All" pressed={allClear} onClick={clearAll} />
            <ToggleChip
              label="Native only"
              pressed={nativeOnly}
              onClick={() => setNativeOnly((value) => !value)}
            />
            {BARRIERS.map((barrier) => (
              <ToggleChip
                key={barrier}
                label={ACCESS_BARRIER_LABEL[barrier]}
                pressed={barriers.includes(barrier)}
                count={BARRIER_TOTAL[barrier]}
                onClick={() => toggleBarrier(barrier)}
              />
            ))}
          </div>
        </div>

        <p
          className="tabular"
          aria-live="polite"
          style={{ marginTop: 16, fontSize: 13.5, color: "var(--muted-foreground)" }}
        >
          Showing {filtered.length} of {SOURCES.length} sources
        </p>
      </div>

      {filtered.length === 0 && (
        <div className="box box--raised" style={{ marginTop: 20, padding: "18px 20px" }} role="status">
          <p style={{ fontSize: 14.5 }}>No source matches these filters.</p>
          <p style={{ marginTop: 4, fontSize: 13.5, color: "var(--muted-foreground)" }}>
            Clear the search text, widen the category, or drop a barrier to see more rows.
          </p>
          <button type="button" className="btn btn-quiet btn-sm" style={{ marginTop: 12 }} onClick={clearAll}>
            Clear filters
          </button>
        </div>
      )}

      {sections.map((key, sectionIndex) => {
        const members = filtered.filter((entry) => entry.category === key);
        const headingId = `source-category-${key}`;
        return (
          <section key={key} className="mt-12 md:mt-16" aria-labelledby={headingId}>
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <h2 id={headingId} style={{ fontSize: 21 }}>
                {SOURCE_CATEGORY_LABEL[key]}
              </h2>
              <p className="tabular" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
                {nativeCount(key)} of {sourcesIn(key).length} in Ocellus
              </p>
            </div>
            <p
              className="mt-2"
              style={{ fontSize: 14, color: "var(--muted-foreground)", maxWidth: "68ch" }}
            >
              {SOURCE_CATEGORY_NOTE[key]}
            </p>

            <ul className="box-grid box-grid--wide" style={{ marginTop: 16 }}>
              {members.map((entry, index) => (
                <SourceCard
                  key={entry.id}
                  entry={entry}
                  knownChecks={knownChecks}
                  index={Math.min(index + sectionIndex, 8)}
                />
              ))}
            </ul>
          </section>
        );
      })}
    </div>
  );
}
