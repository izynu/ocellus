"use client";

/**
 * The check catalogue as a filterable index.
 *
 * The registry lives in a server module: each entry carries a `run` function,
 * which cannot cross into a client bundle. So the page reduces the registry to
 * the four serialisable fields a reader needs (id, title, question, weight) and
 * this component receives that projection. Nothing here knows what a check does,
 * only what it asks, and the page remains the single place that reads `checks`.
 *
 * Two filters, both local state. The text field matches title, question and id.
 * The weight field is a set of 1, 2 and 3: an empty set means every weight, and
 * pressing a weight narrows to that one. Empty groups disappear rather than
 * rendering an empty heading, so a narrowed page has no dead sections.
 */

import { useMemo, useState } from "react";

export type CheckCatalogueGroup = {
  group: string;
  label: string;
  members: Array<{ id: string; title: string; question: string; weight: 1 | 2 | 3 }>;
};

type Weight = 1 | 2 | 3;

const WEIGHT_ORDER: Weight[] = [3, 2, 1];

const WEIGHT_MEANING: Record<Weight, string> = {
  1: "context",
  2: "material",
  3: "structural",
};

export function CheckCatalogue({ groups }: { groups: CheckCatalogueGroup[] }) {
  const [text, setText] = useState("");
  const [weights, setWeights] = useState<Set<Weight>>(new Set());

  const total = useMemo(
    () => groups.reduce((sum, group) => sum + group.members.length, 0),
    [groups],
  );

  const filteredGroups = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return groups
      .map((group) => ({
        ...group,
        members: group.members.filter((check) => {
          if (weights.size > 0 && !weights.has(check.weight)) return false;
          if (needle.length === 0) return true;
          return (
            check.title.toLowerCase().includes(needle) ||
            check.question.toLowerCase().includes(needle) ||
            check.id.toLowerCase().includes(needle)
          );
        }),
      }))
      .filter((group) => group.members.length > 0);
  }, [groups, text, weights]);

  const shown = useMemo(
    () => filteredGroups.reduce((sum, group) => sum + group.members.length, 0),
    [filteredGroups],
  );

  const hasFilters = text.trim().length > 0 || weights.size > 0;

  function toggleWeight(weight: Weight) {
    setWeights((prev) => {
      const next = new Set(prev);
      if (next.has(weight)) next.delete(weight);
      else next.add(weight);
      return next;
    });
  }

  return (
    <div>
      <section
        className="box rise"
        style={{ marginTop: 22, padding: "16px 18px" }}
        aria-label="Filter the catalogue"
      >
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "flex-end", gap: 12 }}>
          <div style={{ flex: "1 1 240px", minWidth: 0 }}>
            <label
              htmlFor="check-filter"
              style={{ display: "block", fontSize: 13, fontWeight: 560, marginBottom: 6 }}
            >
              Filter checks
            </label>
            <input
              id="check-filter"
              className="field"
              type="search"
              autoComplete="off"
              spellCheck={false}
              value={text}
              placeholder="title, question or id"
              onChange={(event) => setText(event.target.value)}
            />
          </div>
          <div style={{ paddingBottom: 4 }}>
            <p className="eyebrow" style={{ marginBottom: 6 }}>
              Weight
            </p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {WEIGHT_ORDER.map((weight) => {
                const pressed = weights.has(weight);
                return (
                  <button
                    key={weight}
                    type="button"
                    className="chip tabular"
                    aria-pressed={pressed}
                    title={`Weight ${weight}: ${WEIGHT_MEANING[weight]}`}
                    onClick={() => toggleWeight(weight)}
                    style={{
                      cursor: "pointer",
                      minHeight: 28,
                      paddingInline: 10,
                      color: pressed ? "var(--primary-foreground)" : undefined,
                      background: pressed ? "var(--primary)" : undefined,
                      borderColor: pressed ? "var(--primary)" : undefined,
                    }}
                  >
                    {weight} {WEIGHT_MEANING[weight]}
                  </button>
                );
              })}
            </div>
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            style={{ marginBottom: 4 }}
            onClick={() => {
              setText("");
              setWeights(new Set());
            }}
            disabled={!hasFilters}
          >
            Reset filters
          </button>
        </div>
        <p
          className="tabular"
          aria-live="polite"
          style={{ marginTop: 12, fontSize: 13, color: "var(--muted-foreground)" }}
        >
          {shown} of {total} checks shown
        </p>
      </section>

      {filteredGroups.length === 0 && (
        <div className="box" style={{ marginTop: 24, padding: "18px 20px" }}>
          <p className="box__body" style={{ marginTop: 0 }}>
            No check matches this filter. Clear the text or release a weight to see the registry
            again.
          </p>
        </div>
      )}

      {filteredGroups.map((group, groupIndex) => {
        const headingId = `group-${group.group}`;
        return (
          <section
            key={group.group}
            className={`mt-12 md:mt-16 area-${group.group}`}
            aria-labelledby={headingId}
          >
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <div className="area-head">
                <span className="dot" aria-hidden="true" />
                <h2 id={headingId} style={{ fontSize: 22 }}>
                  {group.label}
                </h2>
              </div>
              <p className="tabular" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
                {group.members.length}{" "}
                {group.members.length === 1 ? "check" : "checks"}
              </p>
            </div>

            <ul className="box-grid mt-4">
              {group.members.map((check, index) => (
                <li
                  key={check.id}
                  className="box box--area rise"
                  style={{ ["--i" as string]: Math.min(index + groupIndex, 8) }}
                >
                  <div className="box__head">
                    <span className="dot" aria-hidden="true" />
                    <h3 className="box__title">{check.title}</h3>
                  </div>
                  <p className="box__body">{check.question}</p>
                  <div className="box__meta">
                    <span
                      className="chip tabular"
                      title={`Weight ${check.weight}: ${WEIGHT_MEANING[check.weight]}`}
                    >
                      weight {check.weight}
                    </span>
                    <span className="mono">{check.id}</span>
                  </div>
                </li>
              ))}
            </ul>
          </section>
        );
      })}
    </div>
  );
}
