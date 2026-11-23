"use client";

/**
 * The dork catalogue, with a live target and client-side filters.
 *
 * A static build cannot know which domain the visitor wants, so the target is
 * local state: one input, and every query on the page is re-rendered from it.
 * Nothing typed here leaves the page. There is no request, no storage and no
 * analytics, which is why the component can say so plainly under the input.
 *
 * The filters are local state for the same reason. A text field matches against
 * the label, the query and the category name; the category and engine chips are
 * multi-select toggles marked with `aria-pressed`. An empty selection means
 * every category or engine, so a reader never starts on an empty page.
 *
 * Copying prefers the clipboard API and falls back to selecting a block, because
 * the clipboard is unavailable on an insecure origin and in some browsers. In
 * the fallback the text is selected and the visitor presses the copy shortcut,
 * which is a worse result than the clipboard but still works. Every copy result
 * is announced in a live region as well as printed on the button.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import type { DorkCategory } from "@/lib/types";
import {
  DORK_CATEGORY_LABEL,
  DORK_CATEGORY_NOTE,
  DORK_TEMPLATES,
  dorkUrl,
  renderDork,
  type DorkEngine,
  type DorkTemplate,
} from "@/lib/recon/dorks";

/** Label order follows the record's key order, which is severity order. */
const CATEGORY_ORDER = Object.keys(DORK_CATEGORY_LABEL) as DorkCategory[];

const ENGINE_ORDER: DorkEngine[] = ["google", "bing", "duckduckgo", "shodan", "github", "censys"];

const ENGINE_LABEL: Record<DorkEngine, string> = {
  google: "Google",
  bing: "Bing",
  duckduckgo: "DuckDuckGo",
  shodan: "Shodan",
  github: "GitHub",
  censys: "Censys",
};

/** Used when the field is empty, so every query still reads as a query. */
const FALLBACK_DOMAIN = "example.com";

/**
 * Reduce whatever was typed to a hostname.
 *
 * A pasted URL is the common case, so the scheme, path, query and trailing dot
 * are stripped. The result is only ever substituted into a query string, which
 * `dorkUrl` then percent-encodes, so no value here can reach markup as HTML.
 */
function normaliseDomain(raw: string): string {
  let value = raw.trim().toLowerCase();
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  value = value.replace(/[/?#].*$/, "");
  value = value.replace(/\.$/, "");
  return value;
}

/** Toggle one value in a set, returning a new set. */
function toggle<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

type CopyStatus = "idle" | "copied" | "selected";

function DorkCard({
  template,
  domain,
  index,
}: {
  template: DorkTemplate;
  domain: string;
  index: number;
}) {
  const [status, setStatus] = useState<CopyStatus>("idle");
  const codeRef = useRef<HTMLElement | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const query = renderDork(template, {
    domain,
    host: domain,
    origin: `https://${domain}`,
  });
  const engine = ENGINE_LABEL[template.engine];

  function settle(next: CopyStatus) {
    setStatus(next);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setStatus("idle"), 2200);
  }

  function selectText() {
    const el = codeRef.current;
    if (!el) return;
    const range = document.createRange();
    range.selectNodeContents(el);
    const selection = window.getSelection();
    if (!selection) return;
    selection.removeAllRanges();
    selection.addRange(range);
  }

  async function copy() {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(query);
        settle("copied");
        return;
      }
      selectText();
      settle("selected");
    } catch {
      selectText();
      settle("selected");
    }
  }

  const buttonLabel =
    status === "copied" ? "Copied" : status === "selected" ? "Selected, press Ctrl+C" : "Copy query";

  return (
    <li className="box rise" style={{ padding: "13px 15px", ["--i" as string]: index }}>
      <div className="box__head">
        <span className="box__title" style={{ fontSize: 14 }}>
          {template.label}
        </span>
        <span className="chip" style={{ marginLeft: "auto" }} title={`Runs in ${engine}`}>
          {engine}
        </span>
      </div>

      <code
        ref={codeRef}
        className="mono"
        style={{
          display: "block",
          marginTop: 10,
          padding: "8px 10px",
          background: "var(--muted)",
          border: "1px solid var(--border)",
          borderRadius: 8,
          fontSize: 12,
          lineHeight: 1.55,
          overflowWrap: "anywhere",
          userSelect: "all",
        }}
      >
        {query}
      </code>

      {template.note && (
        <p className="box__body" style={{ fontSize: 12.5 }}>
          {template.note}
        </p>
      )}

      <div className="box__meta" style={{ gap: 8 }}>
        <button type="button" className="btn btn-quiet btn-sm" onClick={copy}>
          {buttonLabel}
        </button>
        <a
          className="btn btn-ghost btn-sm"
          href={dorkUrl(template.engine, query)}
          target="_blank"
          rel="noopener noreferrer"
        >
          Open in {engine}
        </a>
      </div>

      <span className="sr-only" role="status">
        {status === "copied"
          ? "Query copied to clipboard."
          : status === "selected"
            ? "Query selected. Press the copy shortcut to copy it."
            : ""}
      </span>
    </li>
  );
}

export function DorkCatalogue() {
  const [value, setValue] = useState(FALLBACK_DOMAIN);
  const normalised = normaliseDomain(value);
  const domain = normalised || FALLBACK_DOMAIN;

  const [text, setText] = useState("");
  const [categories, setCategories] = useState<Set<DorkCategory>>(new Set());
  const [engines, setEngines] = useState<Set<DorkEngine>>(new Set());

  const [bulk, setBulk] = useState<CopyStatus>("idle");
  const [showBlock, setShowBlock] = useState(false);
  const blockRef = useRef<HTMLPreElement | null>(null);
  const bulkTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (bulkTimer.current) clearTimeout(bulkTimer.current);
    };
  }, []);

  const filtered = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return DORK_TEMPLATES.filter((template) => {
      if (categories.size > 0 && !categories.has(template.category)) return false;
      if (engines.size > 0 && !engines.has(template.engine)) return false;
      if (needle.length === 0) return true;
      return (
        template.label.toLowerCase().includes(needle) ||
        template.query.toLowerCase().includes(needle) ||
        DORK_CATEGORY_LABEL[template.category].toLowerCase().includes(needle) ||
        template.category.includes(needle)
      );
    });
  }, [text, categories, engines]);

  const visibleBlock = useMemo(
    () =>
      filtered
        .map((template) => renderDork(template, { domain, host: domain, origin: `https://${domain}` }))
        .join("\n"),
    [filtered, domain],
  );

  function settleBulk(next: CopyStatus) {
    setBulk(next);
    if (bulkTimer.current) clearTimeout(bulkTimer.current);
    bulkTimer.current = setTimeout(() => setBulk("idle"), 2600);
  }

  function selectBlock() {
    const el = blockRef.current;
    if (!el) return;
    const range = document.createRange();
    range.selectNodeContents(el);
    const selection = window.getSelection();
    if (!selection) return;
    selection.removeAllRanges();
    selection.addRange(range);
  }

  async function copyAll() {
    if (filtered.length === 0) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(visibleBlock);
        setShowBlock(false);
        settleBulk("copied");
        return;
      }
      setShowBlock(true);
      requestAnimationFrame(() => {
        selectBlock();
        settleBulk("selected");
      });
    } catch {
      setShowBlock(true);
      requestAnimationFrame(() => {
        selectBlock();
        settleBulk("selected");
      });
    }
  }

  function resetFilters() {
    setText("");
    setCategories(new Set());
    setEngines(new Set());
  }

  const hasFilters = text.trim().length > 0 || categories.size > 0 || engines.size > 0;

  return (
    <div>
      <div className="box rise" style={{ marginTop: 22, padding: "16px 18px" }}>
        <label
          htmlFor="dork-domain"
          style={{ display: "block", fontSize: 13, fontWeight: 560, marginBottom: 8 }}
        >
          Target domain
        </label>
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10 }}>
          <div style={{ flex: "1 1 260px", minWidth: 0, maxWidth: 420 }}>
            <input
              id="dork-domain"
              className="field"
              type="text"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              value={value}
              placeholder={FALLBACK_DOMAIN}
              onChange={(event) => setValue(event.target.value)}
            />
          </div>
          <p className="mono tabular" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
            {domain}
          </p>
        </div>
        <p style={{ marginTop: 10, fontSize: 13, color: "var(--muted-foreground)", maxWidth: "66ch" }}>
          Every query below is filled in with <span className="mono">{domain}</span> as you type. This
          input is never sent anywhere. There is no request, no storage and no analytics: the queries
          are generated in this tab and copied or opened by you.
        </p>
      </div>

      <section className="box rise" style={{ marginTop: 14, padding: "16px 18px" }} aria-label="Filter the catalogue">
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "flex-end", gap: 12 }}>
          <div style={{ flex: "1 1 240px", minWidth: 0 }}>
            <label
              htmlFor="dork-filter"
              style={{ display: "block", fontSize: 13, fontWeight: 560, marginBottom: 6 }}
            >
              Filter queries
            </label>
            <input
              id="dork-filter"
              className="field"
              type="search"
              autoComplete="off"
              spellCheck={false}
              value={text}
              placeholder="label, query or category"
              onChange={(event) => setText(event.target.value)}
            />
          </div>
          <p
            className="tabular"
            style={{ fontSize: 13, color: "var(--muted-foreground)", paddingBottom: 11 }}
            aria-live="polite"
          >
            {filtered.length} of {DORK_TEMPLATES.length} shown
          </p>
          <div style={{ display: "flex", gap: 8, paddingBottom: 4 }}>
            <button
              type="button"
              className="btn btn-quiet btn-sm"
              onClick={() => void copyAll()}
              disabled={filtered.length === 0}
            >
              {bulk === "copied"
                ? "Copied visible"
                : bulk === "selected"
                  ? "Selected, press Ctrl+C"
                  : "Copy all visible"}
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={resetFilters}
              disabled={!hasFilters}
            >
              Reset filters
            </button>
          </div>
        </div>

        <div style={{ marginTop: 16 }}>
          <p className="eyebrow" style={{ marginBottom: 8 }}>
            Category
          </p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {CATEGORY_ORDER.map((category) => {
              const members = DORK_TEMPLATES.filter((template) => template.category === category);
              if (members.length === 0) return null;
              const pressed = categories.has(category);
              return (
                <button
                  key={category}
                  type="button"
                  className="chip"
                  aria-pressed={pressed}
                  onClick={() => setCategories((prev) => toggle(prev, category))}
                  style={{
                    cursor: "pointer",
                    minHeight: 28,
                    paddingInline: 10,
                    color: pressed ? "var(--primary-foreground)" : undefined,
                    background: pressed ? "var(--primary)" : undefined,
                    borderColor: pressed ? "var(--primary)" : undefined,
                  }}
                >
                  {DORK_CATEGORY_LABEL[category]}
                  <span className="tabular" style={{ opacity: 0.75 }}>
                    {members.length}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <div style={{ marginTop: 14 }}>
          <p className="eyebrow" style={{ marginBottom: 8 }}>
            Engine
          </p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {ENGINE_ORDER.map((engine) => {
              const members = DORK_TEMPLATES.filter((template) => template.engine === engine);
              if (members.length === 0) return null;
              const pressed = engines.has(engine);
              return (
                <button
                  key={engine}
                  type="button"
                  className="chip"
                  aria-pressed={pressed}
                  onClick={() => setEngines((prev) => toggle(prev, engine))}
                  style={{
                    cursor: "pointer",
                    minHeight: 28,
                    paddingInline: 10,
                    color: pressed ? "var(--primary-foreground)" : undefined,
                    background: pressed ? "var(--primary)" : undefined,
                    borderColor: pressed ? "var(--primary)" : undefined,
                  }}
                >
                  {ENGINE_LABEL[engine]}
                  <span className="tabular" style={{ opacity: 0.75 }}>
                    {members.length}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {showBlock && (
          <div style={{ marginTop: 14 }}>
            <p style={{ fontSize: 12.5, color: "var(--muted-foreground)", marginBottom: 6 }}>
              The clipboard was unavailable, so the block is selected below. Press your copy shortcut.
            </p>
            <pre
              ref={blockRef}
              className="mono"
              style={{
                margin: 0,
                padding: "10px 12px",
                background: "var(--muted)",
                border: "1px solid var(--border)",
                borderRadius: 8,
                fontSize: 12,
                lineHeight: 1.6,
                whiteSpace: "pre-wrap",
                overflowWrap: "anywhere",
                maxHeight: 260,
                overflowY: "auto",
              }}
            >
              {visibleBlock}
            </pre>
          </div>
        )}

        <span className="sr-only" role="status">
          {bulk === "copied"
            ? `${filtered.length} queries copied to clipboard.`
            : bulk === "selected"
              ? "Queries selected. Press the copy shortcut to copy them."
              : ""}
        </span>
      </section>

      {filtered.length === 0 && (
        <div className="box" style={{ marginTop: 24, padding: "18px 20px" }}>
          <p className="box__body" style={{ marginTop: 0 }}>
            No query matches this filter. Clear the text or release a category or engine to see the
            catalogue again.
          </p>
        </div>
      )}

      {CATEGORY_ORDER.map((category, categoryIndex) => {
        const members = filtered.filter((template) => template.category === category);
        if (members.length === 0) return null;
        const headingId = `dork-${category}`;
        return (
          <section key={category} className="mt-12 md:mt-16" aria-labelledby={headingId}>
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <h2 id={headingId} style={{ fontSize: 21 }}>
                {DORK_CATEGORY_LABEL[category]}
              </h2>
              <p className="tabular" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
                {members.length} {members.length === 1 ? "query" : "queries"}
              </p>
            </div>
            <p
              className="mt-2"
              style={{ fontSize: 14, color: "var(--muted-foreground)", maxWidth: "68ch" }}
            >
              {DORK_CATEGORY_NOTE[category]}
            </p>
            <ul className="box-grid" style={{ margin: "16px 0 0" }}>
              {members.map((template, index) => (
                <DorkCard
                  key={template.id}
                  template={template}
                  domain={domain}
                  index={Math.min(index + categoryIndex, 8)}
                />
              ))}
            </ul>
          </section>
        );
      })}

      <section className="mt-16 md:mt-20" aria-labelledby="dorks-rules">
        <h2 id="dorks-rules" style={{ fontSize: 20 }}>
          What this page does and does not do
        </h2>
        <div className="box box--raised" style={{ marginTop: 14, padding: "18px 20px" }}>
          <ul className="prose" style={{ margin: 0, maxWidth: "70ch" }}>
            <li>
              Ocellus does not run a dork. It builds the query and hands it to you, so the search
              engine sees your browser rather than a server of ours. Every search engine forbids
              automated querying without an API key, and a report that claimed to have run one
              would describe a request nobody made.
            </li>
            <li>
              A hit is a last step, not a first one. Confirm the file or panel is reachable, then
              remove it or close it. An index entry can outlive the page it points at, so a result
              in the engine is not proof the resource is live.
            </li>
            <li>
              Run these against a domain you own or have written permission to assess. Querying a
              third party this way can breach their terms and, depending on where you are, the
              law.
            </li>
          </ul>
        </div>
        <p style={{ marginTop: 12, fontSize: 13.5, color: "var(--muted-foreground)" }}>
          The queries come from the community dork lists this page was built against. The{" "}
          <Link href="/recon" style={{ color: "var(--primary)" }}>
            recon page
          </Link>{" "}
          places this step in the wider workflow.
        </p>
      </section>
    </div>
  );
}
