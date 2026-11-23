"use client";

/**
 * The dork catalogue, with a live target.
 *
 * A static build cannot know which domain the visitor wants, so the target is
 * local state: one input, and every query on the page is re-rendered from it.
 * Nothing typed here leaves the page. There is no request, no storage and no
 * analytics, which is why the component can say so plainly under the input.
 *
 * Copying prefers the clipboard API and falls back to selecting the code block,
 * because the clipboard is unavailable on an insecure origin and in some
 * browsers. In the fallback the text is selected and the visitor presses the
 * copy shortcut, which is a worse result than the clipboard but still works.
 */

import { useEffect, useRef, useState } from "react";
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

const ENGINE_LABEL: Record<DorkEngine, string> = {
  google: "Google",
  bing: "Bing",
  duckduckgo: "DuckDuckGo",
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
          Every query below is filled in with{" "}
          <span className="mono">{domain}</span> as you type. This input is never sent anywhere.
          There is no request, no storage and no analytics: the queries are generated in this tab
          and copied or opened by you.
        </p>
      </div>

      {CATEGORY_ORDER.map((category, categoryIndex) => {
        const members = DORK_TEMPLATES.filter((template) => template.category === category);
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
            <ul
              className="box-grid"
              style={{ margin: "16px 0 0" }}
            >
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
